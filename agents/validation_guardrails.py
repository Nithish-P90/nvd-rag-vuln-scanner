# agents/validation_guardrails.py
"""
Guardrails for the ValidationAgent: a fixed threat taxonomy and a fixed,
evidence-based scoring rule, so a verdict means the same thing for every
finding instead of being whatever the validator LLM says.

The LLM's verdict is one input (L). The rest are measured from the code and
its code property graph (CPG):

  S  statement_present    the flagged statement exists in the file (gate)
  O  operation_evidence   the dangerous operation for this threat category is
                          at the finding's lines (catalog sink / sensitive op /
                          resource issue / entry point, per category kind)
  A  attacker_control     how attacker data reaches it:
                            proven    taint path from an untrusted source or entry point
                            boundary  flows from a parameter of a function nothing in
                                      the project calls (public API: assume reachable)
                            unknown   cannot tell (no data flow available)
                            none      only constants / internal data reach it
  M  mitigation           sanitizer or check on that path:
                            none / partial (a guarding check) / sanitized / unknown
  L  llm_verdict          the validator model's verdict (CONFIRMED / NEEDS_CONTEXT /
                          FALSE_POSITIVE); treated as NEEDS_CONTEXT when its own
                          reasoning contradicts it

  score = 25*O + 25*A + 20*M + 30*L        (0-100)
     O: yes 1, no 0
     A: proven 1, boundary 0.5, unknown 0.3, none 0
     M: none 1, partial 0.6, unknown 0.5, sanitized 0
     L: CONFIRMED 1, NEEDS_CONTEXT 0.5, FALSE_POSITIVE 0
  For "intrinsic" categories (the operation itself is the flaw: weak crypto,
  hard-coded secret, use-after-free, ...) A is not about taint, so A := O.
  For "access" categories A := O, where O is "an entry point reaches it".

  Verdict: score >= 75 CONFIRMED, score < 40 FALSE_POSITIVE, else NEEDS_CONTEXT,
  after these gates:
     G0  manual-memory flaw (buffer overrun, use-after-free, double free) in a
         memory-safe language without native interop -> FALSE_POSITIVE
         (memory_safety_gate, applied by the ValidationAgent to every path)
     G1  S false                                 -> FALSE_POSITIVE (statement not in code)
     G2  taint category and A = none              -> FALSE_POSITIVE, or NEEDS_CONTEXT if L confirmed
     G3  M = sanitized                            -> never CONFIRMED; FALSE_POSITIVE if L agrees
     G4  O = no                                   -> never CONFIRMED
     G5  category OTHER (outside the taxonomy)    -> never CONFIRMED
"""

import re
from typing import Optional

from joern_cpg.security_catalog import catalog_for, compiled, family_of

# ─── Fixed threat taxonomy ─────────────────────────────────
# kind:
#   taint      exploitable only if attacker-controlled data reaches the operation
#   intrinsic  the operation is unsafe by itself (no attacker data needed)
#   access     about who may invoke the code (needs a reachable entry point)
THREAT_TAXONOMY = [
    {"id": "INJECTION", "name": "Injection",
     "definition": "Untrusted data is interpreted as part of a command, query or code: OS command, SQL, "
                   "LDAP/XPath, template or eval-style code execution.",
     "kind": "taint",
     "cwes": ["CWE-77", "CWE-78", "CWE-88", "CWE-89", "CWE-90", "CWE-94", "CWE-95", "CWE-643",
              "CWE-917", "CWE-943", "CWE-1336", "CWE-564"]},
    {"id": "XSS", "name": "Cross-site scripting",
     "definition": "Untrusted data is written into HTML/JavaScript output without encoding, so it runs "
                   "as script in a victim's browser.",
     "kind": "taint", "cwes": ["CWE-79", "CWE-80", "CWE-87"]},
    {"id": "MEMORY_CORRUPTION", "name": "Memory corruption",
     "definition": "A write or read outside a buffer's bounds, or a size calculation that wraps, driven "
                   "by input: buffer overflow, out-of-bounds write/read, integer overflow, format string.",
     "kind": "taint",
     "cwes": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126", "CWE-127", "CWE-131",
              "CWE-134", "CWE-190", "CWE-191", "CWE-680", "CWE-787", "CWE-805", "CWE-806"]},
    {"id": "MEMORY_LIFECYCLE", "name": "Memory/resource lifecycle",
     "definition": "Memory or a resource is used after release, released twice, never released, or used "
                   "without checking that acquisition succeeded (NULL).",
     "kind": "intrinsic",
     "cwes": ["CWE-401", "CWE-404", "CWE-415", "CWE-416", "CWE-476", "CWE-690", "CWE-772", "CWE-825",
              "CWE-824", "CWE-457", "CWE-908"]},
    {"id": "PATH_TRAVERSAL", "name": "Path traversal / file access",
     "definition": "Untrusted data selects a file path, letting an attacker read or write files outside "
                   "the intended directory.",
     "kind": "taint", "cwes": ["CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-59", "CWE-73", "CWE-434"]},
    {"id": "DESERIALIZATION", "name": "Unsafe deserialization",
     "definition": "Untrusted bytes are deserialized with a format that can instantiate arbitrary "
                   "objects or run code (pickle, yaml.load, Java ObjectInputStream, ...).",
     "kind": "taint", "cwes": ["CWE-502"]},
    {"id": "XXE", "name": "XML external entities",
     "definition": "Untrusted XML is parsed with external entities enabled, allowing file disclosure or SSRF.",
     "kind": "taint", "cwes": ["CWE-611", "CWE-776", "CWE-827"]},
    {"id": "SSRF", "name": "Server-side request forgery / redirect",
     "definition": "Untrusted data chooses the URL the server fetches or redirects to.",
     "kind": "taint", "cwes": ["CWE-918", "CWE-601"]},
    {"id": "PROMPT_INJECTION", "name": "Prompt injection",
     "definition": "Untrusted text is placed into an LLM prompt where it can override instructions.",
     "kind": "taint", "cwes": ["CWE-1427"]},
    {"id": "SECRETS", "name": "Hard-coded or exposed secrets",
     "definition": "A password, key or token is embedded in source or stored/transmitted in cleartext.",
     "kind": "intrinsic",
     "cwes": ["CWE-798", "CWE-259", "CWE-321", "CWE-256", "CWE-312", "CWE-319", "CWE-522"]},
    {"id": "CRYPTO", "name": "Weak cryptography / randomness / TLS",
     "definition": "A broken or weak algorithm, non-cryptographic randomness for security values, or "
                   "disabled certificate validation.",
     "kind": "intrinsic",
     "cwes": ["CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-295", "CWE-297", "CWE-916"]},
    {"id": "ACCESS_CONTROL", "name": "Broken authentication / authorization",
     "definition": "A sensitive operation reachable from outside lacks an authentication or authorization "
                   "check, or the check is wrong.",
     "kind": "access",
     "cwes": ["CWE-284", "CWE-285", "CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-639", "CWE-862",
              "CWE-863", "CWE-269", "CWE-250", "CWE-352"]},
    {"id": "RESOURCE_EXHAUSTION", "name": "Denial of service / resource exhaustion",
     "definition": "Unbounded loops, recursion or allocation that an attacker can trigger to exhaust CPU, "
                   "memory or other resources.",
     "kind": "taint", "cwes": ["CWE-400", "CWE-770", "CWE-835", "CWE-674", "CWE-1333"]},
    {"id": "RACE_CONDITION", "name": "Race condition",
     "definition": "Shared state is accessed concurrently without synchronization, or checked and then "
                   "used after it may have changed (TOCTOU).",
     "kind": "intrinsic", "cwes": ["CWE-362", "CWE-364", "CWE-366", "CWE-367"]},
    {"id": "INFO_EXPOSURE", "name": "Information exposure",
     "definition": "Internal details or sensitive data reach logs, error messages or responses where "
                   "unauthorized parties can read them; debug features left enabled.",
     "kind": "intrinsic", "cwes": ["CWE-200", "CWE-209", "CWE-489", "CWE-532", "CWE-1327"]},
    {"id": "OTHER", "name": "Other (outside taxonomy)",
     "definition": "Does not map to any category above; can be reported but never auto-confirmed.",
     "kind": "intrinsic", "cwes": []},
]
TAXONOMY = {c["id"]: c for c in THREAT_TAXONOMY}
_CWE_TO_CATEGORY = {cwe: c["id"] for c in THREAT_TAXONOMY for cwe in c["cwes"]}

# Category keywords, used only when the finding carries no mappable CWE.
_KEYWORDS = [
    ("INJECTION",           r"inject|sql|command exec|code exec|eval|rce|template"),
    ("XSS",                 r"xss|cross.site script"),
    ("MEMORY_LIFECYCLE",    r"use.after.free|double free|memory leak|null (pointer|deref)|uninitiali[sz]ed|leak"),
    ("MEMORY_CORRUPTION",   r"overflow|out.of.bounds|format string|buffer|integer (overflow|wrap)"),
    ("PATH_TRAVERSAL",      r"path traversal|directory traversal|file (inclusion|upload)"),
    ("DESERIALIZATION",     r"deserial|pickle|unmarshal"),
    ("XXE",                 r"xxe|xml external"),
    ("SSRF",                r"ssrf|request forgery|open redirect"),
    ("PROMPT_INJECTION",    r"prompt"),
    ("SECRETS",             r"hard.?coded|credential|secret|password|api key|cleartext"),
    ("CRYPTO",              r"crypto|hash|md5|sha1|random|tls|ssl|certificate|cipher"),
    ("ACCESS_CONTROL",      r"auth|access control|privilege|csrf|permission"),
    ("RESOURCE_EXHAUSTION", r"denial of service|dos\b|exhaust|infinite loop|recursion|redos"),
    ("RACE_CONDITION",      r"race|toctou|concurren"),
    ("INFO_EXPOSURE",       r"information (disclosure|exposure|leak)|debug|stack trace|error message"),
]

WEIGHTS          = {"O": 25, "A": 25, "M": 20, "L": 30}
A_VALUE          = {"proven": 1.0, "boundary": 0.5, "unknown": 0.3, "none": 0.0}
M_VALUE          = {"none": 1.0, "partial": 0.6, "unknown": 0.5, "sanitized": 0.0}
L_VALUE          = {"CONFIRMED": 1.0, "NEEDS_CONTEXT": 0.5, "FALSE_POSITIVE": 0.0}
CONFIRM_AT       = 75
FALSE_POSITIVE_BELOW = 40

# Resource-analysis phrases (joern_cpg.security_profile.resource_findings) per CWE.
_RESOURCE_CWES = [
    (r"used at L\d+ after release", "CWE-416"),
    (r"released twice",             "CWE-415"),
    (r"never NULL-checked",         "CWE-476"),
    (r"no release in the function", "CWE-401"),
]


def _norm_cwe(c) -> Optional[str]:
    m = re.search(r"(\d+)", str(c or ""))
    return f"CWE-{int(m.group(1))}" if m and "NVD-CWE" not in str(c) else None


def classify(finding: dict) -> str:
    """Taxonomy id for a finding: its CWEs first, then keywords in its category name."""
    cwes = finding.get("cwe_ids") or [finding.get("cwe_id")]
    for c in cwes if isinstance(cwes, list) else [cwes]:
        cat = _CWE_TO_CATEGORY.get(_norm_cwe(c))
        if cat:
            return cat
    text = f"{finding.get('category', '')} {finding.get('vulnerability_type', '')}".lower()
    for cat, rx in _KEYWORDS:
        if re.search(rx, text):
            return cat
    return "OTHER"


def category_of_cwe(cwe: Optional[str]) -> Optional[str]:
    return _CWE_TO_CATEGORY.get(_norm_cwe(cwe))


# ─── LLM reasoning consistency ─────────────────────────────
_SAYS_VULN = re.compile(r"\b(is|are|remains?|still) (vulnerable|exploitable)|can be exploited|allows? (an )?attackers?"
                        r"|leads? to (arbitrary|remote)|directly (injects?|concatenat)|without (any )?(sanitiz|validat|bounds)", re.I)
_SAYS_SAFE = re.compile(r"\bnot (vulnerable|exploitable)|no (vulnerability|risk)|is safe|properly (sanitiz|validat|escap)"
                        r"|cannot be (exploited|controlled)|not (attacker|user).controlled|false positive", re.I)


def llm_contradiction(verdict: str, reasoning: str) -> bool:
    """True when the validator's reasoning argues the opposite of its verdict."""
    vuln, safe = bool(_SAYS_VULN.search(reasoning or "")), bool(_SAYS_SAFE.search(reasoning or ""))
    if verdict == "FALSE_POSITIVE":
        return vuln and not safe
    if verdict == "CONFIRMED":
        return safe and not vuln
    return False


# ─── Evidence from the code / CPG ──────────────────────────
def _squash(s: str) -> str:
    return re.sub(r"\s+", "", s or "")


def statement_present(code: str, snippets: list, anchors: list) -> bool:
    """
    The flagged statement exists in the file. When forensics quoted the
    statement, that quote must match (allowing whitespace/punctuation
    differences); a CPG anchor alone is not enough, since anchors also match
    unrelated calls of the same kind. Without a quote, a CPG anchor counts.
    """
    snippets = [s for s in snippets if s and len(_squash(str(s))) >= 6]
    if not snippets:
        return bool(anchors)
    flat = _squash(code)
    for snip in snippets:
        s = _squash(str(snip)).rstrip(";")
        if len(s) >= 6 and s in flat:
            return True
        # Partial match: most identifiers of the statement on one source line.
        idents = [t for t in re.findall(r"[A-Za-z_]\w{2,}", str(snip))]
        if len(idents) >= 2:
            for line in code.splitlines():
                if sum(1 for t in idents if t in line) >= max(2, int(0.7 * len(idents))):
                    return True
    return False


def _near(line: int, lines: set, tol: int = 1) -> bool:
    return any(abs(line - ln) <= tol for ln in lines)


def operation_evidence(category: str, profiler, lines: set) -> tuple:
    """(bool, basis): the category's dangerous operation is at the finding's lines."""
    if profiler is None or not lines:
        return False, "no located lines"
    kind = TAXONOMY[category]["kind"]
    if kind == "access":
        entry = _entry_reaching(profiler, lines)
        return (True, f"reachable from {entry}") if entry else (False, "no entry point reaches it")
    for kind_name in ("sinks", "sensitive"):
        for s in profiler.sites(kind_name):
            if _near(s.line, lines) and category_of_cwe(s.cwe) == category:
                return True, f"{s.label} at L{s.line}"
    for item in profiler.resource_findings():
        for rx, cwe in _RESOURCE_CWES:
            m = re.search(rx, item)
            if m and category_of_cwe(cwe) == category:
                found = {int(n) for n in re.findall(r"L(\d+)", item)}
                if found & {ln + d for ln in lines for d in (-1, 0, 1)}:
                    return True, item
    return False, f"no {TAXONOMY[category]['name'].lower()} operation at L{','.join(map(str, sorted(lines)))}"


def _method_at(profiler, line: int):
    cpg = profiler.cpg
    if cpg is None:
        return None
    ms = [m for m in cpg.methods.values() if m.contains(line) and "<" not in m.name]
    return min(ms, key=lambda m: m.span) if ms else None


def _entry_reaching(profiler, lines: set) -> Optional[str]:
    for ln in sorted(lines):
        m = _method_at(profiler, ln)
        if m is None:
            continue
        chain = profiler.entry_chain(m)
        if chain:
            return f"{chain[0].name}()" + (f" via {len(chain) - 1} call(s)" if len(chain) > 1 else "")
    return None


def attacker_control(profiler, lines: set) -> tuple:
    """((proven|boundary|unknown|none), basis, matching taint path or None)."""
    if profiler is None or not lines:
        return "unknown", "no located lines", None
    paths = [p for p in profiler.taint_paths() if _near(p["sink_line"], lines)]
    if paths:
        p = min(paths, key=lambda p: bool(p["sanitized_by"]))      # prefer an unsanitized one
        return "proven", f"{p['source']} reaches L{p['sink_line']} ({p['origin']})", p
    cpg = profiler.cpg
    if cpg is None:
        return "unknown", "no data-flow graph (tree-sitter fallback)", None
    for ln in sorted(lines):
        m = _method_at(profiler, ln)
        if m is None:
            continue
        sl = cpg.backward_slice(m, {ln}, depth=None)
        params = {p.get("name") for p in m.params} - {None, "self", "this", "cls"}
        used = profiler._idents(sl, m.file) & params
        if used:
            if not cpg.callers_of(m):
                return "boundary", f"parameter {', '.join(sorted(used))} of {m.name}() (no callers in project)", None
            return "unknown", f"parameter {', '.join(sorted(used))} of {m.name}(); callers pass no traced untrusted data", None
        return "none", f"only constants/locals reach L{ln} in {m.name}()", None
    return "unknown", "statement not inside a known function", None


def mitigation(profiler, lines: set, path: Optional[dict]) -> tuple:
    """((none|partial|sanitized|unknown), basis)."""
    if path is not None:
        if path["sanitized_by"]:
            return "sanitized", "; ".join(path["sanitized_by"][:2])
        if path["checks"]:
            return "partial", "checked by " + "; ".join(path["checks"][:2])
        return "none", "no sanitizer or check on the path"
    if profiler is None or profiler.cpg is None or not lines:
        return "unknown", "no data-flow graph"
    for ln in sorted(lines):
        m = _method_at(profiler, ln)
        if m is None:
            continue
        sl = profiler.cpg.backward_slice(m, {ln}, depth=None) | {ln}
        sans = [s for s in profiler._method_sites(m, "sanitizers") if s.line in sl]
        if sans:
            return "sanitized", f"{sans[0].label} at L{sans[0].line}"
        if profiler.cpg.controllers_of(m, ln):
            return "partial", f"guarded by a condition at L{profiler.cpg.controllers_of(m, ln)[0]}"
        return "none", "no sanitizer or guard in the function"
    return "unknown", "statement not inside a known function"


# ─── Decision ──────────────────────────────────────────────
def assess(finding: dict, code: str, profiler, anchors: list, signals: list,
           llm_verdict: str, llm_reasoning: str) -> dict:
    """
    Apply the guardrails to one validated finding. Returns the `validation`
    record: category, the six parameters with their basis, score, final
    verdict and the rule that decided it.
    """
    category = classify(finding)
    cat      = TAXONOMY[category]
    sig_lines = set()
    for s in signals:
        try:
            if int(s.get("line") or 0) > 0:
                sig_lines.add(int(s["line"]))
        except (TypeError, ValueError):
            pass
    lines = set(anchors or []) | sig_lines

    snippets = [s.get("affected_code") for s in signals if s.get("affected_code")]
    snippets += re.findall(r"`([^`]+)`", str(finding.get("evidence", "")))
    S = statement_present(code, snippets, anchors)

    O, o_basis = operation_evidence(category, profiler, lines) if category != "OTHER" else (False, "outside taxonomy")
    if cat["kind"] == "taint":
        A, a_basis, path = attacker_control(profiler, lines)
    else:
        A, a_basis, path = ("proven" if O else "none"), "not taint-based: follows operation evidence", None
    M, m_basis = mitigation(profiler, lines, path)

    L = llm_verdict if llm_verdict in L_VALUE else "NEEDS_CONTEXT"
    contradiction = llm_contradiction(L, llm_reasoning)
    L_used = "NEEDS_CONTEXT" if contradiction else L

    score = round(WEIGHTS["O"] * (1.0 if O else 0.0) + WEIGHTS["A"] * A_VALUE[A]
                  + WEIGHTS["M"] * M_VALUE[M] + WEIGHTS["L"] * L_VALUE[L_used])

    if score >= CONFIRM_AT:
        verdict, rule = "CONFIRMED", f"score {score} >= {CONFIRM_AT}"
    elif score < FALSE_POSITIVE_BELOW:
        verdict, rule = "FALSE_POSITIVE", f"score {score} < {FALSE_POSITIVE_BELOW}"
    else:
        verdict, rule = "NEEDS_CONTEXT", f"score {score} between {FALSE_POSITIVE_BELOW} and {CONFIRM_AT}"

    def cap(reason: str):
        nonlocal verdict, rule
        if verdict == "CONFIRMED":
            verdict, rule = "NEEDS_CONTEXT", reason

    if not S:
        verdict, rule, score = "FALSE_POSITIVE", "G1: flagged statement not found in the code", 0
    elif cat["kind"] == "taint" and A == "none":
        verdict, rule = (("NEEDS_CONTEXT", "G2: no attacker data reaches it, but the validator confirmed")
                         if L_used == "CONFIRMED" else
                         ("FALSE_POSITIVE", "G2: only constants/internal data reach the operation"))
    elif M == "sanitized":
        if L_used == "FALSE_POSITIVE":
            verdict, rule = "FALSE_POSITIVE", f"G3: sanitized ({m_basis}) and the validator agrees"
        else:
            cap(f"G3: sanitized ({m_basis}) — cannot auto-confirm")
    if verdict == "CONFIRMED" and not O:
        cap("G4: the category's dangerous operation is not at the finding")
    if verdict == "CONFIRMED" and category == "OTHER":
        cap("G5: outside the threat taxonomy")

    return {
        "threat_category":   category,
        "category_name":     cat["name"],
        "category_kind":     cat["kind"],
        "parameters": {
            "statement_present":  S,
            "operation_evidence": {"value": O, "basis": o_basis},
            "attacker_control":   {"value": A, "basis": a_basis},
            "mitigation":         {"value": M, "basis": m_basis},
            "llm_verdict":        {"value": L, "used_as": L_used, "contradiction": contradiction},
        },
        "score":   score,
        "verdict": verdict,
        "rule":    rule,
    }


# ─── Language gate ─────────────────────────────────────────
# In these families the runtime owns memory: a buffer overrun, use-after-free
# or double free cannot be written in their source, only in native code they
# call (an outdated native dependency is a dependency finding, not a code one).
MEMORY_SAFE_FAMILIES = {"python", "js", "java", "go", "php"}
_UNMANAGED_MEMORY_CWES = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126",
                          "CWE-127", "CWE-131", "CWE-787", "CWE-805", "CWE-806",
                          "CWE-415", "CWE-416", "CWE-824", "CWE-825"}
_UNMANAGED_MEMORY_RX = re.compile(r"use.after.free|double.free|dangling pointer|buffer (?:overflow|overrun)"
                                  r"|out.of.bounds (?:read|write)|heap (?:overflow|corruption)", re.I)
# Interop that hands raw memory back to the program.
_NATIVE_INTEROP_RX = re.compile(r"\bctypes\b|\bcffi\b|\bsun\.misc\.Unsafe\b|\bunsafe\.Pointer\b"
                                r"|\bBuffer\.allocUnsafe\b|\bFFI::|\bffi\.")


def memory_safety_gate(finding: dict, language: Optional[str], code: str) -> Optional[str]:
    """
    Reason a finding cannot hold in this language (G0), or None.
    A manual-memory flaw reported for a memory-safe language is ruled out
    unless the file uses native interop.
    """
    if family_of(language) not in MEMORY_SAFE_FAMILIES:
        return None
    cwes = finding.get("cwe_ids") or [finding.get("cwe_id")]
    cwes = {_norm_cwe(c) for c in (cwes if isinstance(cwes, list) else [cwes])}
    text = f"{finding.get('category', '')} {finding.get('vulnerability_type', '')}"
    if not (cwes & _UNMANAGED_MEMORY_CWES or _UNMANAGED_MEMORY_RX.search(text)):
        return None
    if _NATIVE_INTEROP_RX.search(code or ""):
        return None
    return f"G0: manual-memory flaw reported in memory-safe {family_of(language)} code with no native interop"


# ─── Advisory check ────────────────────────────────────────
def _sink_cwes(snippet: str, language: Optional[str]) -> dict:
    """{CWE: label} for every catalog sink in the snippet."""
    found = {}
    for pattern, label, cwe in catalog_for(language).get("sinks", []):
        if compiled(pattern).search(snippet or ""):
            found.setdefault(cwe, label)
    return found


def fix_regressions(original: str, fixed: str, language: Optional[str]) -> list:
    """
    Sink kinds the suggested fix adds that the flagged code did not have,
    e.g. a fix that turns in-memory image bytes into a file path. Swapping
    one sink for a safer one of the same kind (os.system -> subprocess.run)
    is not a regression.
    """
    before = _sink_cwes(original, language)
    return [f"{label} ({cwe})" for cwe, label in _sink_cwes(fixed, language).items() if cwe not in before]
