# agents/risk_evidence.py
"""
Evidence-based baselines for the six risk dimensions.

The CategorizationAgent's LLM may adjust CWE- and CVSS-based baselines by ±1 (CPG facts are fixed), so the
score is anchored to facts about the code and about similar real CVEs:

  exploitability        CPG taint path into the finding (remote vs local source,
                        sanitized or not, entry point reachability)
                        -> else CVSS AV/AC/PR/UI of the finding's matched CVEs
  exposure              entry point that reaches the finding (HTTP route,
                        network server, CLI, main) / kind of taint source
                        -> else CVSS AV of the matched CVEs
  attack_prerequisites  shape of the taint path (direct, cross-function,
                        guarded by checks) -> else CVSS AC/PR/UI
  confidentiality,      what the CWE allows in general (table below)
  integrity,            -> else CVSS C/I/A of the matched CVEs
  availability

A dimension with no evidence keeps the LLM's score (default 3).
"""

import re
import statistics
from typing import Optional


# ─── CVSS vector -> dimensions ─────────────────────────────
def _parse_vector(vector: str) -> dict:
    parts = (vector or "").split("/")
    out   = {"version": "2.0"}
    if parts and parts[0].startswith("CVSS:"):
        out["version"] = parts[0][5:]
        parts = parts[1:]
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            out[k] = v
    return out


def cvss_dimensions(vector: str) -> dict:
    """
    One CVE's CVSS vector mapped onto the 1-5 criteria.

      exploitability:  AV:P -> 1; otherwise count barriers (PR required,
                       AC:H, local access): 0 -> 5 (4 with user interaction),
                       1 -> 3, 2 -> 2, 3 -> 1
      exposure:        AV:N without privileges -> 4, AV:N with privileges -> 3,
                       AV:A -> 2, AV:L/P -> 1
      prerequisites:   AV:P -> 1, AC:H -> 2, AC:L + PR:N + UI:N -> 4, else 3
      C / I / A:       v3 H -> 4 (5 when scope changed), L -> 2, N -> 1
                       v2 C -> 5, P -> 3, N -> 1
    """
    v = _parse_vector(vector)
    if "AV" not in v:
        return {}
    if v["version"].startswith("2"):
        av, ac = v["AV"], ("H" if v.get("AC") == "H" else "L")
        pr, ui = ("N" if v.get("Au") == "N" else "L"), "N"
        cia_map, changed = {"C": 5, "P": 3, "N": 1}, False
    else:
        av, ac, pr, ui = v["AV"], v.get("AC", "L"), v.get("PR", "N"), v.get("UI", "N")
        changed = v.get("S") == "C"
        cia_map = {"H": 5 if changed else 4, "L": 2, "N": 1}

    if av == "P":
        exploitability = 1
    else:
        barriers = (pr != "N") + (ac == "H") + (av == "L")
        exploitability = {0: 5 if ui == "N" else 4, 1: 3, 2: 2}.get(barriers, 1)
    exposure = {"N": 4 if pr == "N" else 3, "A": 2}.get(av, 1)
    if av == "P":
        prerequisites = 1
    elif ac == "H":
        prerequisites = 2
    elif pr == "N" and ui == "N":
        prerequisites = 4
    else:
        prerequisites = 3

    out = {"exploitability": exploitability, "exposure": exposure,
           "attack_prerequisites": prerequisites}
    for dim, key in (("confidentiality", "C"), ("integrity", "I"), ("availability", "A")):
        if key in v:
            out[dim] = cia_map.get(v[key], 1)
    return out

# ─── CWE impact baselines (confidentiality, integrity, availability) ──
# What a successful exploit of the weakness typically yields, on the 1-5
# criteria scale. Memory-corruption writes and injection give code execution
# (integrity 5); reads and leaks are confidentiality-only; crashes are DoS.
_CIA_GROUPS = [
    (("CWE-78", "CWE-77", "CWE-88", "CWE-94", "CWE-95", "CWE-502"),          (5, 5, 5)),
    (("CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-119", "CWE-131",
      "CWE-190", "CWE-191", "CWE-680", "CWE-416", "CWE-415", "CWE-134"),     (4, 5, 4)),
    (("CWE-89", "CWE-943", "CWE-564"),                                        (5, 4, 3)),
    (("CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-256"),                 (5, 4, 2)),
    (("CWE-287", "CWE-306", "CWE-288", "CWE-290"),                            (4, 4, 3)),
    (("CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-639", "CWE-269"),      (4, 4, 2)),
    (("CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73", "CWE-59"),            (4, 3, 2)),
    (("CWE-611", "CWE-776", "CWE-827"),                                       (4, 1, 3)),
    (("CWE-918",),                                                            (4, 2, 2)),
    (("CWE-125", "CWE-126", "CWE-127"),                                       (4, 1, 3)),
    (("CWE-457", "CWE-908", "CWE-824"),                                       (3, 2, 3)),
    (("CWE-79", "CWE-80", "CWE-87"),                                          (3, 3, 1)),
    (("CWE-1427",),                                                           (3, 3, 2)),
    (("CWE-295", "CWE-297"),                                                  (4, 3, 1)),
    (("CWE-327", "CWE-326", "CWE-328", "CWE-916"),                            (4, 2, 1)),
    (("CWE-330", "CWE-338"),                                                  (3, 2, 1)),
    (("CWE-362", "CWE-367", "CWE-366", "CWE-364"),                            (2, 3, 3)),
    (("CWE-352",),                                                            (2, 3, 1)),
    (("CWE-601",),                                                            (2, 2, 1)),
    (("CWE-200", "CWE-209", "CWE-532", "CWE-312", "CWE-319"),                 (3, 1, 1)),
    (("CWE-476", "CWE-690"),                                                  (1, 1, 4)),
    (("CWE-400", "CWE-770", "CWE-835", "CWE-674", "CWE-401", "CWE-772",
      "CWE-404", "CWE-399"),                                                  (1, 1, 4)),
]
CWE_CIA = {cwe: cia for cwes, cia in _CIA_GROUPS for cwe in cwes}

# ─── Taint source / entry point classification ─────────────
# Labels come from joern_cpg.security_catalog.
_REMOTE_SOURCE = re.compile(r"http|network|request|uploaded|form|browser|socket|message|websocket", re.I)
_LOCAL_SOURCE  = re.compile(r"command-line|stdin|environment|file|process input|stream", re.I)
_PUBLIC_ENTRY  = re.compile(r"http|route|serverless|network server|message handler|websocket", re.I)
_LOCAL_ENTRY   = re.compile(r"cli|command|script|program entry", re.I)

_WORD = re.compile(r"[a-z]{3,}")


def _cwes(finding: dict) -> list:
    raw = finding.get("cwe_ids") or [finding.get("cwe_id")]
    out = []
    for c in raw if isinstance(raw, list) else [raw]:
        m = re.search(r"(\d+)", str(c or ""))
        if m and "NVD-CWE" not in str(c):
            out.append(f"CWE-{int(m.group(1))}")
    return out


def linked_signals(finding: dict, signals: list) -> list:
    """Forensics signals behind a categorized finding (shared CWE or category words)."""
    cwes  = set(_cwes(finding))
    words = set(_WORD.findall(str(finding.get("category", "")).lower())) - {"vulnerability", "insecure"}
    out = []
    for s in signals:
        if not isinstance(s, dict):
            continue
        s_words = set(_WORD.findall(str(s.get("vulnerability_type", "")).lower()))
        if (cwes and set(_cwes(s)) & cwes) or (words and len(words & s_words) >= min(2, len(words))):
            out.append(s)
    return out


def _lines(signals: list) -> list:
    out = []
    for s in signals:
        try:
            if int(s.get("line") or 0) > 0:
                out.append(int(s["line"]))
        except (TypeError, ValueError):
            pass
    return out


# ─── CPG evidence ──────────────────────────────────────────
def _entry_for_line(profiler, line: int) -> Optional[str]:
    """Label of an entry point that reaches the method containing `line`."""
    cpg = profiler.cpg
    if cpg is None:
        return None
    methods = [m for m in cpg.methods.values() if m.contains(line) and "<" not in m.name]
    if not methods:
        return None
    method = min(methods, key=lambda m: m.span)
    chain  = profiler.entry_chain(method)
    if not chain:
        return None
    entry = chain[0]
    label = next((e["label"] for e in profiler.entry_points(entry.file)
                  if e["method"] is not None and e["method"].key == entry.key), "entry point")
    hops  = f" via {len(chain) - 1} call(s)" if len(chain) > 1 else ""
    return f"{label} {entry.name}(){hops}"


def cpg_evidence(profiler, lines: list) -> dict:
    """
    {dimension: (score, basis)} for exploitability / exposure / attack_prerequisites
    from the taint paths and entry points touching the finding's lines.
    """
    if profiler is None or not lines:
        return {}
    try:
        paths = [p for p in profiler.taint_paths()
                 if any(abs(p["sink_line"] - ln) <= 1 for ln in lines)]
        entry = next((e for e in (_entry_for_line(profiler, ln) for ln in lines) if e), None)
    except Exception:
        return {}

    # Prefer the most dangerous path: unsanitized, remote source.
    def danger(p):
        return (not (p["sanitized_by"] or p["checks"]), bool(_REMOTE_SOURCE.search(p["source"])))
    path = max(paths, key=danger) if paths else None

    remote = bool(path and _REMOTE_SOURCE.search(path["source"])) or bool(entry and _PUBLIC_ENTRY.search(entry))
    local  = bool(path and _LOCAL_SOURCE.search(path["source"])) or bool(entry and _LOCAL_ENTRY.search(entry))
    out = {}

    # exposure: who can reach this code
    if entry and _PUBLIC_ENTRY.search(entry):
        out["exposure"] = (4, f"reached from {entry}")
    elif path and _REMOTE_SOURCE.search(path["source"]):
        out["exposure"] = (4, f"consumes {path['source']}")
    elif entry or (path and local):
        out["exposure"] = (2, f"local input only ({entry or path['source']})")

    if path is None:
        if entry:
            out["exploitability"] = (4 if remote else 3,
                                     f"no traced taint path, but reachable from {entry}")
        return out

    guarded = path["sanitized_by"] or path["checks"]
    guard   = ", ".join((path["sanitized_by"] + path["checks"])[:2])
    src     = path["source"]

    # exploitability: remote + unguarded is the worst case
    if remote:
        score = 5 if (not guarded and entry) else 4
    elif local:
        score = 3
    else:
        score = 3
    if guarded:
        score -= 1
    out["exploitability"] = (score, f"{src} reaches the sink"
                                    + (f" past {guard}" if guarded else " with no sanitizer/check")
                                    + (f"; {entry}" if entry else ""))

    # attack_prerequisites: how much the attacker must know/arrange
    if guarded:
        out["attack_prerequisites"] = (2, f"must bypass {guard}")
    elif path["interprocedural"]:
        out["attack_prerequisites"] = (3, "input crosses function/file boundaries to the sink")
    else:
        out["attack_prerequisites"] = (4, "direct unchecked flow from input to sink")
    return out


# ─── Combination ───────────────────────────────────────────
def evidence_baselines(finding: dict, signals: list, profiler=None, cvss_vectors: Optional[list] = None) -> dict:
    """
    {dimension: {"score": int, "source": "cpg"|"cvss"|"cwe", "basis": str}} for
    every dimension that has evidence. Priority: code facts (CPG, CWE) over
    similar-CVE statistics (CVSS).
    """
    linked = linked_signals(finding, signals)
    out = {}

    for dim, (score, basis) in cpg_evidence(profiler, _lines(linked)).items():
        out[dim] = {"score": score, "source": "cpg", "basis": basis}

    cia = next((CWE_CIA[c] for c in _cwes(finding) if c in CWE_CIA), None)
    if cia:
        cwe = next(c for c in _cwes(finding) if c in CWE_CIA)
        for dim, score in zip(("confidentiality", "integrity", "availability"), cia):
            out[dim] = {"score": score, "source": "cwe", "basis": f"typical impact of {cwe}"}

    per_cve = [d for d in (cvss_dimensions(v) for v in (cvss_vectors or [])) if d]
    if per_cve:
        for dim in per_cve[0]:
            if dim in out:
                continue
            vals = [d[dim] for d in per_cve if dim in d]
            out[dim] = {"score": int(round(statistics.median(vals))), "source": "cvss",
                        "basis": f"median of {len(vals)} similar CVE(s)"}
    return out


# How far the LLM may move a baseline, by evidence source. CPG facts are about
# this exact code, so they are fixed; CWE norms and similar-CVE statistics are
# priors the LLM may refine with context it sees in the code.
MAX_LLM_SHIFT = {"cpg": 0, "cwe": 1, "cvss": 1}


def blend(baseline: Optional[dict], llm_score: Optional[int]) -> tuple:
    """(final score, llm shift applied). No baseline -> LLM score (default 3)."""
    if baseline is None:
        return (llm_score if llm_score is not None else 3), 0
    base = baseline["score"]
    if llm_score is None:
        return base, 0
    max_shift = MAX_LLM_SHIFT.get(baseline["source"], 1)
    shift = max(-max_shift, min(max_shift, llm_score - base))
    return max(1, min(5, base + shift)), shift
