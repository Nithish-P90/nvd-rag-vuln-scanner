# agents/joern_cpg/context.py
"""
CPG-driven context extraction for the LLM.

Instead of feeding the model the whole file/CPG, `ContextExtractor.extract()`
returns a small, finding-specific slice:

  base (always):  the anchor statement(s), the enclosing method signature,
                  the backward data-dependence slice of the anchor, and the
                  guarding control structures.
  on request:     extra facets named in a `ContextRequest` — more data flow,
                  callers, callees, declarations, the full function, or every
                  use of specific symbols.

The ValidationAgent calls `extract()` again with a bigger request whenever
the model answers NEEDS_CONTEXT, so only the missing context is added.
"""

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

from .graph import CPG, CPGMethod
from .security_profile import SecurityProfiler, SecurityProfile

# Facets a context request may name (also the menu offered to the LLM).
FACETS = (
    "data_flow",       # unbounded backward slice + forward slice of anchors
    "guards",          # every branch/loop in the method touching slice variables
    "callers",         # call sites of the enclosing method (how args arrive)
    "callees",         # bodies of in-file functions called from the slice
    "declarations",    # file-level #define/typedef/struct/global lines
    "full_function",   # the whole enclosing function
    "taint",           # source -> sink paths touching the finding (interprocedural)
    "sanitizers",      # sanitizers / validation checks in the enclosing function
    "resources",       # memory & resource management issues in the function
    "boundaries",      # entry point reachability (is the input attacker-controlled?)
    "sensitive",       # crypto / credential / privileged API use in the function
)

# Facets answered by the SecurityProfiler (rendered as facts, not code lines).
PROFILE_FACETS = ("taint", "sanitizers", "resources", "boundaries", "sensitive")

# CWE -> sink function names used to locate the anchor when evidence text is vague.
CWE_SINKS = {
    "CWE-120": ["strcpy", "strcat", "gets", "sprintf", "memcpy", "strncpy"],
    "CWE-121": ["strcpy", "strcat", "gets", "sprintf", "memcpy"],
    "CWE-122": ["malloc", "calloc", "realloc", "memcpy"],
    "CWE-787": ["strcpy", "memcpy", "memmove", "memset", "sprintf"],
    "CWE-119": ["memcpy", "memmove", "memset", "strcpy"],
    "CWE-190": ["malloc", "calloc", "realloc"],
    "CWE-416": ["free", "delete"],
    "CWE-415": ["free", "delete"],
    "CWE-476": ["malloc", "calloc", "realloc", "fopen"],
    "CWE-134": ["printf", "fprintf", "sprintf", "syslog", "snprintf"],
    "CWE-78":  ["system", "popen", "exec", "execl", "execv", "execvp", "subprocess", "os.system"],
    "CWE-89":  ["execute", "executemany", "query", "raw"],
    "CWE-94":  ["eval", "exec"],
    "CWE-502": ["loads", "load", "unserialize", "ObjectInputStream", "readObject"],
    "CWE-22":  ["open", "fopen", "send_file", "readFile"],
    "CWE-79":  ["innerHTML", "write", "html"],
    "CWE-327": ["MD5", "SHA1", "DES", "RC4"],
    "CWE-798": [],
}


@dataclass
class ContextRequest:
    """What the validator wants beyond the base slice."""
    facets:  list = field(default_factory=list)   # subset of FACETS
    symbols: list = field(default_factory=list)   # identifiers whose every use is wanted

    def merge(self, other: "ContextRequest") -> "ContextRequest":
        return ContextRequest(
            facets  = list(dict.fromkeys(self.facets + other.facets)),
            symbols = list(dict.fromkeys(self.symbols + other.symbols)),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExtractedContext:
    code:        str                       # line-numbered source slice
    facts:       str                       # compact structural notes
    anchors:     list                      # anchor line numbers
    method:      Optional[str]
    facets:      list
    truncated:   bool = False
    source:      str  = "cpg"              # "cpg" | "fallback"

    def render(self, with_facts: bool = True) -> str:
        if with_facts and self.facts:
            return f"{self.code}\n\n{self.facts}"
        return self.code


class ContextExtractor:
    def __init__(self, cpg: Optional[CPG], code: str, ast_functions: Optional[list] = None,
                 language: str = "unknown"):
        self.cpg = cpg
        self.code = code
        self.lines = code.splitlines()
        self.ast_functions = ast_functions or []
        self.profiler = SecurityProfiler(cpg, code, language,
                                         file=cpg.file if cpg is not None else "")

    def profile(self, max_chars: int = 3500, code_chars: int = 2500,
                backend: str = "") -> SecurityProfile:
        """File-level security context for the ForensicsAgent."""
        return self.profiler.profile(max_chars=max_chars, code_chars=code_chars, backend=backend)

    # ── public ─────────────────────────────────────────────
    def extract(
        self,
        finding: dict,
        request: Optional[ContextRequest] = None,
        max_chars: int = 1200,
    ) -> ExtractedContext:
        request = request or ContextRequest()
        if self.cpg is None or not self.cpg.methods:
            return self._fallback(finding, request, max_chars)

        anchors = self._locate_anchors(finding)
        if not anchors:
            return self._fallback(finding, request, max_chars)

        method = self.cpg.method_at(anchors[0])
        if method is None:
            return self._fallback(finding, request, max_chars)

        # Priority-ordered line groups; earlier groups survive truncation.
        groups: list = []        # [(label, set(lines))]
        facts:  list = []
        anchor_set = set(anchors)

        groups.append(("anchor", anchor_set))
        if method.line:
            groups.append(("signature", {method.line}))

        depth = None if "data_flow" in request.facets else 3
        back  = self.cpg.backward_slice(method, anchor_set, depth)
        groups.append(("data_flow", back))
        if "data_flow" in request.facets:
            groups.append(("forward_flow", self.cpg.forward_slice(method, anchor_set, None)))

        slice_vars = self._vars_in(back | anchor_set)
        guard_lines, guard_facts = self._guards(method, anchor_set, slice_vars,
                                                all_guards="guards" in request.facets)
        groups.append(("guards", guard_lines))
        facts += guard_facts

        # Declarations of variables in the slice (buffer sizes, types).
        decl = {l["line"] for l in method.locals
                if l.get("line") and l.get("name") in slice_vars}
        groups.append(("locals", decl))
        facts += self._param_facts(method, slice_vars)

        if request.symbols:
            groups.append(("symbols", self._symbol_uses(method, request.symbols)))
        if "full_function" in request.facets and method.line and method.end:
            groups.append(("full_function", set(range(method.line, method.end + 1))))
        if "declarations" in request.facets:
            groups.append(("declarations", self._file_level_decls(slice_vars | set(request.symbols))))

        extra_blocks: list = []
        if "callers" in request.facets:
            extra_blocks += self._caller_blocks(method)
        if "callees" in request.facets:
            extra_blocks += self._callee_blocks(method, back | anchor_set)

        for facet in request.facets:
            if facet in PROFILE_FACETS:
                facts += [f"{facet}: {item}" for item in
                          self.profiler.focused(facet, method, anchor_set)[:4]]

        code, truncated = self._render(groups, extra_blocks, max_chars)
        facts.insert(0, f"Enclosing function: {method.signature or method.name} "
                        f"(lines {method.line}-{method.end}) in {method.file or 'snippet'}")
        return ExtractedContext(
            code=code, facts="\n".join(f"- {f}" for f in facts if f),
            anchors=sorted(anchors), method=method.key,
            facets=list(request.facets), truncated=truncated, source="cpg",
        )

    # ── anchor location ────────────────────────────────────
    def _locate_anchors(self, finding: dict) -> list:
        evidence = str(finding.get("evidence", "")) + " " + str(finding.get("affected_code", ""))
        cwes     = [str(c).upper() for c in (finding.get("cwe_ids") or [])]
        sinks    = {s for c in cwes for s in CWE_SINKS.get(c, [])}

        scored: dict = {}   # line -> score
        for m in self.cpg.methods.values():
            for c in m.calls:
                line = c.get("line")
                name = c.get("name", "")
                if not line or name.startswith("<operator>"):
                    continue
                score = 0
                if name in sinks:
                    score += 2
                if name and re.search(rf"\b{re.escape(name)}\b", evidence):
                    score += 2
                code = c.get("code", "")
                if len(code) > 6 and code in evidence:
                    score += 3
                if score:
                    scored[line] = max(scored.get(line, 0), score)

        # Literal evidence snippets (quoted code, lines of affected_code).
        for frag in re.findall(r"`([^`]+)`|([A-Za-z_][\w.]*\s*\([^)]*\))", evidence):
            text = (frag[0] or frag[1]).strip()
            if len(text) < 5:
                continue
            for i, src in enumerate(self.lines, 1):
                if text in src:
                    scored[i] = max(scored.get(i, 0), 3)

        ranked = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0]))
        return [line for line, _ in ranked[:5]]

    # ── facets ─────────────────────────────────────────────
    def _vars_in(self, lines: set) -> set:
        idents = set()
        for ln in lines:
            idents |= set(re.findall(r"[A-Za-z_]\w*", self.cpg.line_text(ln)))
        return idents

    def _guards(self, method: CPGMethod, anchors: set, slice_vars: set, all_guards: bool):
        lines, facts = set(), []
        for cs in method.controls:
            start, end = cs.get("line"), cs.get("end")
            if not start:
                continue
            encloses = end is not None and any(start <= a <= end for a in anchors)
            cond     = " ".join(cs.get("cond", [])) or cs.get("code", "")
            mentions = bool(set(re.findall(r"[A-Za-z_]\w*", cond)) & slice_vars)
            # `if (bad) return;` before the anchor guards it without enclosing it.
            early_exit = (
                end is not None and mentions and end < min(anchors)
                and any(start <= r.get("line", 0) <= end for r in method.returns)
            )
            if encloses or early_exit or (all_guards and mentions):
                lines.add(start)
                facts.append(f"{cs.get('type', 'branch')} at line {start}: {cond[:80]}")
        return lines, facts[:6]

    def _param_facts(self, method: CPGMethod, slice_vars: set) -> list:
        out = []
        for p in method.params:
            if p.get("name") in slice_vars:
                out.append(f"param {p['name']}: {p.get('type', '?')} (caller-controlled)")
        for l in method.locals:
            if l.get("name") in slice_vars and l.get("type"):
                out.append(f"local {l['name']}: {l['type']}")
        return out[:8]

    def _symbol_uses(self, method: CPGMethod, symbols: list) -> set:
        pats = [re.compile(rf"\b{re.escape(s)}\b") for s in symbols if s]
        lo, hi = method.line or 1, method.end or len(self.lines)
        return {i for i in range(lo, hi + 1)
                if any(p.search(self.cpg.line_text(i)) for p in pats)}

    def _file_level_decls(self, names: set) -> set:
        out = set()
        covered = [(m.line, m.end) for m in self.cpg.methods.values() if m.line and m.end]
        for i, src in enumerate(self.lines, 1):
            if any(a <= i <= b for a, b in covered):
                continue
            if re.match(r"\s*(#define|typedef|struct|enum|union|const|static|extern|import|from)\b", src) \
                    or re.match(r"\s*[A-Za-z_][\w\s\*]*\s+\w+\s*(=|;|\[)", src):
                if not names or set(re.findall(r"[A-Za-z_]\w*", src)) & names:
                    out.add(i)
        return out

    def _caller_blocks(self, method: CPGMethod) -> list:
        blocks = []
        for caller, call in self.cpg.callers_of(method)[:3]:
            ln = call.get("line")
            if not ln:
                continue
            lo = max(caller.line or 1, ln - 3)
            hi = min(caller.end or ln, ln + 1)
            body = self._numbered(range(lo, hi + 1), caller.file)
            blocks.append(
                f"// caller {caller.name} in {caller.file} "
                f"(args: {', '.join(call.get('args', [])[:4])})\n{body}"
            )
        if not blocks:
            blocks.append(f"// no callers of {method.name} found in the project — arguments are external input")
        return blocks

    def _callee_blocks(self, method: CPGMethod, lines: set) -> list:
        called = {c.get("name") for c in method.calls if c.get("line") in lines}
        blocks = []
        for callee in self.cpg.callees_of(method):
            if callee.name in called and callee.line and callee.end:
                body = self._numbered(range(callee.line, min(callee.end, callee.line + 25) + 1), callee.file)
                blocks.append(f"// callee {callee.name} in {callee.file}\n{body}")
        return blocks[:3]

    # ── rendering ──────────────────────────────────────────
    def _numbered(self, lines, file: Optional[str] = None) -> str:
        return "\n".join(f"{i:>4}: {self.cpg.line_text(i, file)}" for i in lines)

    def _render(self, groups: list, extra_blocks: list, max_chars: int):
        chosen: set = set()
        used, truncated = 0, False
        for _, lines in groups:
            for ln in sorted(lines):
                if ln in chosen or not (1 <= ln <= len(self.lines)):
                    continue
                cost = len(self.cpg.line_text(ln)) + 7
                if used + cost > max_chars:
                    truncated = True
                    continue
                chosen.add(ln)
                used += cost

        out, prev = [], None
        for ln in sorted(chosen):
            if prev is not None and ln > prev + 1:
                out.append("     ...")
            out.append(f"{ln:>4}: {self.cpg.line_text(ln)}")
            prev = ln

        for block in extra_blocks:
            if used + len(block) > max_chars * 2:     # extra blocks get their own headroom
                truncated = True
                break
            out.append("")
            out.append(block)
            used += len(block)
        return "\n".join(out), truncated

    # ── fallback when Joern/CPG is unavailable ─────────────
    def _fallback(self, finding: dict, request: ContextRequest, max_chars: int) -> ExtractedContext:
        evidence = str(finding.get("evidence", "")) + " " + str(finding.get("affected_code", ""))
        hit = None
        for i, src in enumerate(self.lines, 1):
            s = src.strip()
            if len(s) > 5 and s in evidence:
                hit = i
                break
        want_full = "full_function" in request.facets or "data_flow" in request.facets
        facts = "\n".join(
            f"- {facet}: {item}"
            for facet in request.facets if facet in PROFILE_FACETS
            for item in self.profiler.focused(facet, None, {hit} if hit else set())[:4]
        )
        if hit is None:
            body = self.code[:max_chars * (3 if want_full else 1)]
            return ExtractedContext(body, facts, [], None, list(request.facets),
                                    truncated=len(self.code) > len(body), source="fallback")
        radius = 25 if want_full else 6
        lo, hi = max(1, hit - radius), min(len(self.lines), hit + radius)
        body = "\n".join(f"{i:>4}: {self.lines[i-1]}" for i in range(lo, hi + 1))
        return ExtractedContext(body[:max_chars * (3 if want_full else 1)], facts, [hit], None,
                                list(request.facets), source="fallback")
