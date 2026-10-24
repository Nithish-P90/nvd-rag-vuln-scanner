# agents/joern_cpg/security_profile.py
"""
Security-focused context extraction over a CPG view.

`SecurityProfiler.profile()` produces the file-level context the
ForensicsAgent sees instead of the raw file / whole graph:

  1. metadata            file, language, size, functions, classes, imports
  2. boundaries          entry points, untrusted parameters, where untrusted
                         data enters and where data leaves the process
  3. taint flows         source -> sink paths (Joern's interprocedural flows +
                         a CPG slice walk across callers), with sanitizers and
                         checks found on each path
  4. sinks / sources     labelled call sites (+ CWE)
  5. validation          sanitizers, validators, guard conditions
  6. control flow / deps per sink: controlling conditions (CDG), loops,
                         early exits, data dependencies
  7. call graph          callers/callees of security-relevant functions,
                         cross-file
  8. memory & resources  unreleased resources, use after release, double
                         release, unchecked allocations
  9. sensitive ops       crypto, RNG, credentials, privileged/debug settings
 10. code slice          line-numbered lines referenced above

`focused(...)` returns the same sections restricted to one function, used by
the ValidationAgent when it re-extracts context for a single finding.

Works without a CPG (tree-sitter/regex fallback) by scanning source lines;
sections that need the graph (data/control dependence, callers) are then
omitted.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from .graph import CPG, CPGMethod
from .security_catalog import catalog_for, compiled, family_of

_STRING_LIT = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_IDENT      = re.compile(r"[A-Za-z_]\w*")
_COMMENT    = re.compile(r"^\s*(?:#|//|/\*|\*)")
_LOOP_TYPES = {"WHILE", "FOR", "DO"}
_SKIP_PARAMS = {"self", "cls", "this"}

# Sink CWEs whose operation crosses a trust boundary (data leaves the process
# or controls something outside it).
BOUNDARY_CWES = {"CWE-78", "CWE-89", "CWE-94", "CWE-22", "CWE-79", "CWE-502",
                 "CWE-611", "CWE-918", "CWE-1427", "CWE-829"}

MAX_TRACE_DEPTH = 3          # caller hops for the slice-based taint walk
MAX_ITEMS       = 8          # items per section in the rendered profile


def _blank_strings(text: str) -> str:
    return _STRING_LIT.sub('""', text)


def _short(text: str, n: int = 100) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


@dataclass
class Site:
    kind:   str              # sources | sinks | sanitizers | sensitive
    label:  str
    cwe:    str
    file:   str
    line:   int
    code:   str
    method: Optional[str]    # CPGMethod.key, None without a CPG


@dataclass
class SecurityProfile:
    text:     str                       # rendered sections (no code)
    code:     str                       # line-numbered code slice
    sections: dict = field(default_factory=dict)   # title -> [items]
    stats:    dict = field(default_factory=dict)

    def render(self) -> str:
        return f"{self.text}\n\n## Relevant code (line-numbered)\n{self.code}" if self.code else self.text


class SecurityProfiler:
    def __init__(self, cpg: Optional[CPG], code: str, language: str = "unknown", file: str = ""):
        self.cpg      = cpg if (cpg is not None and cpg.methods) else None
        self.code     = code
        self.lines    = code.splitlines()
        lang          = language if family_of(language) else (cpg.language if cpg is not None else language)
        self.language = lang or "unknown"
        self.cat      = catalog_for(self.language)
        self.file     = file or (cpg.file if cpg is not None else "")
        if self.cpg is not None and not self.file:
            # Snippet CPGs are not file-scoped (cpg.file == ""), but Joern still
            # names the staged file (input.c). Without it, entry points and
            # Joern flows (which carry that name) never match this file.
            files = {m.file for m in self.cpg.methods.values() if m.file and not m.file.startswith("<")}
            if len(files) == 1:
                self.file = files.pop()
        self._sites: dict        = {}
        self._msites: dict       = {}
        self._entry_cache: dict  = {}
        self._paths: Optional[list] = None

    # ═══ low-level helpers ═════════════════════════════════
    def _text(self, line: int, file: Optional[str] = None) -> str:
        if self.cpg is not None:
            return self.cpg.line_text(line, file if file is not None and file != self.file else None)
        return self.lines[line - 1] if 1 <= line <= len(self.lines) else ""

    def _where(self, file: str, line: int) -> str:
        return f"L{line}" if file == self.file else f"{file}:{line}"

    def _mname(self, key: Optional[str]) -> str:
        if key is None or self.cpg is None:
            return "<file>"
        m = self.cpg.project_methods.get(key)
        return m.name if m else key

    def _match(self, kind: str, text: str) -> list:
        """[(label, cwe)] of catalog entries of `kind` matching `text`."""
        t = text if kind == "sensitive" else _blank_strings(text)
        hits = []
        for entry in self.cat.get(kind, []):
            if compiled(entry[0]).search(t):
                hits.append((entry[1], entry[2] if len(entry) > 2 else ""))
        return hits

    def _idents(self, lines, file: Optional[str] = None) -> set:
        out = set()
        for ln in lines:
            out |= set(_IDENT.findall(_blank_strings(self._text(ln, file))))
        return out

    def _own_lines(self, m: CPGMethod) -> list:
        """Lines of `m` that are not inside a nested method (matters for <module>)."""
        if not (m.line and m.end):
            return []
        nested = [
            (o.line, o.end) for o in self.cpg.project_methods.values()
            if o.file == m.file and o.key != m.key and o.line and o.end
            and m.line <= o.line and o.end <= m.end and o.span < m.span
        ]
        return [ln for ln in range(m.line, m.end + 1)
                if not any(a <= ln <= b for a, b in nested)]

    # ═══ call-site labelling ═══════════════════════════════
    def _method_sites(self, m: CPGMethod, kind: str) -> list:
        """Catalog matches among the calls of one method (any file)."""
        key = (m.key, kind)
        if key in self._msites:
            return self._msites[key]
        best: dict = {}
        for c in m.calls:
            line = c.get("line")
            code = (c.get("code") or "").split("\n")[0]    # first line: avoids matching whole def bodies
            if not line or not code:
                continue
            for label, cwe in self._match(kind, code):
                k = (label, line)
                if k not in best or len(code) < len(best[k].code):
                    best[k] = Site(kind, label, cwe, m.file, line, code, m.key)
        out = sorted(best.values(), key=lambda s: s.line)
        self._msites[key] = out
        return out

    def sites(self, kind: str) -> list:
        """Labelled sites of `kind` in this file."""
        if kind in self._sites:
            return self._sites[kind]
        out, seen = [], set()
        if self.cpg is not None:
            for m in sorted(self.cpg.methods.values(), key=lambda x: x.span):   # innermost first
                for s in self._method_sites(m, kind):
                    if (s.label, s.line) not in seen:
                        seen.add((s.label, s.line))
                        out.append(s)
        else:
            for i, src in enumerate(self.lines, 1):
                if _COMMENT.match(src):
                    continue
                for label, cwe in self._match(kind, src):
                    out.append(Site(kind, label, cwe, self.file, i, src.strip(), None))
        out.sort(key=lambda s: s.line)
        self._sites[kind] = out
        return out

    def _line_scan(self, kind: str, file: Optional[str] = None) -> list:
        """[(line, label)] for patterns that are not calls (validators, entry points)."""
        lines = self.cpg.lines_of(file) if (self.cpg is not None and file and file != self.file) else self.lines
        out = []
        for i, src in enumerate(lines, 1):
            if _COMMENT.match(src):
                continue
            t = _blank_strings(src) if kind != "entry_points" else src
            for entry in self.cat.get(kind, []):
                if compiled(entry[0]).search(t):
                    out.append((i, entry[1]))
                    break
        return out

    # ═══ entry points / boundaries ═════════════════════════
    def entry_points(self, file: Optional[str] = None) -> list:
        """[{label, line, method(CPGMethod|None)}] for `file` (default: this file)."""
        file = file if file is not None else self.file
        if file in self._entry_cache:
            return self._entry_cache[file]
        eps = []
        for line, label in self._line_scan("entry_points", file):
            m = None
            if self.cpg is not None:
                cands = [o for o in self.cpg.project_methods.values() if o.file == file]
                # decorator lines precede the def; take the method starting just below
                below = [o for o in cands if o.line and line <= o.line <= line + 4 and "<" not in o.name]
                m = min(below, key=lambda o: o.line) if below else None
                if m is None:
                    inside = [o for o in cands if o.contains(line)]
                    m = min(inside, key=lambda o: o.span) if inside else None
            eps.append({"label": label, "line": line, "method": m})
        self._entry_cache[file] = eps
        return eps

    def _entry_keys(self, file: str) -> set:
        return {e["method"].key for e in self.entry_points(file) if e["method"] is not None}

    def entry_chain(self, m: CPGMethod, max_depth: int = 4) -> Optional[list]:
        """Shortest caller chain [entry, ..., m] from an entry point to `m`, or None."""
        if self.cpg is None:
            return None
        frontier, seen = [[m]], {m.key}
        for _ in range(max_depth + 1):
            nxt = []
            for chain in frontier:
                head = chain[0]
                if head.key in self._entry_keys(head.file):
                    return chain
                for caller, _call in self.cpg.callers_of(head):
                    if caller.key not in seen:
                        seen.add(caller.key)
                        nxt.append([caller] + chain)
            frontier = nxt
            if not frontier:
                break
        return None

    # ═══ taint ═════════════════════════════════════════════
    def _trace(self, m: CPGMethod, seeds: set, depth: int, visited: frozenset) -> list:
        """
        Walk backwards from `seeds` in `m` over data dependence; when the slice
        reaches a parameter, continue from each caller's call site.
        Returns [{label, steps: [(file, line)], slices: {key: set(lines)}}].
        """
        if m is None or m.key in visited or depth > MAX_TRACE_DEPTH:
            return []
        visited = visited | {m.key}
        sl   = self.cpg.backward_slice(m, set(seeds), depth=None)
        top  = max(seeds)
        out  = []

        for s in self._method_sites(m, "sources"):
            if s.line in sl:
                steps = [(m.file, ln) for ln in sorted(sl) if s.line <= ln <= top]
                out.append({"label": s.label, "steps": steps or [(m.file, s.line)], "slices": {m.key: sl}})
        if out:
            return out

        params = {p.get("name") for p in m.params if p.get("name") not in _SKIP_PARAMS}
        used   = self._idents(sl, m.file) & params
        if not used:
            return []
        local_steps = [(m.file, m.line)] + [(m.file, ln) for ln in sorted(sl) if ln <= top and ln != m.line]

        if m.key in self._entry_keys(m.file):
            return [{"label": f"untrusted parameter {', '.join(sorted(used))} of entry point {m.name}",
                     "steps": local_steps, "slices": {m.key: sl}}]

        for caller, call in self.cpg.callers_of(m)[:4]:
            cl = call.get("line")
            if not cl:
                continue
            for up in self._trace(caller, {cl}, depth + 1, visited):
                slices = dict(up["slices"])
                slices[m.key] = sl
                out.append({"label": up["label"], "steps": up["steps"] + local_steps, "slices": slices})
        return out

    @staticmethod
    def _thin(steps: list, keep: int = 7) -> list:
        """Keep the first, last and a few middle steps of a long path."""
        uniq = list(dict.fromkeys(steps))
        if len(uniq) <= keep:
            return uniq
        mid = uniq[1:-1]
        stride = max(1, len(mid) // (keep - 2))
        return [uniq[0]] + mid[::stride][: keep - 2] + [uniq[-1]]

    def _checks_on(self, slices: dict, sink: Site, source_at=None) -> tuple:
        """
        (sanitizers, checks) found on the methods/lines of a path. A sanitizer
        on the source statement itself (e.g. sizeof() inside recv()) bounds
        the read, not the flow, so it does not count.
        """
        sans, checks = [], {}
        for key, sl in slices.items():
            m = self.cpg.project_methods.get(key) if self.cpg is not None else None
            if m is None:
                continue
            for s in self._method_sites(m, "sanitizers"):
                if s.line in sl and (m.file, s.line) != source_at:
                    sans.append(f"{s.label} @{self._where(m.file, s.line)}")
            vars_ = self._idents(sl, m.file)
            for cs in m.controls:
                cond = " ".join(cs.get("cond", [])) or cs.get("code", "")
                if cs.get("line") and set(_IDENT.findall(cond)) & vars_:
                    checks.setdefault((m.file, cs["line"]), f"{self._where(m.file, cs['line'])} {_short(cond, 60)}")
        if self.cpg is not None and sink.method:
            sm = self.cpg.project_methods.get(sink.method)
            if sm is not None:
                for ln in self.cpg.controllers_of(sm, sink.line)[:3]:
                    checks.setdefault((sm.file, ln), f"{self._where(sm.file, ln)} {_short(self._text(ln, sm.file).strip(), 60)}")
        return list(dict.fromkeys(sans))[:4], list(checks.values())[:4]

    def taint_paths(self) -> list:
        if self._paths is not None:
            return self._paths
        paths, seen = [], set()
        sinks = self.sites("sinks")

        def add(origin, label, sink, steps, slices, interproc):
            key = (label, steps[0] if steps else None, sink.line, sink.label)
            if key in seen:
                return
            seen.add(key)
            sans, checks = self._checks_on(slices, sink, steps[0] if steps else None) if slices else ([], [])
            paths.append({
                "origin": origin, "source": label, "sink": sink.label, "cwe": sink.cwe,
                "sink_line": sink.line, "sink_method": sink.method,
                "interprocedural": interproc,
                "steps": [f"{self._where(f, l)} {_short(self._text(l, f).strip(), 70)}" for f, l in self._thin(steps)],
                "lines": {(f, l) for f, l in steps},
                "sanitized_by": sans, "checks": checks,
            })

        if self.cpg is not None:
            by_line = {}
            for s in sinks:
                by_line.setdefault(s.line, s)
            # A. Joern interprocedural flows ending at a sink in this file
            for flow in self.cpg.flows:
                f_last, l_last, _ = flow[-1]
                if f_last != self.file or l_last not in by_line:
                    continue
                f0, l0, c0 = flow[0]
                label = next((lab for lab, _ in self._match("sources", c0)), "untrusted input")
                steps = [(f, l) for f, l, _ in flow]
                sm = self.cpg.project_methods.get(by_line[l_last].method) if by_line[l_last].method else None
                slices = {sm.key: {l for f, l in steps if f == sm.file}} if sm else {}
                add("joern", label, by_line[l_last], steps, slices, len({f for f, _ in steps}) > 1)
            # B. CPG slice walk (covers frontends where Joern's taint is shallow, e.g. Python)
            for s in sinks:
                m = self.cpg.project_methods.get(s.method) if s.method else None
                for t in self._trace(m, {s.line}, 0, frozenset()):
                    add("cpg-slice", t["label"], s, t["steps"], t["slices"], len(t["slices"]) > 1)
        else:
            # C. no graph: variable assigned from a source and later used by a sink
            tainted = {}
            for src in self.sites("sources"):
                mt = re.match(r"\s*(?:[\w\*\s]+\s)?\**(\w+)\s*(?:\[[^\]]*\])?\s*=", self._text(src.line))
                if mt:
                    tainted[mt.group(1)] = src
            for s in sinks:
                for var, src in tainted.items():
                    if src.line < s.line and re.search(rf"\b{re.escape(var)}\b", _blank_strings(self._text(s.line))):
                        add("heuristic", src.label, s, [(self.file, src.line), (self.file, s.line)], {}, False)

        paths.sort(key=lambda p: (p["sanitized_by"] != [], p["sink_line"]))
        self._paths = paths
        return paths

    # ═══ control flow / dependencies ═══════════════════════
    def sink_flow(self, s: Site) -> Optional[str]:
        if self.cpg is None or not s.method:
            return None
        m = self.cpg.project_methods.get(s.method)
        if m is None:
            return None
        parts = []
        ctl = self.cpg.controllers_of(m, s.line)
        if ctl:
            parts.append("controlled by " + "; ".join(
                f"L{ln} {_short(self._text(ln).strip(), 50)}" for ln in ctl[:3]))
        loops = [cs for cs in m.controls if cs.get("type") in _LOOP_TYPES and cs.get("line") and cs.get("end")
                 and cs["line"] <= s.line <= cs["end"]]
        if loops:
            parts.append("inside loop " + ", ".join(f"L{cs['line']}" for cs in loops[:2]))
        exits = [cs["line"] for cs in m.controls
                 if cs.get("line") and cs.get("end") and cs["end"] < s.line
                 and any(cs["line"] <= r.get("line", 0) <= cs["end"] for r in m.returns)]
        if exits:
            parts.append("early exit before it at " + ", ".join(f"L{x}" for x in exits[:3]))
        deps = sorted(d for d in self.cpg.backward_slice(m, {s.line}, depth=2) if d < s.line)
        if deps:
            parts.append("data deps " + ", ".join(f"L{d}" for d in deps[-6:]))
        if not parts:
            parts.append("unconditional; no in-function data dependencies")
        return f"L{s.line} {s.label} in {m.name}: " + " | ".join(parts)

    # ═══ memory & resource management ══════════════════════
    def resource_findings(self, only: Optional[str] = None) -> list:
        out = []
        if self.cpg is not None:
            scopes = [(m, self._own_lines(m)) for m in self.cpg.methods.values()
                      if only is None or m.key == only]
        else:
            scopes = [(None, list(range(1, len(self.lines) + 1)))]

        for kind, acq, rel in self.cat.get("resources", []):
            rx_a, rx_r = compiled(acq), compiled(rel)
            for m, own in scopes:
                name = m.name if m else "<file>"
                f    = m.file if m else self.file
                text = {ln: _blank_strings(self._text(ln, f)) for ln in own}
                acqs = [ln for ln in own if rx_a.search(text[ln])]
                rels = [ln for ln in own if rx_r.search(text[ln])]
                rets = " ".join(text[ln] for ln in own if re.match(r"\s*return\b", text[ln]))

                for a in acqs:
                    if rx_r.search(text[a]):                       # e.g. `with open(...)`
                        continue
                    mv  = re.match(r"\s*(?:[\w\*\s]+\s)?\**([\w.]+)\s*=", text[a])
                    var = mv.group(1) if mv else None
                    if var and (var.startswith("self.") or re.search(rf"\b{re.escape(var)}\b", rets)):
                        continue                                    # ownership handed to caller/object
                    if not rels:
                        out.append(f"{name}: {kind} acquired L{a}{f' ({var})' if var else ''} with no release in the function")
                    if kind == "heap memory" and var:
                        checked = any(ln > a and re.search(rf"\bif\b.*\b{re.escape(var)}\b", text[ln]) for ln in own)
                        if not checked:
                            out.append(f"{name}: allocation result {var} (L{a}) is never NULL-checked")

                released: dict = {}
                for r in rels:
                    mv  = re.search(r"\(\s*&?\s*([A-Za-z_]\w*)", text[r]) or re.search(r"([A-Za-z_]\w*)\s*\.\s*\w+\s*\(", text[r])
                    var = mv.group(1) if mv else None
                    if not var:
                        continue
                    if var in released:
                        reassigned = any(released[var] < ln < r and re.match(rf"\s*\**{re.escape(var)}\s*=", text[ln]) for ln in own)
                        if not reassigned:
                            out.append(f"{name}: {var} released twice (L{released[var]}, L{r})")
                    released[var] = r
                    for ln in own:
                        if ln <= r:
                            continue
                        if re.match(rf"\s*\**{re.escape(var)}\s*=", text[ln]):
                            break
                        if re.search(rf"\b{re.escape(var)}\b", text[ln]) and not rx_r.search(text[ln]):
                            out.append(f"{name}: {var} used at L{ln} after release at L{r}")
                            break
        return list(dict.fromkeys(out))

    # ═══ call graph ════════════════════════════════════════
    def call_graph(self, keys: list) -> list:
        if self.cpg is None:
            return []
        out = []
        for k in keys:
            m = self.cpg.project_methods.get(k)
            if m is None or "<" in m.name:
                continue
            callers = [f"{c.name}@{self._where(c.file, call.get('line') or 0)}"
                       for c, call in self.cpg.callers_of(m)][:4]
            callees = [c.name for c in self.cpg.callees_of(m)][:5]
            chain   = self.entry_chain(m)
            reach   = (" | reachable from entry point via " + " -> ".join(x.name for x in chain)) if chain and len(chain) > 1 else \
                      (" | is an entry point" if chain else "")
            out.append(
                f"{m.name} ({self._where(m.file, m.line or 0)}) <- callers: {', '.join(callers) or 'none in project'}"
                f" | -> callees: {', '.join(callees) or 'none in project'}{reach}"
            )
        return out

    # ═══ metadata ══════════════════════════════════════════
    def metadata(self, backend: str = "") -> list:
        loc = sum(1 for l in self.lines if l.strip())
        if self.cpg is not None:
            funcs = sorted({m.name for m in self.cpg.methods.values() if "<" not in m.name})
        else:
            funcs = sorted(set(re.findall(r"^\s*(?:def|function|func)\s+(\w+)", self.code, re.M)))
        classes = sorted(set(re.findall(r"^\s*(?:class|struct)\s+(\w+)", self.code, re.M)))
        imports = []
        for l in self.lines:
            mi = re.match(r"\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+)|#include\s*[<\"]([^>\"]+)|.*\brequire\s*\(\s*['\"]([^'\"]+))", l)
            if mi:
                imports.append(next(g for g in mi.groups() if g))
        items = [
            f"path: {self.file or '<snippet>'} | language: {self.language} | {loc} LOC | backend: {backend or ('cpg' if self.cpg else 'text')}",
            f"functions ({len(funcs)}): {', '.join(funcs[:15])}{' ...' if len(funcs) > 15 else ''}" if funcs else "functions: none (top-level code only)",
        ]
        if classes:
            items.append(f"classes/structs: {', '.join(classes[:10])}")
        if imports:
            items.append(f"imports: {', '.join(list(dict.fromkeys(imports))[:15])}")
        return items

    # ═══ file-level profile (ForensicsAgent) ═══════════════
    def profile(self, max_chars: int = 3500, code_chars: int = 2500, backend: str = "") -> SecurityProfile:
        sinks, sources = self.sites("sinks"), self.sites("sources")
        sans, sens     = self.sites("sanitizers"), self.sites("sensitive")
        paths          = self.taint_paths()
        eps            = self.entry_points()

        boundaries = []
        for e in eps:
            m = e["method"]
            if m is not None and "<" not in m.name:
                ps = [p["name"] for p in m.params if p.get("name") not in _SKIP_PARAMS]
                boundaries.append(f"{e['label']}: {m.name} (L{e['line']})" + (f" - untrusted params: {', '.join(ps)}" if ps else ""))
            else:
                boundaries.append(f"{e['label']} at L{e['line']}")
        for s in sources:
            boundaries.append(f"untrusted data enters: {s.label} at L{s.line} in {self._mname(s.method)}")
        for s in sinks:
            if s.cwe in BOUNDARY_CWES:
                boundaries.append(f"data leaves process: {s.label} at L{s.line} in {self._mname(s.method)}")

        taint = []
        for i, p in enumerate(paths, 1):
            tag = ("interprocedural, " if p["interprocedural"] else "") + p["origin"]
            guard = ("sanitized by " + "; ".join(p["sanitized_by"])) if p["sanitized_by"] else "NO sanitizer on path"
            if p["checks"]:
                guard += " | checks: " + "; ".join(p["checks"])
            taint.append(f"{i}. {p['source']} -> {p['sink']} [{p['cwe']}] ({tag})\n     "
                         + " -> ".join(p["steps"]) + f"\n     {guard}")
        tainted_sinks = {p["sink_line"] for p in paths}
        for s in sinks:
            if s.line not in tainted_sinks:
                taint.append(f"- {s.label} at L{s.line}: no source reaches it in the CPG (check arguments manually)")

        validation = [f"sanitizer: {s.label} at L{s.line} `{_short(s.code, 60)}`" for s in sans]
        validation += [f"check: {lab} at L{ln} `{_short(self._text(ln).strip(), 60)}`"
                       for ln, lab in self._line_scan("validators")]

        flow_items = [x for x in (self.sink_flow(s) for s in sinks) if x]

        keys = list(dict.fromkeys([s.method for s in sinks + sources if s.method]))
        cg   = self.call_graph(keys)

        sections = [
            ("File metadata",                          self.metadata(backend)),
            ("Security boundaries & entry points",      boundaries),
            ("Taint flows (source -> sink)",            taint),
            ("Sinks (security-sensitive operations)",   [f"L{s.line} {self._mname(s.method)}: `{_short(s.code, 70)}` - {s.label} [{s.cwe}]" for s in sinks]),
            ("Sources (untrusted input)",               [f"L{s.line} {self._mname(s.method)}: `{_short(s.code, 70)}` - {s.label}" for s in sources]),
            ("Validation, sanitization & security checks", validation),
            ("Control flow & program dependencies",     flow_items),
            ("Call graph (interprocedural)",            cg),
            ("Memory & resource management",            resources := self.resource_findings()),
            ("Security-sensitive operations",           [f"L{s.line} {self._mname(s.method)}: `{_short(s.code, 70)}` - {s.label} [{s.cwe}]" for s in sens]),
        ]
        text = self._render_sections(sections, max_chars)
        code = self._code_slice(sinks, sources, sans, paths, code_chars)
        return SecurityProfile(
            text=text, code=code, sections={t: i for t, i in sections},
            stats={"sinks": len(sinks), "sources": len(sources), "taint_paths": len(paths),
                   "unsanitized_paths": sum(1 for p in paths if not p["sanitized_by"]),
                   "entry_points": len(eps), "sensitive": len(sens),
                   "resource_issues": len(resources)},
        )

    # ═══ per-finding sections (ValidationAgent) ════════════
    def focused(self, facet: str, method: Optional[CPGMethod], anchors: set) -> list:
        """Items of one facet restricted to the finding's function / lines."""
        key   = method.key if method is not None else None
        in_fn = (lambda s: s.method == key) if key else (lambda s: True)

        if facet == "taint":
            out = []
            for p in self.taint_paths():
                if (key and p["sink_method"] == key) or (p["sink_line"] in anchors) or \
                        any(l in anchors for f, l in p["lines"] if f == self.file):
                    guard = ("sanitized by " + "; ".join(p["sanitized_by"])) if p["sanitized_by"] else "no sanitizer on path"
                    out.append(f"{p['source']} -> {p['sink']} [{p['cwe']}]: " + " -> ".join(p["steps"]) + f" ({guard})")
            return out or ["no source -> sink path reaches this code in the CPG"]
        if facet == "sanitizers":
            out = [f"sanitizer {s.label} at L{s.line} `{_short(s.code, 60)}`" for s in self.sites("sanitizers") if in_fn(s)]
            lo, hi = (method.line, method.end) if method is not None and method.line and method.end else (1, len(self.lines))
            out += [f"check {lab} at L{ln} `{_short(self._text(ln).strip(), 60)}`"
                    for ln, lab in self._line_scan("validators") if lo <= ln <= hi]
            return out or ["no sanitizer or validation check in this function"]
        if facet == "resources":
            return self.resource_findings(only=key) or ["no resource-management issue detected in this function"]
        if facet == "boundaries":
            if method is None or self.cpg is None:
                return [f"{e['label']} at L{e['line']}" for e in self.entry_points()] or ["no entry point found"]
            chain = self.entry_chain(method)
            if chain is None:
                return [f"no entry point in the project reaches {method.name}"]
            if len(chain) == 1:
                return [f"{method.name} is itself an entry point (its parameters are attacker-controlled)"]
            return ["reachable from entry point: " + " -> ".join(f"{m.name} ({self._where(m.file, m.line or 0)})" for m in chain)]
        if facet == "sensitive":
            return [f"L{s.line} `{_short(s.code, 60)}` - {s.label} [{s.cwe}]"
                    for s in self.sites("sensitive") if in_fn(s)] or ["no sensitive API use in this function"]
        return []

    # ═══ rendering ═════════════════════════════════════════
    @staticmethod
    def _render_sections(sections: list, max_chars: int) -> str:
        """Every non-empty section gets its first items before any gets more."""
        lines_by = {t: [] for t, _ in sections}
        used = 0
        for rnd in range(MAX_ITEMS):
            progress = False
            for title, items in sections:
                if rnd < len(items):
                    item = _short_multiline(items[rnd], 400)
                    cost = len(item) + 3 + (len(title) + 4 if rnd == 0 else 0)
                    if used + cost > max_chars:
                        continue
                    lines_by[title].append(item)
                    used += cost
                    progress = True
            if not progress:
                break
        out = []
        for title, items in sections:
            if not items:
                continue
            shown = lines_by[title]
            out.append(f"## {title}")
            out += [x if re.match(r"(?:-|\d+\.)\s", x) else f"- {x}" for x in shown]
            if len(items) > len(shown):
                out.append(f"  (+{len(items) - len(shown)} more)")
        return "\n".join(out)

    def _code_slice(self, sinks, sources, sans, paths, max_chars: int) -> str:
        prio: list = []                                  # priority-ordered line groups
        prio.append({s.line for s in sinks})
        prio.append({s.line for s in sources})
        prio.append({l for p in paths for f, l in p["lines"] if f == self.file})
        if self.cpg is not None:
            sig = set()
            for s in sinks + sources:
                m = self.cpg.project_methods.get(s.method) if s.method else None
                if m is not None and m.line and "<" not in m.name:
                    sig.add(m.line)
                if m is not None:
                    sig |= set(self.cpg.controllers_of(m, s.line))
            prio.append(sig)
        prio.append({s.line for s in sans})
        prio.append({s.line + d for s in sinks for d in (-1, 1)})

        if not any(prio):
            body = self.code[:max_chars]
            return "\n".join(f"{i:>4}: {l}" for i, l in enumerate(body.splitlines(), 1))

        chosen, used = set(), 0
        for group in prio:
            for ln in sorted(group):
                if ln in chosen or not (1 <= ln <= len(self.lines)):
                    continue
                cost = len(self.lines[ln - 1]) + 7
                if used + cost > max_chars:
                    continue
                chosen.add(ln)
                used += cost
        out, prev = [], None
        for ln in sorted(chosen):
            if prev is not None and ln > prev + 1:
                out.append("     ...")
            out.append(f"{ln:>4}: {self.lines[ln - 1]}")
            prev = ln
        return "\n".join(out)


def _short_multiline(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."
