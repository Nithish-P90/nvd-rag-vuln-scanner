# agents/joern_cpg/graph.py
"""
In-memory view of a Joern CPG.

One Joern run covers a whole project (per language). `CPG.from_json` loads
that project-wide summary; `CPG.view(file, code)` returns a per-file view that
the ContextExtractor works on, while cross-file queries (callers, callees,
callee bodies) still resolve against the whole project.

Method identity is `key` = "<file>::<fullName>", so same-named functions in
different files never collide.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CPGMethod:
    file:       str
    name:       str
    full_name:  str
    signature:  str
    line:       Optional[int]
    end:        Optional[int]
    params:     list = field(default_factory=list)    # {name, type, order}
    locals:     list = field(default_factory=list)    # {name, type, line, code}
    calls:      list = field(default_factory=list)    # {name, code, line, callee, args}
    controls:   list = field(default_factory=list)    # {type, code, line, end, cond}
    returns:    list = field(default_factory=list)    # {code, line}

    @property
    def key(self) -> str:
        return f"{self.file}::{self.full_name}"

    def contains(self, line: int) -> bool:
        return (
            self.line is not None and self.end is not None
            and self.line <= line <= self.end
        )

    @property
    def span(self) -> int:
        return (self.end - self.line) if self.line and self.end else 0


@dataclass
class CPG:
    source_lines:    list                                 # lines of `file` (this view)
    language:        str = "unknown"
    backend:         str = "joern"
    file:            str = ""                             # file this view is scoped to
    methods:         dict = field(default_factory=dict)   # key -> CPGMethod in `file`
    ddg:             list = field(default_factory=list)   # (method_key, from, to, var) in `file`
    project_methods: dict = field(default_factory=dict)   # key -> CPGMethod, whole project
    project_ddg:     list = field(default_factory=list)
    cdg:             list = field(default_factory=list)   # (method_key, controlling, controlled) in `file`
    project_cdg:     list = field(default_factory=list)
    flows:           list = field(default_factory=list)   # taint flows touching `file`: [(file, line, code), ...]
    project_flows:   list = field(default_factory=list)
    root:            Optional[Path] = None                # project root, to read other files
    _file_cache:     dict = field(default_factory=dict, repr=False)

    # ── construction ───────────────────────────────────────
    @classmethod
    def from_json(
        cls,
        data: dict,
        language: str = "unknown",
        root: Optional[Path] = None,
        source: str = "",
        file: Optional[str] = None,
    ) -> "CPG":
        """
        Load a Joern dump. `file=None` keeps every method in the view (used for
        single-snippet CPGs); otherwise the view is scoped to that file.
        """
        project = {}
        for m in data.get("methods", []):
            cm = CPGMethod(
                file      = (m.get("file") or "").replace("\\", "/"),
                name      = m.get("name", ""),
                full_name = m.get("fullName", m.get("name", "")),
                signature = m.get("signature", ""),
                line      = m.get("line"),
                end       = m.get("end"),
                params    = m.get("params", []),
                locals    = m.get("locals", []),
                calls     = m.get("calls", []),
                controls  = m.get("controls", []),
                returns   = m.get("returns", []),
            )
            project[cm.key] = cm

        project_ddg = []
        for e in data.get("ddg", []):
            f, full, a, b, v = e
            # Joern's VARIABLE value is sometimes the whole statement text; keep the first line.
            v = (v or "").split("\n")[0][:80]
            project_ddg.append((f"{f.replace(chr(92), '/')}::{full}", a, b, v))

        project_cdg = [
            (f"{f.replace(chr(92), '/')}::{full}", a, b)
            for f, full, a, b in data.get("cdg", [])
        ]
        project_flows = [
            [(f.replace("\\", "/"), line, code) for f, line, code in flow]
            for flow in data.get("flows", [])
        ]

        scoped_file = file if file is not None else ""
        if file is None:
            methods, ddg, cdg, flows = project, project_ddg, project_cdg, project_flows
        else:
            methods = {k: m for k, m in project.items() if m.file == file}
            ddg     = [e for e in project_ddg if e[0] in methods]
            cdg     = [e for e in project_cdg if e[0] in methods]
            flows   = [fl for fl in project_flows if any(st[0] == file for st in fl)]

        return cls(
            source_lines    = source.splitlines(),
            language        = language,
            file            = scoped_file,
            methods         = methods,
            ddg             = ddg,
            project_methods = project,
            project_ddg     = project_ddg,
            cdg             = cdg,
            project_cdg     = project_cdg,
            flows           = flows,
            project_flows   = project_flows,
            root            = root,
        )

    def view(self, file: str, code: str) -> "CPG":
        """Per-file view over the same project CPG; `code` is what the pipeline analyses."""
        file = file.replace("\\", "/")
        methods = {k: m for k, m in self.project_methods.items() if m.file == file}
        return CPG(
            source_lines    = code.splitlines(),
            language        = self.language,
            file            = file,
            methods         = methods,
            ddg             = [e for e in self.project_ddg if e[0] in methods],
            project_methods = self.project_methods,
            project_ddg     = self.project_ddg,
            cdg             = [e for e in self.project_cdg if e[0] in methods],
            project_cdg     = self.project_cdg,
            flows           = [fl for fl in self.project_flows if any(st[0] == file for st in fl)],
            project_flows   = self.project_flows,
            root            = self.root,
            _file_cache     = self._file_cache,
        )

    # ── source access ──────────────────────────────────────
    def lines_of(self, file: str) -> list:
        if file == self.file:
            return self.source_lines
        if file not in self._file_cache:
            lines = []
            if self.root is not None:
                try:
                    lines = (self.root / file).read_text(encoding="utf-8", errors="ignore").splitlines()
                except OSError:
                    lines = []
            self._file_cache[file] = lines
        return self._file_cache[file]

    def line_text(self, line: int, file: Optional[str] = None) -> str:
        lines = self.lines_of(file) if file is not None else self.source_lines
        return lines[line - 1] if 1 <= line <= len(lines) else ""

    # ── structural queries ─────────────────────────────────
    def method_at(self, line: int) -> Optional[CPGMethod]:
        """Innermost method in this view containing `line`."""
        hits = [m for m in self.methods.values() if m.contains(line)]
        return min(hits, key=lambda m: m.span) if hits else None

    def method_by_name(self, name: str, prefer_file: Optional[str] = None) -> Optional[CPGMethod]:
        matches = [m for m in self.project_methods.values()
                   if m.name == name or m.full_name == name]
        if not matches:
            return None
        if prefer_file:
            for m in matches:
                if m.file == prefer_file:
                    return m
        return matches[0]

    def callers_of(self, method: CPGMethod) -> list:
        """[(caller CPGMethod, call dict)] for every call site targeting `method`, project-wide."""
        out = []
        for m in self.project_methods.values():
            for c in m.calls:
                if c.get("callee") == method.full_name:
                    out.append((m, c))
                elif c.get("name") == method.name and m.file == method.file:
                    out.append((m, c))
        return out

    def callees_of(self, method: CPGMethod) -> list:
        """Project-defined methods called from `method`."""
        seen, out = set(), []
        for c in method.calls:
            tgt = self.method_by_name(c.get("callee") or c.get("name", ""), prefer_file=method.file)
            if tgt and tgt.key != method.key and tgt.key not in seen:
                seen.add(tgt.key)
                out.append(tgt)
        return out

    def controllers_of(self, method: CPGMethod, line: int) -> list:
        """Lines whose condition decides whether `line` runs (CDG), nearest first."""
        ctl = sorted({a for (k, a, b) in self.cdg if k == method.key and b == line}, reverse=True)
        return ctl

    # ── data-dependence slices (line level, within one method) ──
    def backward_slice(self, method: CPGMethod, lines: set, depth: Optional[int] = 3) -> set:
        """Lines whose definitions reach `lines` (transitively, up to `depth` hops)."""
        edges = [e for e in self.ddg if e[0] == method.key]
        result, frontier, hops = set(lines), set(lines), 0
        while frontier and (depth is None or hops < depth):
            nxt = {src for (_, src, dst, _) in edges if dst in frontier and src not in result}
            result |= nxt
            frontier = nxt
            hops += 1
        return result

    def forward_slice(self, method: CPGMethod, lines: set, depth: Optional[int] = 3) -> set:
        """Lines that use values defined at `lines` (e.g. use-after-free sites)."""
        edges = [e for e in self.ddg if e[0] == method.key]
        result, frontier, hops = set(lines), set(lines), 0
        while frontier and (depth is None or hops < depth):
            nxt = {dst for (_, src, dst, _) in edges if src in frontier and dst not in result}
            result |= nxt
            frontier = nxt
            hops += 1
        return result
