# agents/joern_cpg/runner.py
"""
Builds Code Property Graphs with the Joern CLI and loads them as `CPG` (graph.py).

Two modes:
  build_project(root, files, language)  – one CPG over every selected file of a
                                          project for one language (cross-file
                                          call graph). This is the scanner path.
  build(code, language)                 – CPG for a single snippet.

Joern location, in order: $JOERN_HOME/joern(.bat), DEFAULT_JOERN_HOME, `joern` on PATH.
If none is found, JoernUnavailable is raised and the caller falls back to
tree-sitter.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from .graph import CPG

SCRIPT_PATH       = Path(__file__).resolve().parent / "extract_cpg.sc"
DEFAULT_JOERN_HOME = Path(r"C:\tools\joern-cli") if os.name == "nt" else Path.home() / "bin" / "joern-cli"
TIMEOUT_SEC       = int(os.environ.get("JOERN_TIMEOUT", "1800"))

# Language -> frontend mapping lives with the security catalog.
from .security_catalog import LANGUAGE_MAP, catalog_for, joern_regex


class JoernUnavailable(RuntimeError):
    pass


class JoernRunner:
    def __init__(self, timeout: int = TIMEOUT_SEC):
        self.timeout = timeout
        self.joern   = self._find_joern()
        if self.joern is None:
            raise JoernUnavailable(
                "Joern not found. Install the CLI from https://github.com/joernio/joern/releases "
                "and set JOERN_HOME to its folder (the one containing joern.bat / joern)."
            )

    @staticmethod
    def _find_joern() -> Optional[str]:
        names = ("joern.bat", "joern") if os.name == "nt" else ("joern",)
        home = os.environ.get("JOERN_HOME")
        for base in filter(None, [home, str(DEFAULT_JOERN_HOME)]):
            for n in names:
                p = Path(base) / n
                if p.is_file():
                    return str(p)
        return shutil.which("joern")

    @staticmethod
    def supports(language: str) -> bool:
        return (language or "").lower() in LANGUAGE_MAP

    @staticmethod
    def frontend_for(language: str) -> Optional[str]:
        return LANGUAGE_MAP.get((language or "").lower())

    # ── public builders ────────────────────────────────────
    def build_project(self, root: Path, files: Iterable[str], language: str) -> CPG:
        """
        One CPG over `files` (paths relative to `root`) for one language.
        Only the selected files are staged for Joern, so ignored trees
        (venv, node_modules, datasets) are never imported.
        """
        frontend = self._require_frontend(language)
        root = Path(root).resolve()
        files = list(files)
        with tempfile.TemporaryDirectory(prefix="joern_stage_") as stage_tmp:
            stage = Path(stage_tmp) / "src"
            for rel in files:
                dst = stage / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / rel, dst)
            data = self._run(stage, frontend)
        return CPG.from_json(data, language=language, root=root)

    def build(self, code: str, language: str) -> CPG:
        """CPG for one snippet. Methods are not file-scoped (file = '')."""
        frontend = self._require_frontend(language)
        with tempfile.TemporaryDirectory(prefix="joern_snip_") as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            ext = {"c": ".c", "java": ".java", "js": ".js", "python": ".py",
                   "go": ".go", "php": ".php"}[frontend]
            (src / f"input{ext}").write_text(code, encoding="utf-8")
            data = self._run(src, frontend)
        return CPG.from_json(data, language=language, root=None, source=code)

    # ── internals ──────────────────────────────────────────
    def _require_frontend(self, language: str) -> str:
        frontend = self.frontend_for(language)
        if frontend is None:
            raise JoernUnavailable(f"Joern has no frontend for language '{language}'")
        return frontend

    def _run(self, src_dir: Path, frontend: str) -> dict:
        """
        Run the extraction script over `src_dir`.
        Each run gets a fresh working directory: Joern otherwise reuses the
        CPG of an earlier import with the same project name.
        """
        with tempfile.TemporaryDirectory(prefix="joern_work_") as work_tmp:
            work   = Path(work_tmp)
            script = work / "extract_cpg.sc"
            out    = work / "cpg.json"
            shutil.copy2(SCRIPT_PATH, script)

            env = dict(os.environ)
            env["JOERN_INPUT"]    = str(src_dir)
            env["JOERN_OUT"]      = str(out)
            env["JOERN_LANGUAGE"] = frontend
            cat = catalog_for(frontend)
            env["JOERN_SOURCE_RE"] = joern_regex(cat["sources"])
            env["JOERN_SINK_RE"]   = joern_regex(cat["sinks"])

            try:
                proc = subprocess.run(
                    [self.joern, "--script", str(script)],
                    cwd=work_tmp, env=env,
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=self.timeout,
                )
            except subprocess.TimeoutExpired as e:
                raise RuntimeError(f"Joern timed out after {self.timeout}s") from e

            if proc.returncode != 0 or not out.is_file():
                tail = _strip_ansi((proc.stderr or proc.stdout or ""))[-1500:]
                raise RuntimeError(f"Joern failed (exit {proc.returncode}): {tail}")

            return json.loads(out.read_text(encoding="utf-8"))


def _strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", text)
