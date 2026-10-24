# tests/test_security_profile.py
"""
Unit tests for the CPG security context extractor (joern_cpg.SecurityProfiler)
and its use by the ForensicsAgent.

Fixtures are real Joern 4.0.654 dumps (extract_cpg.sc) of two small programs:
  fixtures/cpg/app.py  – Flask route -> SQL query across two functions
  fixtures/cpg/net.c   – recv/argv -> strcpy, use after free, FILE leak
No Joern or LLM is needed to run these tests.
"""

import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for p in (_ROOT / "agents", _ROOT / "rag"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from joern_cpg import CPG, ContextExtractor, ContextRequest, SecurityProfiler
from orchestrator2 import ForensicsAgent, PipelineState

_FIX = _ROOT / "tests" / "fixtures" / "cpg"

SECTIONS = (
    "File metadata",
    "Security boundaries & entry points",
    "Taint flows (source -> sink)",
    "Sinks (security-sensitive operations)",
    "Sources (untrusted input)",
    "Validation, sanitization & security checks",
    "Control flow & program dependencies",
    "Call graph (interprocedural)",
)


def _load(rel: str, language: str):
    code = (_FIX / rel).read_text(encoding="utf-8")
    data = json.loads((_FIX / f"{rel.replace('.', '_')}.cpg.json").read_text(encoding="utf-8"))
    project = CPG.from_json(data, language=language, root=_FIX)
    return project.view(rel, code), code


class TestPythonProfile(unittest.TestCase):

    def setUp(self):
        self.view, self.code = _load("app.py", "python")
        self.prof = SecurityProfiler(self.view, self.code, "python").profile()

    def test_all_sections_present(self):
        for title in SECTIONS:
            self.assertIn(f"## {title}", self.prof.text, title)
        self.assertIn("6:     name = request.args.get", self.prof.code)

    def test_interprocedural_unsanitized_sql_taint(self):
        p = SecurityProfiler(self.view, self.code, "python").taint_paths()
        sql = [x for x in p if x["cwe"] == "CWE-89"]
        self.assertTrue(sql, "expected a request -> execute path")
        path = sql[0]
        self.assertEqual(path["source"], "HTTP request data")
        self.assertEqual(path["sanitized_by"], [])
        self.assertTrue(any("L10" in s for s in path["steps"]), "path must cross the run(q) call")
        self.assertTrue(path["steps"][-1].startswith("L14"))

    def test_entry_point_and_reachability(self):
        self.assertIn("HTTP route handler: get_user", self.prof.text)
        self.assertIn("reachable from entry point via get_user -> run", self.prof.text)

    def test_focused_facets_for_validation(self):
        ex = ContextExtractor(self.view, self.code, language="python")
        finding = {"category": "SQL Injection", "cwe_ids": ["CWE-89"],
                   "evidence": "cur.execute(q) with concatenated user input"}
        ctx = ex.extract(finding, ContextRequest(["taint", "boundaries", "sanitizers"]), max_chars=2400)
        self.assertEqual(ctx.source, "cpg")
        self.assertIn("taint: HTTP request data -> SQL execution", ctx.facts)
        self.assertIn("boundaries: reachable from entry point", ctx.facts)


class TestCProfile(unittest.TestCase):

    def setUp(self):
        self.view, self.code = _load("net.c", "c")
        self.profiler = SecurityProfiler(self.view, self.code, "c")
        self.prof = self.profiler.profile()

    def test_memory_and_resource_findings(self):
        res = self.profiler.resource_findings()
        self.assertTrue(any("p used at L18 after release at L17" in r for r in res), res)
        self.assertTrue(any("FILE stream acquired L19" in r for r in res), res)
        self.assertTrue(any("never NULL-checked" in r for r in res), res)

    def test_taint_into_strcpy_across_calls(self):
        paths = self.profiler.taint_paths()
        strcpy = [p for p in paths if p["cwe"] == "CWE-120"]
        self.assertTrue(strcpy)
        self.assertTrue(any(p["interprocedural"] for p in strcpy))

    def test_sanitizer_on_source_line_does_not_sanitize_flow(self):
        recv_paths = [p for p in self.profiler.taint_paths()
                      if p["source"] == "network/file read" and p["cwe"] == "CWE-120"]
        self.assertTrue(recv_paths)
        self.assertEqual(recv_paths[0]["sanitized_by"], [])

    def test_control_dependence_and_entry_chain(self):
        self.assertIn("controlled by L14 if (n <= 0)", self.prof.text)
        self.assertIn("main -> handle -> copy_name", self.prof.text)
        self.assertIn("untrusted params: argc, argv", self.prof.text)


class TestFallbackWithoutCPG(unittest.TestCase):

    def test_line_scan_profile(self):
        code = (_FIX / "app.py").read_text(encoding="utf-8")
        prof = SecurityProfiler(None, code, "python").profile()
        self.assertIn("SQL execution", prof.text)
        self.assertIn("HTTP request data", prof.text)
        self.assertIn("backend: text", prof.text)


class TestForensicsAgentUsesContext(unittest.TestCase):

    def test_prompt_contains_cpg_context_not_raw_file(self):
        view, code = _load("app.py", "python")
        state = PipelineState(code=code, language="python")
        state.cpg_backend = "joern-project"
        state.cpg_extractor = ContextExtractor(view, code, language="python")

        agent, seen = ForensicsAgent(), {}

        def fake_llm(prompt, model, temperature=0, schema=None):
            seen["prompt"] = prompt
            return '[{"vulnerability_type": "SQL injection", "affected_code": "cur.execute(q)",' \
                   ' "cwe_id": "CWE-89", "confidence": "HIGH", "line": 14}]'

        agent._llm = fake_llm
        agent._log = lambda *_: None
        state = agent.run(state)

        prompt = seen["prompt"]
        for title in ("Taint flows (source -> sink)", "Security boundaries & entry points",
                      "Call graph (interprocedural)", "Relevant code (line-numbered)"):
            self.assertIn(title, prompt)
        self.assertEqual(state.forensics_signals[0]["line"], 14)
        self.assertEqual(state.security_stats["taint_paths"], 1)
        self.assertIn("Taint flows", state.security_context)


if __name__ == "__main__":
    unittest.main()
