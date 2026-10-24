# tests/test_validation_guardrails.py
"""
Unit tests for the ValidationAgent guardrails (agents/validation_guardrails.py):
  - fixed threat taxonomy: every CWE maps to exactly one category
  - classification from CWE, then from category keywords, else OTHER
  - detection of validator reasoning that contradicts its verdict
  - scoring weights / thresholds and the hard gates
"""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "agents"))

import validation_guardrails as vg


class FakeSite:
    def __init__(self, line, label, cwe):
        self.line, self.label, self.cwe = line, label, cwe


class FakeProfiler:
    """Minimal profiler: one sink at `line`, optional taint path, no CPG."""
    cpg = None

    def __init__(self, sink_line=None, cwe="CWE-78", path=None, sensitive=None):
        self._sinks = [FakeSite(sink_line, "OS command execution", cwe)] if sink_line else []
        self._sensitive = sensitive or []
        self._paths = [path] if path else []

    def sites(self, kind):
        return {"sinks": self._sinks, "sensitive": self._sensitive}.get(kind, [])

    def resource_findings(self):
        return []

    def taint_paths(self):
        return self._paths


CODE = 'import os\nhost = input()\nos.system("ping " + host)\n'
SIGNAL = {"affected_code": 'os.system("ping " + host)', "line": 3}
FINDING = {"category": "Command Injection", "cwe_ids": ["CWE-78"], "evidence": "os.system"}


def path(sanitized=False, checks=False):
    return {"source": "stdin input", "sink_line": 3, "origin": "heuristic",
            "sanitized_by": ["shell quoting @L3"] if sanitized else [],
            "checks": ["L2 if host"] if checks else []}


class TestTaxonomy(unittest.TestCase):

    def test_each_cwe_in_one_category(self):
        seen = {}
        for cat in vg.THREAT_TAXONOMY:
            for cwe in cat["cwes"]:
                self.assertNotIn(cwe, seen, f"{cwe} in {seen.get(cwe)} and {cat['id']}")
                seen[cwe] = cat["id"]

    def test_every_category_defined(self):
        for cat in vg.THREAT_TAXONOMY:
            self.assertTrue(cat["definition"])
            self.assertIn(cat["kind"], ("taint", "intrinsic", "access"))

    def test_classify_by_cwe_then_keywords(self):
        self.assertEqual(vg.classify({"cwe_ids": ["CWE-89"]}), "INJECTION")
        self.assertEqual(vg.classify({"cwe_ids": ["cwe-416"]}), "MEMORY_LIFECYCLE")
        self.assertEqual(vg.classify({"cwe_ids": ["NVD-CWE-Other"], "category": "Weak Crypto"}), "CRYPTO")
        self.assertEqual(vg.classify({"category": "Buffer Overflow"}), "MEMORY_CORRUPTION")
        self.assertEqual(vg.classify({"category": "Something odd"}), "OTHER")


class TestContradiction(unittest.TestCase):

    def test_fp_with_vulnerable_reasoning(self):
        self.assertTrue(vg.llm_contradiction(
            "FALSE_POSITIVE", "The code is vulnerable to OS Command Injection because it directly injects input"))

    def test_consistent_verdicts(self):
        self.assertFalse(vg.llm_contradiction("FALSE_POSITIVE", "The input is properly sanitized with shlex.quote"))
        self.assertFalse(vg.llm_contradiction("CONFIRMED", "host is not sanitized and allows an attacker to run commands"))


class TestDecision(unittest.TestCase):

    def run_case(self, profiler, llm="CONFIRMED", reason="allows an attacker to run commands",
                 finding=FINDING, signal=SIGNAL, code=CODE):
        return vg.assess(finding, code, profiler, [3], [signal], llm, reason)

    def test_proven_unsanitized_confirmed(self):
        g = self.run_case(FakeProfiler(3, path=path()))
        self.assertEqual(g["verdict"], "CONFIRMED")
        self.assertEqual(g["score"], 100)

    def test_g1_statement_not_in_code(self):
        g = self.run_case(FakeProfiler(3, path=path()),
                          signal={"affected_code": "cursor.execute(query)", "line": 9}, code="x = 1\n")
        self.assertEqual(g["verdict"], "FALSE_POSITIVE")
        self.assertTrue(g["rule"].startswith("G1"))

    def test_g3_sanitized_never_confirmed(self):
        g = self.run_case(FakeProfiler(3, path=path(sanitized=True)))
        self.assertNotEqual(g["verdict"], "CONFIRMED")
        g = self.run_case(FakeProfiler(3, path=path(sanitized=True)), llm="FALSE_POSITIVE",
                          reason="input is properly sanitized")
        self.assertEqual(g["verdict"], "FALSE_POSITIVE")

    def test_g4_no_operation_evidence(self):
        g = self.run_case(FakeProfiler(None, path=path()))
        self.assertNotEqual(g["verdict"], "CONFIRMED")

    def test_unknown_reach_needs_context(self):
        # No CPG and no taint path: attacker control unknown -> not auto-confirmed.
        g = self.run_case(FakeProfiler(3))
        self.assertEqual(g["parameters"]["attacker_control"]["value"], "unknown")
        self.assertEqual(g["verdict"], "NEEDS_CONTEXT")

    def test_validator_fp_low_evidence_is_false_positive(self):
        g = self.run_case(FakeProfiler(None), llm="FALSE_POSITIVE", reason="not exploitable here")
        self.assertEqual(g["verdict"], "FALSE_POSITIVE")

    def test_intrinsic_category_needs_operation(self):
        crypto = {"category": "Weak Crypto", "cwe_ids": ["CWE-327"], "evidence": "md5"}
        sig = {"affected_code": "hashlib.md5(pw)", "line": 1}
        code = "h = hashlib.md5(pw)\n"
        with_op = FakeProfiler(sensitive=[FakeSite(1, "weak cryptography", "CWE-327")])
        self.assertEqual(vg.assess(crypto, code, with_op, [1], [sig], "CONFIRMED", "md5 is broken")["verdict"],
                         "CONFIRMED")
        self.assertNotEqual(vg.assess(crypto, code, FakeProfiler(), [1], [sig], "CONFIRMED", "md5 is broken")["verdict"],
                            "CONFIRMED")


IMAGE_CODE = ("from PIL import Image\nimport io\n"
              "def blend(original_bytes):\n"
              "    return Image.open(io.BytesIO(original_bytes)).convert('RGB')\n")


class TestMemorySafetyGate(unittest.TestCase):
    """G0: manual-memory flaws cannot be written in memory-safe languages."""

    def test_use_after_free_in_python_ruled_out(self):
        uaf = {"category": "Use After Free", "cwe_ids": ["CWE-416"]}
        self.assertIn("G0", vg.memory_safety_gate(uaf, "python", IMAGE_CODE))

    def test_keyword_without_cwe_ruled_out(self):
        self.assertIsNotNone(vg.memory_safety_gate({"category": "Heap Buffer Overflow"}, "javascript", "x = 1"))

    def test_c_keeps_memory_findings(self):
        self.assertIsNone(vg.memory_safety_gate({"category": "Use After Free", "cwe_ids": ["CWE-416"]}, "c", "free(p);"))

    def test_native_interop_keeps_memory_findings(self):
        code = "import ctypes\nbuf = ctypes.create_string_buffer(8)\n"
        self.assertIsNone(vg.memory_safety_gate({"cwe_ids": ["CWE-787"]}, "python", code))

    def test_other_categories_untouched(self):
        self.assertIsNone(vg.memory_safety_gate({"category": "Path Traversal", "cwe_ids": ["CWE-22"]}, "python", IMAGE_CODE))
        # Resource leaks are real in managed languages.
        self.assertIsNone(vg.memory_safety_gate({"category": "Memory Leak", "cwe_ids": ["CWE-401"]}, "java", ""))


class TestFixRegressions(unittest.TestCase):

    def test_bytes_to_path_fix_rejected(self):
        added = vg.fix_regressions("Image.open(io.BytesIO(original_bytes))",
                                   "Image.open(os.path.normpath(image_bytes.decode('utf-8')))", "python")
        self.assertEqual(added, ["filesystem path use (CWE-22)"])
        self.assertTrue(vg.fix_regressions("Image.open(io.BytesIO(b))", "cv2.imread(os.path.normpath(p))", "python"))

    def test_same_kind_replacement_allowed(self):
        self.assertEqual(vg.fix_regressions('os.system("ping " + host)',
                                            'subprocess.run(["ping", host], check=True)', "python"), [])

    def test_fix_without_sink_allowed(self):
        self.assertEqual(vg.fix_regressions("pickle.loads(data)", "json.loads(data)", "python"), [])


class TestPythonPathCatalog(unittest.TestCase):
    """CWE-22 sinks and sanitizers for Python."""

    def setUp(self):
        from joern_cpg.security_catalog import catalog_for, compiled
        cat = catalog_for("python")
        self.sink = compiled(next(p for p, _, cwe in cat["sinks"] if cwe == "CWE-22"))
        self.sanitizer = compiled(next(p for p, label in cat["sanitizers"] if label == "path normalisation"))

    def test_in_memory_stream_is_not_a_path(self):
        self.assertIsNone(self.sink.search("Image.open(io.BytesIO(original_bytes)).convert('RGB')"))
        self.assertIsNone(self.sink.search("Image.open( BytesIO(data) )"))

    def test_real_paths_still_sinks(self):
        for code in ("open(user_path)", "Image.open(filename)", "cv2.imread(path)", "zf.extractall(dest)"):
            self.assertIsNotNone(self.sink.search(code), code)

    def test_normalisation_alone_is_not_a_sanitizer(self):
        for code in ("os.path.normpath(p)", "os.path.abspath(p)", "os.path.realpath(p)", "Path(p).resolve()"):
            self.assertIsNone(self.sanitizer.search(code), code)
        self.assertIsNotNone(self.sanitizer.search("secure_filename(name)"))


if __name__ == "__main__":
    unittest.main()
