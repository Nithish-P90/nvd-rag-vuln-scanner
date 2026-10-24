# tests/test_report_integrity.py
"""
Regression tests for the Ai-ad-visual-optimiser audit, where the report
  - confirmed a "Use After Free" in Python and a path traversal on
    Image.open(io.BytesIO(...)),
  - suggested fixes that turned image bytes into a file path,
  - showed backend/main.py with no content (unresolved findings dropped),
  - and missed outdated dependencies entirely.
No LLM or network: agents' model calls are stubbed.
"""

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for p in (_ROOT / "agents", _ROOT / "rag"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from orchestrator2 import AdvisoryAgent, PipelineState, ValidationAgent
from project_scanner import FileScanResult, ProjectReportFormatter, ProjectScanResult, file_status

CODE = ("from PIL import Image\nimport io\n"
        "def blend_images(original_bytes):\n"
        "    return Image.open(io.BytesIO(original_bytes)).convert('RGB')\n")
UAF = {"category": "Use After Free", "severity": "MEDIUM", "cwe_ids": ["CWE-416"],
       "evidence": "Image.open(io.BytesIO(original_bytes))"}
PATH = {"category": "Filesystem Path Use without Sanitization", "severity": "MEDIUM", "cwe_ids": ["CWE-22"],
        "evidence": "Image.open(io.BytesIO(original_bytes))"}


def validation_state():
    return PipelineState(code=CODE, language="python", ranked_findings=[dict(UAF), dict(PATH)])


class TestValidationAgent(unittest.TestCase):

    def agent(self, batch):
        a = ValidationAgent()
        a._get_model = lambda: "llama3.2"
        a._validate_batch = batch
        return a

    def test_failure_confirms_nothing(self):
        def boom(state, model):
            raise RuntimeError("ollama down")
        state = self.agent(boom).run(validation_state())
        self.assertEqual(state.validated_findings, [])
        self.assertEqual(len(state.needs_context_findings), 2)
        self.assertFalse(state.is_clean)
        self.assertIn("not verified", state.needs_context_findings[0]["reasoning"])

    def test_unparseable_response_confirms_nothing(self):
        state = self.agent(lambda s, m: None).run(validation_state())
        self.assertEqual(state.validated_findings, [])
        self.assertEqual(len(state.needs_context_findings), 2)

    def test_memory_gate_overrides_llm(self):
        confirmed = lambda s, m: [{**f, "verdict": "CONFIRMED", "reasoning": "x"} for f in s.ranked_findings]
        state = self.agent(confirmed).run(validation_state())
        self.assertEqual([f["category"] for f in state.false_positives], ["Use After Free"])
        self.assertIn("G0", state.false_positives[0]["reasoning"])
        self.assertEqual([f["category"] for f in state.validated_findings], [PATH["category"]])


class TestAdvisoryCheck(unittest.TestCase):

    def test_bytes_to_path_fix_withheld(self):
        state = PipelineState(code=CODE, language="python", validated_findings=[PATH])
        advs = AdvisoryAgent()._withhold_regressions(state, [{
            "category": PATH["category"],
            "fix_description": "Pass the user input through os.path.normpath()",
            "fixed_code": "Image.open(os.path.normpath(image_bytes.decode('utf-8')))",
        }])
        self.assertNotIn("fixed_code", advs[0])
        self.assertIn("filesystem path use", advs[0]["fix_warning"])

    def test_safe_fix_kept(self):
        state = PipelineState(code="os.system(cmd)", language="python",
                              validated_findings=[{"category": "Command Injection", "evidence": "os.system(cmd)"}])
        advs = AdvisoryAgent()._withhold_regressions(state, [{
            "category": "Command Injection", "fixed_code": "subprocess.run(['ping', host], check=True)"}])
        self.assertIn("fixed_code", advs[0])


def file_result(path, findings=(), needs=(), clean=True, errors=()):
    return FileScanResult(
        filepath=path, relative_path=path, language="python", size_bytes=10, lines_of_code=1,
        is_clean=clean, findings_count=len(findings), severity_breakdown={}, validated_findings=list(findings),
        false_positives=[], explanations=[], advisories=[], cve_matches=[], errors=list(errors),
        scan_duration_sec=0.1, needs_context=list(needs))


class TestReport(unittest.TestCase):

    def setUp(self):
        files = [
            file_result("backend/generator.py"),
            file_result("backend/main.py", clean=False,
                        needs=[{"category": "Permissive CORS", "severity": "MEDIUM", "reasoning": "allow_origins=*"}]),
            file_result("backend/big.py", clean=False,
                        errors=[{"agent": "ProjectScanner", "error": "File skipped: size limit"}]),
            file_result("backend/x.py", findings=[{"category": "SQL Injection", "severity": "HIGH",
                                                   "reasoning": "</script><img src=x onerror=alert(1)>"}], clean=False),
        ]
        for f in files:
            f.status = file_status(f)
        self.result = ProjectScanResult(
            project_name="demo", source_type="git_repo", source_path="https://example.invalid/demo",
            scan_start_time="2026-10-22 13:47:33", scan_duration_sec=1.0, total_files_found=4,
            total_files_scanned=4, total_files_skipped=0, total_lines_of_code=4, total_vulnerabilities=1,
            severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}, clean_files_count=1,
            vulnerable_files_count=1, false_positives_filtered=0, security_score=60, security_grade="C",
            top_cwes=[], top_cves=[], files=files, unresolved_files_count=1, incomplete_files_count=1,
            dependencies={"source": "OSV.dev", "manifests": ["requirements.txt"], "packages_checked": 1,
                          "unpinned": [], "errors": [], "vulnerable": [{
                              "ecosystem": "PyPI", "name": "pillow", "version": "10.1.0", "manifest": "requirements.txt",
                              "dev": False, "severity": "CRITICAL", "fixed_version": "13.0.0",
                              "advisories": [{"id": "GHSA-8g5g-8vmr-9782", "cves": [], "severity": "CRITICAL",
                                              "summary": "Heap buffer overflow in ImagingJpegDecode", "cvss_score": None,
                                              "fixed": "13.0.0", "url": "https://osv.dev/vulnerability/GHSA-8g5g-8vmr-9782"}]}]},
        )

    def test_every_file_has_one_status(self):
        self.assertEqual([f.status for f in self.result.files], ["clean", "unresolved", "incomplete", "vulnerable"])

    def test_markdown_lists_unresolved_and_dependencies(self):
        md = ProjectReportFormatter.format_markdown(self.result)
        self.assertIn("Needs Manual Review", md)
        self.assertIn("backend/main.py", md)
        self.assertIn("Permissive CORS", md)
        self.assertIn("backend/big.py", md)
        self.assertIn("pillow (PyPI) | 10.1.0 | runtime | **CRITICAL**", md)

    def test_terminal_lists_unresolved_and_dependencies(self):
        out = ProjectReportFormatter.format_terminal(self.result)
        self.assertIn("backend/main.py", out)
        self.assertIn("pillow 10.1.0", out)

    def test_html_cannot_break_out_of_script(self):
        html = ProjectReportFormatter.format_html(self.result)
        body = html.split("const reportData = ", 1)[1].split("\n", 1)[0]
        self.assertNotIn("</script>", body)


if __name__ == "__main__":
    unittest.main()
