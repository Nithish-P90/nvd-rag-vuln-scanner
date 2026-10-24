# tests/test_benchmark_scorer.py
"""
Tests for tests/benchmark/score_scan.py, so a PASS from the grader means
something: a scan matching the answer key passes, and each kind of mistake
the original Ai-ad-visual-optimiser report made fails it.
"""

import copy
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "agents"))
sys.path.insert(0, str(_ROOT / "tests" / "benchmark"))

import score_scan  # noqa: E402

TRUTH = json.loads((_ROOT / "tests" / "benchmark" / "ground_truth.json").read_text(encoding="utf-8"))
SEEDED_FILES = sorted(p.relative_to(_ROOT / "tests" / "benchmark" / "seeded_repo").as_posix()
                      for p in (_ROOT / "tests" / "benchmark" / "seeded_repo").rglob("*")
                      if p.suffix in (".py", ".js"))


def perfect_scan() -> dict:
    files = {p: {"relative_path": p, "validated_findings": [], "needs_context": [], "status": "clean"}
             for p in SEEDED_FILES}
    for exp in TRUTH["expected"]:
        files[exp["file"]]["validated_findings"].append(
            {"category": exp["desc"], "severity": "HIGH", "cwe_ids": [exp["cwe"]]})
        files[exp["file"]]["status"] = "vulnerable"
    deps = [{"ecosystem": d["ecosystem"], "name": d["name"], "version": d["version"], "dev": d["dev"],
             "severity": "HIGH", "fixed_version": "9.9.9",
             "advisories": [{"id": "GHSA-x", "cves": [d["cve"]], "severity": "HIGH"}]}
            for d in TRUTH["dependencies"]["vulnerable"]]
    scan = {"files": list(files.values()), "total_files_scanned": len(files),
            "severity_counts": {"HIGH": len(TRUTH["expected"])},
            "dependency_severity_counts": {"HIGH": sum(1 for d in deps if not d["dev"])},
            "dependencies": {"vulnerable": deps, "unpinned": [{"name": n} for n in TRUTH["dependencies"]["unpinned"]],
                             "errors": []},
            "security_grade": "F"}
    scan["security_score"] = 0
    for status in ("vulnerable", "unresolved", "incomplete", "clean"):
        scan[f"{status}_files_count"] = sum(1 for f in scan["files"] if f["status"] == status)
    return scan


def file_of(scan, path):
    return next(f for f in scan["files"] if f["relative_path"] == path)


class TestScorer(unittest.TestCase):

    def test_answer_key_files_exist(self):
        for exp in TRUTH["expected"] + TRUTH["must_not_flag"]:
            self.assertIn(exp["file"], SEEDED_FILES)

    def test_perfect_scan_passes(self):
        report, failed = score_scan.score(perfect_scan(), TRUTH)
        self.assertFalse(failed, report)
        self.assertIn("recall 100%", report)

    def test_missed_vulnerability_fails(self):
        scan = perfect_scan()
        file_of(scan, "app/users.py")["validated_findings"] = []
        report, failed = score_scan.score(scan, TRUTH)
        self.assertTrue(failed)
        self.assertIn("SQLI-1", report.split("MISSED")[0].splitlines()[-1])

    def test_bytesio_path_traversal_is_a_violation(self):
        scan = perfect_scan()
        file_of(scan, "app/thumbnails.py")["validated_findings"] = [
            {"category": "Use After Free", "severity": "MEDIUM", "cwe_ids": ["CWE-416"]}]
        report, failed = score_scan.score(scan, TRUTH)
        self.assertTrue(failed)
        self.assertIn("must-not-flag", report)

    def test_tolerated_category_not_penalised(self):
        scan = perfect_scan()
        file_of(scan, "app/thumbnails.py")["validated_findings"] = [
            {"category": "Unbounded upload", "severity": "LOW", "cwe_ids": ["CWE-400"]}]
        scan["severity_counts"]["LOW"] = 1
        scan["security_score"] = 0
        _, failed = score_scan.score(scan, TRUTH)
        self.assertFalse(failed)

    def test_unresolved_safe_file_fails(self):
        scan = perfect_scan()
        f = file_of(scan, "app/safe_ops.py")
        f["status"], f["needs_context"] = "unresolved", [{"category": "SQL Injection", "cwe_ids": ["CWE-89"]}]
        scan["clean_files_count"] -= 1
        scan["unresolved_files_count"] += 1
        report, failed = score_scan.score(scan, TRUTH)
        self.assertTrue(failed)
        self.assertIn("FAIL app/safe_ops.py: unresolved", report)

    def test_missing_dependency_scan_fails(self):
        scan = perfect_scan()
        scan["dependencies"] = {}
        report, failed = score_scan.score(scan, TRUTH)
        self.assertTrue(failed)
        self.assertIn("dependency scan missing", report)

    def test_inconsistent_buckets_fail(self):
        scan = perfect_scan()
        scan["clean_files_count"] += 1
        _, failed = score_scan.score(copy.deepcopy(scan), TRUTH)
        self.assertTrue(failed)


if __name__ == "__main__":
    unittest.main()
