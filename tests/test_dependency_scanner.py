# tests/test_dependency_scanner.py
"""
Unit tests for agents/dependency_scanner.py (no network: OSV is faked):
  - requirements.txt and package-lock.json parsing
  - CVSS 3.x base score and severity bands
  - fixed-version choice across backport ranges, alias de-duplication
  - end-to-end scan with a fake OSV, and the offline / failure path
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "agents"))

import dependency_scanner as ds


def osv_record(vid, name, fixed, eco="PyPI", aliases=(), severity="HIGH"):
    return {
        "id": vid, "aliases": list(aliases), "summary": f"{vid} summary",
        "database_specific": {"severity": severity},
        "affected": [{"package": {"ecosystem": eco, "name": name},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}] + [{"fixed": f} for f in fixed]}]}],
    }


class TestManifests(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_requirements(self):
        req = self.dir / "requirements.txt"
        req.write_text("# web\nfastapi==0.104.1\nPillow[webp]==10.1.0 ; python_version>'3.8'\n"
                       "requests>=2.0\n-r other.txt\nnumpy  # unpinned\n\n")
        pinned, unpinned = ds.parse_requirements(req)
        self.assertEqual(pinned, [("fastapi", "0.104.1"), ("pillow", "10.1.0")])
        self.assertEqual(unpinned, ["requests", "numpy"])

    def test_package_lock_v3(self):
        lock = self.dir / "package-lock.json"
        lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/react": {"version": "19.2.4"},
            "node_modules/vite": {"version": "5.4.21", "dev": True},
            "node_modules/a/node_modules/nanoid": {"version": "3.3.11", "dev": True},
            "node_modules/local": {"link": True},
        }}))
        self.assertEqual(ds.parse_package_lock(lock), [
            ("nanoid", "3.3.11", True), ("react", "19.2.4", False), ("vite", "5.4.21", True)])

    def test_package_lock_v1(self):
        lock = self.dir / "package-lock.json"
        lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}}}}))
        self.assertEqual(ds.parse_package_lock(lock), [("a", "1.0.0", False), ("b", "2.0.0", True)])

    def test_discovery_skips_ignored_dirs(self):
        (self.dir / "node_modules" / "x").mkdir(parents=True)
        (self.dir / "node_modules" / "x" / "package-lock.json").write_text("{}")
        (self.dir / "backend").mkdir()
        (self.dir / "backend" / "requirements-dev.txt").write_text("")
        found = ds.discover_manifests(self.dir, lambda d: d == "node_modules", lambda p: False)
        self.assertEqual([p.relative_to(self.dir).as_posix() for p in found], ["backend/requirements-dev.txt"])


class TestSeverityAndVersions(unittest.TestCase):

    def test_cvss3_scores(self):
        self.assertEqual(ds.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(ds.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 7.5)
        self.assertEqual(ds.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertIsNone(ds.cvss3_base_score("CVSS:4.0/AV:N/AC:L"))

    def test_severity_prefers_advisory_label(self):
        self.assertEqual(ds.advisory_severity({"database_specific": {"severity": "MODERATE"}})[0], "MEDIUM")
        vec = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(ds.advisory_severity(vec), ("CRITICAL", 9.8))
        self.assertEqual(ds.advisory_severity({})[0], "UNKNOWN")

    def test_version_order(self):
        self.assertGreater(ds.version_key("0.0.18"), ds.version_key("0.0.7"))
        self.assertGreater(ds.version_key("10.3.0"), ds.version_key("10.1.0"))

    def test_fixed_version_picks_lowest_above_installed(self):
        rec = osv_record("GHSA-x", "pillow", ["9.5.1", "10.3.0", "11.0.0"])
        self.assertEqual(ds.fixed_version(rec, "PyPI", "Pillow", "10.1.0"), "10.3.0")
        self.assertIsNone(ds.fixed_version(rec, "npm", "pillow", "10.1.0"))

    def test_dedupe_prefers_ghsa(self):
        kept = ds._dedupe([{"id": "PYSEC-1", "aliases": ["CVE-1"]},
                           {"id": "GHSA-a", "aliases": ["CVE-1", "PYSEC-1"]},
                           {"id": "GHSA-b", "aliases": ["CVE-2"]}])
        self.assertEqual([v["id"] for v in kept], ["GHSA-a", "GHSA-b"])


class TestScan(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "requirements.txt").write_text("pillow==10.1.0\nnumpy==1.26.2\n")
        (self.dir / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/vite": {"version": "5.4.21", "dev": True}}}))
        self.records = {
            "GHSA-p1": osv_record("GHSA-p1", "pillow", ["10.2.0"], aliases=["CVE-1", "PYSEC-1"], severity="HIGH"),
            "PYSEC-1": osv_record("PYSEC-1", "pillow", ["10.2.0"], aliases=["CVE-1", "GHSA-p1"]),
            "GHSA-p2": osv_record("GHSA-p2", "pillow", ["10.3.0"], aliases=["CVE-2"], severity="CRITICAL"),
            "GHSA-v1": osv_record("GHSA-v1", "vite", ["6.4.4"], eco="npm", severity="MODERATE"),
        }
        self.sent = []

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def fake_fetch(self, url, payload):
        if payload is not None:
            self.sent.append(payload)
            hits = {"pillow": ["GHSA-p1", "PYSEC-1", "GHSA-p2"], "vite": ["GHSA-v1"]}
            return {"results": [{"vulns": [{"id": i} for i in hits.get(q["package"]["name"], [])]}
                                if hits.get(q["package"]["name"]) else {} for q in payload["queries"]]}
        return self.records[url.rsplit("/", 1)[-1]]

    def test_scan_reports_packages(self):
        r = ds.scan_dependencies(self.dir, fetch=self.fake_fetch)
        self.assertEqual(r["packages_checked"], 3)
        self.assertEqual(r["errors"], [])
        pillow, vite = r["vulnerable"]
        self.assertEqual((pillow["name"], pillow["dev"], pillow["severity"], pillow["fixed_version"]),
                         ("pillow", False, "CRITICAL", "10.3.0"))
        self.assertEqual([a["id"] for a in pillow["advisories"]], ["GHSA-p2", "GHSA-p1"])
        self.assertEqual((vite["name"], vite["dev"], vite["severity"]), ("vite", True, "MEDIUM"))
        # Only names and versions are sent.
        self.assertIn({"package": {"name": "pillow", "ecosystem": "PyPI"}, "version": "10.1.0"},
                      self.sent[0]["queries"])
        self.assertEqual({tuple(q) for q in self.sent[0]["queries"]}, {("package", "version")})

    def test_offline_returns_error_not_findings(self):
        def down(url, payload):
            raise OSError("network unreachable")
        r = ds.scan_dependencies(self.dir, fetch=down)
        self.assertEqual(r["vulnerable"], [])
        self.assertIn("dependencies were not checked", r["errors"][0])

    def test_no_manifests(self):
        empty = Path(tempfile.mkdtemp())
        try:
            r = ds.scan_dependencies(empty, fetch=self.fake_fetch)
            self.assertEqual((r["packages_checked"], r["vulnerable"], self.sent), (0, [], []))
        finally:
            shutil.rmtree(empty, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
