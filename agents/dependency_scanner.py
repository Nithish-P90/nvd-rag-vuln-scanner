# agents/dependency_scanner.py
"""
Dependency (software composition) scan for the ProjectScanner.

The code pipeline only reads source files, so a project pinned to a library
version with known CVEs looked clean. This module reads the project's
manifests, asks OSV.dev (which aggregates GitHub advisories, PyPA and NVD
CVE ids) which pinned versions are affected, and reports one entry per
vulnerable package.

Manifests:
  requirements*.txt    exact pins (name==version); other specifiers are
                       listed as unpinned, since the installed version is unknown
  package-lock.json    lockfile v1, v2 and v3; dev-only packages are marked

Only package names and versions leave the machine. Without network access
the scan returns an error entry and no findings, and the rest of the
project scan is unaffected.
"""

import json
import math
import os
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{}"
OSV_PAGE_URL  = "https://osv.dev/vulnerability/{}"
OSV_BATCH_MAX = 1000          # OSV's limit on queries per batch call
HTTP_TIMEOUT  = 20
FETCH_WORKERS = 8

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|===)\s*([^\s;#,]+)")
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


# ─── Manifest parsing ──────────────────────────────────────

def parse_requirements(path: Path) -> tuple:
    """([(name, version)], [unpinned names]) from a pip requirements file."""
    pinned, unpinned = [], []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:", "https:")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            pinned.append((m.group(1).lower(), m.group(3)))
        elif _REQ_NAME.match(line):
            unpinned.append(_REQ_NAME.match(line).group(1).lower())
    return pinned, unpinned


def parse_package_lock(path: Path) -> list:
    """[(name, version, dev)] from an npm package-lock.json."""
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore") or "{}")
    out = []
    if isinstance(data.get("packages"), dict):                  # lockfile v2 / v3
        for key, meta in data["packages"].items():
            if not key or meta.get("link") or not meta.get("version"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            out.append((name, meta["version"], bool(meta.get("dev") or meta.get("devOptional"))))
    else:                                                       # lockfile v1
        def walk(deps: dict):
            for name, meta in (deps or {}).items():
                if meta.get("version"):
                    out.append((name, meta["version"], bool(meta.get("dev"))))
                walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return sorted(set(out))


def discover_manifests(base_dir: Path, skip_dir: Callable[[str], bool],
                       is_excluded: Callable[[str], bool]) -> List[Path]:
    found = []
    for root, dirs, files in os.walk(base_dir):
        rel_root = Path(root).relative_to(base_dir).as_posix()
        rel_root = "" if rel_root == "." else rel_root + "/"
        dirs[:] = [d for d in dirs if not skip_dir(d) and not is_excluded(rel_root + d)]
        for name in files:
            if name == "package-lock.json" or re.fullmatch(r"requirements[\w.-]*\.txt", name):
                found.append(Path(root) / name)
    return sorted(found)


# ─── Versions and severity ─────────────────────────────────

def version_key(v: str) -> list:
    """Sortable key: numeric parts compare as numbers ("0.0.18" > "0.0.7")."""
    return [(1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[A-Za-z]+", v or "")]


_CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """CVSS v3.0/3.1 base score from a vector string, or None."""
    if not str(vector).startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope = m["S"]
        iss = 1 - ((1 - _CVSS3_W["C"][m["C"]]) * (1 - _CVSS3_W["C"][m["I"]]) * (1 - _CVSS3_W["C"][m["A"]]))
        impact = (6.42 * iss if scope == "U"
                  else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15)
        expl = 8.22 * _CVSS3_W["AV"][m["AV"]] * _CVSS3_W["AC"][m["AC"]] * _CVSS3_PR[scope][m["PR"]] * _CVSS3_W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = impact + expl if scope == "U" else 1.08 * (impact + expl)
    return _roundup(min(raw, 10))


def severity_of_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def advisory_severity(vuln: dict) -> tuple:
    """(severity, cvss score or None) for an OSV record."""
    score = None
    for s in vuln.get("severity") or []:
        score = cvss3_base_score(s.get("score", "")) if score is None else score
    label = str((vuln.get("database_specific") or {}).get("severity") or "").upper()
    label = {"MODERATE": "MEDIUM"}.get(label, label)
    if label in SEVERITY_ORDER[1:]:
        return label, score
    return severity_of_score(score), score


def fixed_version(vuln: dict, ecosystem: str, name: str, installed: str) -> Optional[str]:
    """Lowest version above `installed` that fixes this advisory for the package."""
    fixes = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            fixes += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    above = [f for f in fixes if version_key(f) > version_key(installed)]
    return min(above, key=version_key) if above else None


# ─── OSV client ────────────────────────────────────────────

def _http_json(url: str, payload: Optional[dict] = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _query_ids(queries: list, fetch: Callable) -> list:
    """Advisory ids per query, in query order."""
    ids = []
    for i in range(0, len(queries), OSV_BATCH_MAX):
        chunk = queries[i:i + OSV_BATCH_MAX]
        results = fetch(OSV_BATCH_URL, {"queries": chunk}).get("results", [])
        ids += [[v["id"] for v in (r.get("vulns") or [])] for r in results]
        ids += [[] for _ in range(len(chunk) - len(results))]
    return ids


def _dedupe(vulns: list) -> list:
    """One record per issue: a GHSA and the PYSEC/CVE ids it aliases are the same advisory."""
    kept, seen = [], set()
    for v in sorted(vulns, key=lambda v: (not v["id"].startswith("GHSA-"), v["id"])):
        keys = {v["id"], *(v.get("aliases") or [])}
        if keys & seen:
            continue
        seen |= keys
        kept.append(v)
    return kept


# ─── Entry point ───────────────────────────────────────────

def scan_dependencies(base_dir: Path, skip_dir: Callable[[str], bool] = lambda d: False,
                      is_excluded: Callable[[str], bool] = lambda p: False,
                      fetch: Callable[[str, Optional[dict]], dict] = _http_json) -> Dict:
    """
    Returns {
      "source", "manifests", "packages_checked",
      "vulnerable": [{ecosystem, name, version, manifest, dev, severity, fixed_version,
                      advisories: [{id, cves, summary, severity, cvss_score, fixed, url}]}],
      "unpinned": [{manifest, name}], "errors": [str]
    }
    """
    base_dir = Path(base_dir).resolve()
    result = {"source": "OSV.dev", "manifests": [], "packages_checked": 0,
              "vulnerable": [], "unpinned": [], "errors": []}

    packages = []   # (ecosystem, name, version, manifest, dev)
    for path in discover_manifests(base_dir, skip_dir, is_excluded):
        rel = path.relative_to(base_dir).as_posix()
        try:
            if path.name == "package-lock.json":
                packages += [("npm", n, v, rel, dev) for n, v, dev in parse_package_lock(path)]
            else:
                pinned, unpinned = parse_requirements(path)
                packages += [("PyPI", n, v, rel, False) for n, v in pinned]
                result["unpinned"] += [{"manifest": rel, "name": n} for n in unpinned]
            result["manifests"].append(rel)
        except Exception as e:
            result["errors"].append(f"{rel}: could not parse ({e})")
    result["packages_checked"] = len(packages)
    if not packages:
        return result

    def fetch_one(vuln_id: str) -> Optional[dict]:
        try:
            return fetch(OSV_VULN_URL.format(vuln_id), None)
        except Exception as e:
            result["errors"].append(f"{vuln_id}: details unavailable ({e})")
            return None

    try:
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for eco, n, v, _, _ in packages]
        ids_per_pkg = _query_ids(queries, fetch)
        unique = sorted({i for ids in ids_per_pkg for i in ids})
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            records = dict(zip(unique, pool.map(fetch_one, unique)))
    except Exception as e:
        result["errors"].append(f"OSV query failed ({e}); dependencies were not checked")
        return result

    for (eco, name, version, manifest, dev), ids in zip(packages, ids_per_pkg):
        vulns = _dedupe([records[i] for i in ids if records.get(i)])
        if not vulns:
            continue
        advisories = []
        for v in vulns:
            sev, score = advisory_severity(v)
            advisories.append({
                "id":         v["id"],
                "cves":       sorted(a for a in v.get("aliases") or [] if a.startswith("CVE-")),
                "summary":    (v.get("summary") or (v.get("details") or "").split("\n", 1)[0])[:200],
                "severity":   sev,
                "cvss_score": score,
                "fixed":      fixed_version(v, eco, name, version),
                "url":        OSV_PAGE_URL.format(v["id"]),
            })
        advisories.sort(key=lambda a: (-SEVERITY_ORDER.index(a["severity"]), a["id"]))
        fixes = [a["fixed"] for a in advisories if a["fixed"]]
        result["vulnerable"].append({
            "ecosystem":     eco,
            "name":          name,
            "version":       version,
            "manifest":      manifest,
            "dev":           dev,
            "severity":      advisories[0]["severity"],
            "fixed_version": max(fixes, key=version_key) if fixes else None,
            "advisories":    advisories,
        })
    result["vulnerable"].sort(key=lambda p: (p["dev"], -SEVERITY_ORDER.index(p["severity"]), p["name"]))
    return result
