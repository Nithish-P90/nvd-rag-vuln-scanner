# tests/benchmark/score_scan.py
"""
Grade a ProjectScanner JSON report against the seeded benchmark's answer key.

    python agents/project_scanner.py --dir tests/benchmark/seeded_repo --format json -o scan.json
    python tests/benchmark/score_scan.py scan.json

Checks:
  code          every seeded vulnerability confirmed (file + threat category);
                confirmed findings that match nothing are false positives;
                must_not_flag violations are listed separately
  clean files   safe look-alike files end with status "clean"
  dependencies  each seeded package found, with its CVE, severity and dev flag;
                unpinned requirements listed
  integrity     every file in exactly one status bucket, and the security score
                equals the documented formula
Exit code 0 only when everything passes.
"""

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "agents"))

from validation_guardrails import classify  # noqa: E402

WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}


def category(finding: dict) -> str:
    return finding.get("threat_category") or classify(finding)


def covers(rules: list, file: str, cat: str) -> bool:
    return any(r["file"] == file and ("*" in r["categories"] or cat in r["categories"]) for r in rules)


def score(scan: dict, truth: dict) -> tuple:
    out, failed = [], False
    files = {f["relative_path"]: f for f in scan["files"]}

    # ── Code findings ──
    confirmed = [(p, f, category(f)) for p, fr in files.items() for f in fr["validated_findings"]]
    unresolved = [(p, f, category(f)) for p, fr in files.items() for f in fr.get("needs_context") or []]
    used = set()
    out.append("CODE FINDINGS (seeded)")
    hits = 0
    for exp in truth["expected"]:
        match = next((i for i, (p, _, c) in enumerate(confirmed)
                      if p == exp["file"] and c in exp["categories"] and i not in used), None)
        if match is not None:
            used.add(match)
            hits += 1
            f = confirmed[match][1]
            verdict = f"FOUND     [{f.get('severity', '?')}] {f.get('category', '')}"
        elif any(p == exp["file"] and c in exp["categories"] for p, _, c in unresolved):
            verdict = "UNRESOLVED (left for manual review, not confirmed)"
            failed = True
        else:
            verdict = "MISSED"
            failed = True
        out.append(f"  {exp['id']:<9} {exp['file']}:{exp['lines'][0]:<4} {exp['cwe']:<8} {verdict}")

    extras = [(p, f, c) for i, (p, f, c) in enumerate(confirmed)
              if i not in used and not covers(truth["tolerated"], p, c)]
    violations = [(p, f, c) for p, f, c in extras if covers(truth["must_not_flag"], p, c)]
    out.append("")
    out.append(f"FALSE POSITIVES (confirmed, not seeded): {len(extras)}")
    for p, f, c in extras:
        tag = "  <- must-not-flag" if (p, f, c) in violations else ""
        out.append(f"  {p}: [{f.get('severity', '?')}] {f.get('category', '')} ({c}){tag}")
    if violations:
        failed = True
    noise = [(p, f, c) for p, f, c in unresolved
             if not any(p == e["file"] and c in e["categories"] for e in truth["expected"])]
    out.append(f"UNRESOLVED, not seeded (manual-review noise): {len(noise)}")
    for p, f, c in noise:
        out.append(f"  {p}: {f.get('category', '')} ({c})")

    precision = hits / (hits + len(extras)) if hits + len(extras) else 1.0
    recall = hits / len(truth["expected"])
    out.append(f"precision {precision:.0%}   recall {recall:.0%}   ({hits}/{len(truth['expected'])} seeded found)")

    # ── Clean look-alikes ──
    out.append("")
    out.append("SAFE FILES (must end clean)")
    for path in truth["expected_clean"]:
        st = files.get(path, {}).get("status", "missing")
        ok = st == "clean"
        failed |= not ok
        out.append(f"  {'ok  ' if ok else 'FAIL'} {path}: {st}")

    # ── Dependencies ──
    out.append("")
    out.append("DEPENDENCIES")
    deps = scan.get("dependencies") or {}
    if not deps:
        out.append("  FAIL dependency scan missing from report")
        failed = True
    found = {(p["ecosystem"], p["name"].lower(), p["version"]): p for p in deps.get("vulnerable", [])}
    for exp in truth["dependencies"]["vulnerable"]:
        p = found.get((exp["ecosystem"], exp["name"], exp["version"]))
        problems = []
        if p is None:
            problems.append("not reported")
        else:
            if not any(exp["cve"] in a["cves"] for a in p["advisories"]):
                problems.append(f"{exp['cve']} missing")
            if p["dev"] != exp["dev"]:
                problems.append(f"dev={p['dev']}, expected {exp['dev']}")
            if p["severity"] == "UNKNOWN":
                problems.append("severity UNKNOWN")
        failed |= bool(problems)
        detail = (f"{p['severity']}, {len(p['advisories'])} advisories, upgrade to {p['fixed_version']}"
                  if p else "")
        out.append(f"  {'ok  ' if not problems else 'FAIL'} {exp['name']} {exp['version']} "
                   f"({'dev' if exp['dev'] else 'runtime'}): {'; '.join(problems) or detail}")
    unpinned = {u["name"] for u in deps.get("unpinned", [])}
    for name in truth["dependencies"]["unpinned"]:
        ok = name in unpinned
        failed |= not ok
        out.append(f"  {'ok  ' if ok else 'FAIL'} {name} listed as unpinned")
    for err in deps.get("errors", []):
        out.append(f"  warning: {err}")

    # ── Report integrity ──
    out.append("")
    out.append("REPORT INTEGRITY")
    buckets = {"vulnerable": scan.get("vulnerable_files_count"), "unresolved": scan.get("unresolved_files_count"),
               "incomplete": scan.get("incomplete_files_count"), "clean": scan.get("clean_files_count")}
    counted = {k: sum(1 for f in scan["files"] if f.get("status") == k) for k in buckets}
    ok = counted == buckets and sum(counted.values()) == scan["total_files_scanned"]
    failed |= not ok
    out.append(f"  {'ok  ' if ok else 'FAIL'} file buckets {counted} cover all {scan['total_files_scanned']} files")
    penalty = sum(w * (scan["severity_counts"].get(k, 0) + scan.get("dependency_severity_counts", {}).get(k, 0))
                  for k, w in WEIGHTS.items())
    expected_score = max(0, min(100, 100 - penalty))
    ok = expected_score == scan["security_score"]
    failed |= not ok
    out.append(f"  {'ok  ' if ok else 'FAIL'} score {scan['security_score']}/100 "
               f"(formula gives {expected_score}; grade {scan['security_grade']})")

    out.append("")
    out.append("RESULT: " + ("PASS" if not failed else "FAIL"))
    return "\n".join(out), failed


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    scan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    truth_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).with_name("ground_truth.json")
    report, failed = score(scan, json.loads(truth_path.read_text(encoding="utf-8")))
    print(report)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
