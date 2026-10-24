# rag/cvss_lookup.py
"""
CVSS vectors for CVEs in the NVD collection.

The collection was originally ingested without vectors, so they are filled
lazily: a vector already in the Qdrant payload is used as is; otherwise it is
fetched once from the NVD 2.0 API and written back to the payload, so every
CVE costs at most one API call ever.

Env:
  NVD_API_KEY      API key (also read from ingestion/.env); raises the rate limit
  RAG_FETCH_CVSS   "0" disables NVD calls (payload vectors only)
"""

import os
import json
import time
import hashlib
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

try:
    from rag_nvd2 import get_qdrant_client, get_collection
except ImportError:          # imported as the `rag` package
    from .rag_nvd2 import get_qdrant_client, get_collection

NVD_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
TIMEOUT_SEC   = 8
# NVD allows 50 requests / 30 s with a key, 5 / 30 s without. Requests start
# at most every MIN_INTERVAL but run concurrently, since each takes 1-3 s.
MIN_INTERVAL  = 0.65
FETCH_WORKERS = 6

_next_slot = 0.0
_slot_lock = threading.Lock()
_api_key: Optional[str] = None


def _key() -> Optional[str]:
    global _api_key
    if _api_key is None:
        _api_key = os.environ.get("NVD_API_KEY", "")
        env_file = Path(__file__).resolve().parent.parent / "ingestion" / ".env"
        if not _api_key and env_file.exists():
            for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("NVD_API_KEY="):
                    _api_key = line.split("=", 1)[1].strip().strip("\"'")
    return _api_key or None


def point_id(cve_id: str) -> int:
    """Qdrant point id used by ingestion for a CVE."""
    return int(hashlib.md5(cve_id.encode()).hexdigest()[:16], 16) % (2**63)


def _wait_for_slot():
    """Thread-safe rate limit: each call reserves the next start slot."""
    global _next_slot
    interval = MIN_INTERVAL if _key() else 6.0
    with _slot_lock:
        start      = max(time.time(), _next_slot)
        _next_slot = start + interval
    delay = start - time.time()
    if delay > 0:
        time.sleep(delay)


def _fetch(cve_id: str) -> Optional[str]:
    """Primary CVSS vector string from NVD (v3.1, then v3.0, then v2), or None."""
    _wait_for_slot()
    req = urllib.request.Request(NVD_URL.format(cve_id),
                                 headers={"apiKey": _key()} if _key() else {})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
        data = json.load(resp)
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        if entries:
            return entries[0].get("cvssData", {}).get("vectorString")
    return None


def get_cvss_vectors(cve_ids: list, known: Optional[dict] = None) -> dict:
    """
    {cve_id: vector string} for the given CVEs (missing ones omitted).
    `known` short-circuits CVEs whose vector the caller already has.
    """
    known  = dict(known or {})
    wanted = [c for c in dict.fromkeys(cve_ids) if c and c not in known]
    if not wanted:
        return known

    client     = get_qdrant_client()
    collection = get_collection(client)
    ids        = {point_id(c): c for c in wanted}
    for p in client.retrieve(collection, ids=list(ids), with_payload=["cve_id", "cvss_vector"]):
        cve = (p.payload or {}).get("cve_id") or ids.get(p.id)
        if (p.payload or {}).get("cvss_vector"):
            known[cve] = p.payload["cvss_vector"]
    missing = [c for c in wanted if c not in known]

    if os.environ.get("RAG_FETCH_CVSS", "1") == "0" or not missing:
        return known

    def fetch(cve):
        try:
            return cve, _fetch(cve)
        except Exception as e:
            print(f"NVD lookup failed for {cve} ({str(e)[:120]}) — skipping CVSS evidence for it.")
            return cve, None

    with ThreadPoolExecutor(max_workers=min(FETCH_WORKERS, len(missing))) as pool:
        fetched = [(c, v) for c, v in pool.map(fetch, missing) if v]
    for cve, vector in fetched:
        known[cve] = vector
        try:
            client.set_payload(collection, payload={"cvss_vector": vector}, points=[point_id(cve)])
        except Exception:
            pass
    return known
