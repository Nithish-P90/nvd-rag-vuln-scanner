# ingestion/ingest_nvd.py

import nvdlib
import os
import time
import json
import hashlib
from datetime import datetime, timezone
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, PayloadSchemaType
import ollama
import sys
from pathlib import Path

# Documents must be embedded exactly as rag_nvd2 expects (prefix, CWE names).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rag"))
from nvd_schema import COLLECTION_NAME, EMBED_MODEL, DOC_PREFIX, document_text

# ─── Load env ──────────────────────────────────────────────
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# ─── Clients ───────────────────────────────────────────────
client = QdrantClient(host="localhost", port=6333)

VECTOR_SIZE     = 768
TIMESTAMP_FILE  = "last_run.json"
OLLAMA_EMBED    = EMBED_MODEL

# ─── CWE targets ───────────────────────────────────────────
# Guarantees coverage of specific weakness classes
# even if they fall below CRITICAL/HIGH threshold
cwe_targets = [
    # Memory safety
    "CWE-119", "CWE-120", "CWE-121", "CWE-122",
    "CWE-125", "CWE-787", "CWE-416", "CWE-415",
    "CWE-476", "CWE-190", "CWE-191", "CWE-134",
    "CWE-362", "CWE-78",  "CWE-20",
    # Injection
    "CWE-89",  "CWE-79",  "CWE-90",  "CWE-611",
    # Path / file
    "CWE-22",  "CWE-73",
    # Crypto / auth
    "CWE-327", "CWE-338", "CWE-326", "CWE-295",
    "CWE-798", "CWE-259", "CWE-862", "CWE-863",
    "CWE-287",
    # Deserialization / type / web
    "CWE-502", "CWE-843", "CWE-400", "CWE-918",
    "CWE-601",
]

# ─── Severity targets ──────────────────────────────────────
# Fetches ALL CVEs at these severity levels — no keyword bias
# CRITICAL + HIGH covers the most impactful vulnerabilities
# while keeping the dataset manageable for local embedding
severity_targets = [
    "CRITICAL",
    "HIGH",
]

# ─── Timestamp helpers ─────────────────────────────────────
def get_last_run_timestamp():
    if not os.path.exists(TIMESTAMP_FILE):
        return None
    with open(TIMESTAMP_FILE) as f:
        raw = json.load(f).get("last_run")
    if not raw:
        return None
    try:
        datetime.strptime(raw, "%Y-%m-%d %H:%M")
        return raw
    except ValueError:
        pass
    try:
        normalized = f"{raw[:10]} {raw[11:16]}"
        datetime.strptime(normalized, "%Y-%m-%d %H:%M")
        return normalized
    except Exception:
        pass
    print(f"⚠️ Could not parse timestamp '{raw}', doing full fetch.")
    return None


def save_last_run_timestamp():
    with open(TIMESTAMP_FILE, "w") as f:
        json.dump({"last_run": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")}, f)


# ─── Embedding via Ollama ──────────────────────────────────
def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed CVE documents with nomic-embed-text (search_document: prefix), in batches."""
    vectors = []
    for i in range(0, len(texts), 64):
        batch = [DOC_PREFIX + t for t in texts[i:i + 64]]
        vectors.extend(ollama.embed(model=OLLAMA_EMBED, input=batch)["embeddings"])
        print(f"   Embedded {len(vectors)}/{len(texts)}")
    return vectors


# ─── Create collection ─────────────────────────────────────
def create_collection(force_recreate: bool = False):
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION_NAME in existing:
        if force_recreate:
            client.delete_collection(COLLECTION_NAME)
            print(f"🗑️  Deleted old collection '{COLLECTION_NAME}'.")
        else:
            print(f"ℹ️  Collection '{COLLECTION_NAME}' already exists.")
            return
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    for key in ("cwe_ids", "severity"):
        client.create_payload_index(COLLECTION_NAME, field_name=key,
                                    field_schema=PayloadSchemaType.KEYWORD)
    print(f"✅ Collection '{COLLECTION_NAME}' created (dim={VECTOR_SIZE}).")


# ─── Fetch CVEs ────────────────────────────────────────────
def fetch_cves(params, label):
    """Fetch CVEs from NVD with exponential backoff retry on 503/429."""
    print(f"\n🔎 {label}")
    max_retries = 5
    backoff     = 10
    for attempt in range(1, max_retries + 1):
        try:
            results = nvdlib.searchCVE(**params)
            print(f"   → Fetched {len(results)} CVEs")
            return results
        except Exception as e:
            err_str = str(e)
            if "503" in err_str or "429" in err_str or "Service Unavailable" in err_str:
                if attempt < max_retries:
                    wait = backoff * attempt
                    print(f"   ⚠️ NVD API unavailable (attempt {attempt}/{max_retries}), "
                          f"retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                else:
                    print(f"   ❌ Still unavailable after {max_retries} attempts, skipping.")
                    return []
            print(f"   ❌ Fetch failed: {e}")
            return []
    return []


def fetch_cves_by_cwe(cwe_id, last_run=None):
    params = {"cweId": cwe_id, "key": NVD_API_KEY, "limit": 500}
    if last_run:
        params["lastModStartDate"] = last_run
        params["lastModEndDate"]   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        label = f"CWE {cwe_id} (incremental)"
    else:
        label = f"CWE {cwe_id} (full)"
    return fetch_cves(params, label)


def fetch_cves_by_severity(severity, last_run=None):
    """
    Fetch ALL CVEs at a given severity level with no keyword filter.
    Broader coverage than keyword matching — captures everything severe.
    """
    params = {
        "cvssV3Severity": severity,
        "key":            NVD_API_KEY,
        "limit":          2000,
    }
    if last_run:
        params["lastModStartDate"] = last_run
        params["lastModEndDate"]   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        label = f"Severity {severity} (incremental)"
    else:
        label = f"Severity {severity} (full)"
    return fetch_cves(params, label)


# ─── Preprocess CVE ────────────────────────────────────────
def preprocess_cve(cve):
    try:
        description = cve.descriptions[0].value if cve.descriptions else None
        if not description:
            return None

        cvss_score = None
        severity   = "UNKNOWN"
        if hasattr(cve, "score") and cve.score:
            try:
                cvss_score = cve.score[1]
                severity   = cve.score[2]
            except Exception:
                pass

        cwe_ids  = [c.value for c in getattr(cve, "cwe", [])]
        cpe_list = [c.criteria for c in getattr(cve, "cpe", [])[:5]]

        text = document_text({"description": description, "cwe_ids": cwe_ids})

        stable_id = int(hashlib.md5(cve.id.encode()).hexdigest()[:16], 16) % (2**63)

        return {
            "id":   stable_id,
            "text": text,
            "payload": {
                "cve_id":        cve.id,
                "description":   description,
                "cvss_score":    cvss_score,
                "cvss_vector":   (getattr(cve, "v31vector", None)
                                    or getattr(cve, "v30vector", None)
                                    or getattr(cve, "v2vector", None)),
                "severity":      severity,
                "cwe_ids":       cwe_ids,
                "cpe":           cpe_list,
                "published":     (
                    getattr(cve, "published", "").isoformat()
                    if isinstance(getattr(cve, "published", ""), datetime)
                    else str(getattr(cve, "published", ""))
                ),
                "last_modified": (
                    getattr(cve, "lastModified", "").isoformat()
                    if isinstance(getattr(cve, "lastModified", ""), datetime)
                    else str(getattr(cve, "lastModified", ""))
                ),
            }
        }
    except Exception as e:
        print(f"⚠️ Skipping {cve.id}: {e}")
        return None


# ─── Deduplicate ───────────────────────────────────────────
def deduplicate(data):
    seen, result = set(), []
    for item in data:
        cve_id = item["payload"]["cve_id"]
        if cve_id not in seen:
            seen.add(cve_id)
            result.append(item)
    print(f"\n🧹 Deduplicated → {len(result)} unique CVEs")
    return result


# ─── Store in Qdrant ───────────────────────────────────────
def store_in_qdrant(data):
    print(f"\n🧠 Embedding {len(data)} CVEs with {OLLAMA_EMBED}...")

    texts   = [item["text"] for item in data]
    vectors = embed_texts(texts)

    points = [
        PointStruct(
            id      = item["id"],
            vector  = vectors[i],
            payload = item["payload"],
        )
        for i, item in enumerate(data)
    ]

    BATCH_SIZE = 100
    for i in range(0, len(points), BATCH_SIZE):
        batch = points[i:i + BATCH_SIZE]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        print(f"   Uploaded {min(i + BATCH_SIZE, len(points))}/{len(points)}")

    print("✅ Stored in Qdrant.")


# ─── Main ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀 Starting ingestion pipeline...\n")

    # force_recreate=True  → only for first run or after embedding model change
    # force_recreate=False → all normal incremental runs
    create_collection(force_recreate=False)

    last_run = get_last_run_timestamp()
    print(f"⏱ Last run: {last_run or 'None (full fetch)'}")

    all_data = []

    # CWE fetch — guarantees coverage of specific weakness classes
    print("\n=== CWE Fetch ===")
    for cwe in cwe_targets:
        cves = fetch_cves_by_cwe(cwe, last_run)
        if not cves:
            print("   → No new CVEs")
        for cve in cves:
            processed = preprocess_cve(cve)
            if processed:
                all_data.append(processed)
        time.sleep(3)

    # Severity fetch — broad coverage with no keyword bias
    print("\n=== Severity Fetch ===")
    for severity in severity_targets:
        cves = fetch_cves_by_severity(severity, last_run)
        if not cves:
            print("   → No new CVEs")
        for cve in cves:
            processed = preprocess_cve(cve)
            if processed:
                all_data.append(processed)
        time.sleep(3)

    if not all_data:
        print("\n⚠️ No new CVEs found. Exiting.")
        exit()

    deduped = deduplicate(all_data)
    store_in_qdrant(deduped)
    save_last_run_timestamp()

    print("\n🎉 Ingestion complete!")