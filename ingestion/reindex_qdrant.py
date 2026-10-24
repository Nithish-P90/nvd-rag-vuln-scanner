# ingestion/reindex_qdrant.py
"""
Rebuilds the NVD collection for the finding-driven RAG without re-fetching
from the NVD API: reads every CVE already in the legacy collection, repairs
its payload, and re-embeds it into nvd_schema.COLLECTION_NAME.

What changes per CVE:
  - payload: cvss_score / severity un-swapped (the original ingestion stored
    them the wrong way round)
  - text:    description + plain-English CWE names, embedded with nomic's
             "search_document:" prefix (queries use "search_query:")
  - indexes: keyword payload indexes on cwe_ids and severity, used by the
             CWE-family filtered search

The source collection is left untouched.

Run (Qdrant and Ollama running, `ollama pull nomic-embed-text` done):
    python ingestion/reindex_qdrant.py
    python ingestion/reindex_qdrant.py --source nvd_threats --target nvd_threats_v2 --recreate
"""

import sys
import time
import argparse
from pathlib import Path

import ollama
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PayloadSchemaType, PointStruct, VectorParams

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rag"))
from nvd_schema import (
    COLLECTION_NAME, LEGACY_COLLECTION, EMBED_MODEL, DOC_PREFIX,
    document_text, normalize_payload,
)

BATCH_SIZE = 64


def embed_documents(texts: list) -> list:
    response = ollama.embed(model=EMBED_MODEL, input=[DOC_PREFIX + t for t in texts])
    return response["embeddings"]


def ensure_target(client: QdrantClient, name: str, dim: int, recreate: bool):
    if client.collection_exists(name):
        if not recreate:
            print(f"ℹ️  '{name}' exists — upserting into it (use --recreate to start fresh).")
            return
        client.delete_collection(name)
        print(f"🗑️  Deleted '{name}'.")
    client.create_collection(
        collection_name=name,
        vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
    )
    for key in ("cwe_ids", "severity"):
        client.create_payload_index(name, field_name=key, field_schema=PayloadSchemaType.KEYWORD)
    print(f"✅ Created '{name}' (dim={dim}) with keyword indexes on cwe_ids, severity.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default=LEGACY_COLLECTION)
    ap.add_argument("--target", default=COLLECTION_NAME)
    ap.add_argument("--recreate", action="store_true", help="drop the target collection first")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=6333)
    args = ap.parse_args()

    if args.source == args.target:
        sys.exit("Source and target must differ — the source is read while the target is written.")

    client = QdrantClient(host=args.host, port=args.port)
    total  = client.count(args.source, exact=True).count
    print(f"🔁 Re-embedding {total} CVEs: '{args.source}' → '{args.target}' with {EMBED_MODEL}")

    dim = len(embed_documents(["probe"])[0])
    ensure_target(client, args.target, dim, args.recreate)

    done, offset, t0 = 0, None, time.time()
    while True:
        points, offset = client.scroll(
            args.source, limit=BATCH_SIZE, offset=offset,
            with_payload=True, with_vectors=False,
        )
        if not points:
            break
        payloads = [normalize_payload(p.payload or {}) for p in points]
        vectors  = embed_documents([document_text(p) for p in payloads])
        client.upsert(args.target, points=[
            PointStruct(id=p.id, vector=v, payload=pl)
            for p, v, pl in zip(points, vectors, payloads)
        ])
        done += len(points)
        rate  = done / max(time.time() - t0, 1e-6)
        print(f"   {done}/{total}  ({rate:.0f}/s, ~{(total - done) / max(rate, 1e-6) / 60:.1f} min left)", end="\r")
        if offset is None:
            break

    print(f"\n🎉 Done: {done} CVEs in '{args.target}' ({(time.time() - t0) / 60:.1f} min).")


if __name__ == "__main__":
    main()
