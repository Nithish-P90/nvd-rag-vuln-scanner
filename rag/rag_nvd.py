# rag/rag_nvd.py
"""
RAG retrieval module: given a code snippet, retrieve and rerank
relevant CVEs from the Qdrant NVD vector database.

Pipeline:
  code snippet
      ↓  extract_security_context()   – tightened regex, highlight risky patterns
      ↓  ollama.embed()               – nomic-embed-text 768-dim embedding
      ↓  Qdrant.search()              – cosine-similarity top-k*2
      ↓  llm_rerank()                 – llama3.2 scores each CVE 0-10
      ↓  format_results()             – human-readable output
"""

import re
import json
from typing import Optional
from qdrant_client import QdrantClient
import ollama

# ─── Config ────────────────────────────────────────────────
COLLECTION_NAME  = "nvd_threats"
VECTOR_SIZE      = 768
DEFAULT_TOP_K    = 5
OLLAMA_EMBED     = "nomic-embed-text"
OLLAMA_LLM       = "llama3.2"

# ─── Tightened risky patterns ──────────────────────────────
RISKY_PATTERNS = [
    # strcpy/strcat/gets with a variable argument (not a literal)
    (
        r"\b(strcpy|strcat|gets|sprintf)\s*\(\s*\w+\s*,\s*\w+",
        "unbounded string copy — likely buffer overflow",
        ["CWE-120", "CWE-121", "CWE-787"],
    ),

    # free() followed within ~3 lines by a dereference of the same pointer
    (
        r"free\s*\(\s*(\w+)\s*\)[\s\S]{0,120}\1\s*(?:->|\[)",
        "free then dereference — use-after-free",
        ["CWE-416"],
    ),

    # double free: two free() calls on the same variable
    (
        r"free\s*\(\s*(\w+)\s*\)[\s\S]{0,200}free\s*\(\s*\1\s*\)",
        "double free",
        ["CWE-415"],
    ),

    # NULL/nullptr dereference: dereferencing a value that was just
    # returned from a function (common pattern: p = f(); p->x)
    (
        r"=\s*\w+\s*\([^)]*\)\s*;[\s\S]{0,80}(?:->|\[\s*0\s*\])",
        "unchecked return value dereference — possible null pointer dereference",
        ["CWE-476"],
    ),

    # system()/popen()/exec with a non-literal argument
    (
        r"\b(system|popen|execl|execv|execlp|execvp)\s*\(\s*(?!\s*\")",
        "shell execution with variable input — command injection",
        ["CWE-78"],
    ),

    # printf/fprintf where the format argument is a variable, not a literal
    (
        r"\b(printf|fprintf|syslog)\s*\(\s*(?:stderr\s*,\s*)?\w+\s*\)",
        "variable as format string — format string vulnerability",
        ["CWE-134"],
    ),

    # malloc size involving user input or arithmetic that could wrap
    (
        r"malloc\s*\([^)]*(?:len|size|count|num|n)\s*[+*]",
        "malloc with arithmetic on length — possible integer overflow/wrap",
        ["CWE-190", "CWE-122"],
    ),

    # memcpy/memmove/memset with a size that comes from user input
    (
        r"\b(memcpy|memmove|memset)\s*\([^)]*(?:len|size|count|num|n)\b",
        "raw memory op with variable size — possible out-of-bounds write",
        ["CWE-119", "CWE-787"],
    ),

    # FIX: removed variable-width lookbehind — not supported in Python re
    (
        r"pthread_create|pthread_join",
        "shared state modified in thread — possible race condition",
        ["CWE-362"],
    ),
]

# ─── Lazy-loaded Qdrant client ─────────────────────────────
_qdrant_client: Optional[QdrantClient] = None


def get_qdrant_client(host: str = "localhost", port: int = 6333) -> QdrantClient:
    global _qdrant_client
    if _qdrant_client is None:
        _qdrant_client = QdrantClient(host=host, port=port)
    return _qdrant_client


# ─── Embedding ─────────────────────────────────────────────
def embed_query(text: str) -> list[float]:
    """Embed a single text string using nomic-embed-text via Ollama."""
    response = ollama.embed(model=OLLAMA_EMBED, input=text)
    return response["embeddings"][0]


# ─── Security context extraction ───────────────────────────
def extract_security_context(code: str) -> dict:
    """
    Scan code for risky patterns and build an enriched natural-language
    query that sits in the same embedding space as stored CVE descriptions.
    """
    found_patterns = []
    extra_keywords = []

    for regex, label, cwe_hints in RISKY_PATTERNS:
        if re.search(regex, code, re.IGNORECASE | re.DOTALL):
            found_patterns.append({"label": label, "cwe_hints": cwe_hints})
            extra_keywords.append(label)

    # Build enriched query — natural language so it matches CVE description space
    if extra_keywords:
        enriched = (
            "This code contains the following security vulnerabilities: "
            + "; ".join(extra_keywords)
            + ". Original code: "
            + code
        )
    else:
        enriched = "Analyse this code for security vulnerabilities: " + code

    return {"patterns": found_patterns, "enriched_query": enriched}


# ─── LLM Reranking ─────────────────────────────────────────
def llm_rerank(code: str, candidates: list[dict]) -> list[dict]:
    """
    Ask llama3.2 to score each candidate CVE 0-10 for relevance
    to the given code snippet, then re-sort by that score.
    """
    if not candidates:
        return candidates

    cve_list = "\n".join([
        f"{i+1}. [{r['cve_id']}] {r['description'][:200]}"
        for i, r in enumerate(candidates)
    ])

    prompt = f"""You are a security expert. Given this code snippet:
{code}
Rate each CVE below from 0 to 10 for how directly relevant it is to the
vulnerabilities present in the code. 10 = exact match, 0 = completely unrelated.

CVEs:
{cve_list}

Respond ONLY with a JSON array of integers, one score per CVE, in order.
Example: [8, 3, 7, 1, 5]"""

    try:
        response = ollama.chat(
            model=OLLAMA_LLM,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0},
        )
        raw = response["message"]["content"].strip()

        # Extract JSON array robustly
        match = re.search(r"\[[\d,\s]+\]", raw)
        if not match:
            print("⚠️ Reranker returned unexpected format, skipping rerank.")
            return candidates

        scores = json.loads(match.group())
        if len(scores) != len(candidates):
            print("⚠️ Score count mismatch, skipping rerank.")
            return candidates

        # Attach LLM score and re-sort
        for i, r in enumerate(candidates):
            r["llm_score"] = scores[i]

        reranked = sorted(candidates, key=lambda x: x["llm_score"], reverse=True)

        # Update ranks after resorting
        for i, r in enumerate(reranked):
            r["rank"] = i + 1

        return reranked

    except Exception as e:
        print(f"⚠️ Reranking failed ({e}), returning original order.")
        return candidates


# ─── Main retrieval entry-point ────────────────────────────
def retrieve(
    code: str,
    top_k: int = DEFAULT_TOP_K,
    score_threshold: float = 0.55,
    severity_filter: Optional[str] = None,
    host: str = "localhost",
    port: int = 6333,
) -> dict:
    """
    Main RAG entry-point.

    Args:
        code:             Source code snippet (any language).
        top_k:            Number of results to return after reranking.
        score_threshold:  Minimum cosine similarity to include a result.
        severity_filter:  If set, only return CVEs with this severity.
        host / port:      Qdrant connection.

    Returns:
        {
          "query_analysis": { "patterns": [...], "enriched_query": str },
          "results": [
              {
                "rank":        int,
                "score":       float,   # vector similarity
                "llm_score":   int,     # 0-10 from reranker, None if rerank failed
                "cve_id":      str,
                "description": str,
                "severity":    str,
                "cvss_score":  float | None,
                "cwe_ids":     [str],
                "cpe":         [str],
                "published":   str,
              }, ...
          ]
        }
    """
    client = get_qdrant_client(host, port)

    # 1. Analyse code and build enriched query
    analysis       = extract_security_context(code)
    enriched_query = analysis["enriched_query"]

    # 2. Embed enriched query
    vector = embed_query(enriched_query)

    # 3. Build optional severity filter
    qdrant_filter = None
    if severity_filter:
        from qdrant_client.models import Filter, FieldCondition, MatchValue
        qdrant_filter = Filter(
            must=[FieldCondition(
                key="severity",
                match=MatchValue(value=severity_filter.upper()),
            )]
        )

    # 4. Search Qdrant — fetch top_k*2 so reranker has enough candidates
    try:
        # qdrant-client >= 1.7
        response = client.query_points(
            collection_name=COLLECTION_NAME,
            query=vector,
            limit=top_k * 2,
            score_threshold=score_threshold,
            query_filter=qdrant_filter,
            with_payload=True,
        )
        hits = response.points
    except AttributeError:
        # fallback for older qdrant-client
        hits = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=vector,
            limit=top_k * 2,
            score_threshold=score_threshold,
            query_filter=qdrant_filter,
            with_payload=True,
        )

    # 5. Build candidate list from hits
    candidates = []
    for hit in hits:
        p = hit.payload
        candidates.append({
            "rank":        len(candidates) + 1,
            "score":       round(hit.score, 4),
            "llm_score":   None,
            "cve_id":      p.get("cve_id", "N/A"),
            "description": p.get("description", ""),
            "severity":    p.get("severity", "UNKNOWN"),
            "cvss_score":  p.get("cvss_score"),
            "cwe_ids":     p.get("cwe_ids", []),
            "cpe":         p.get("cpe", []),
            "published":   p.get("published", ""),
        })

    # 6. LLM rerank candidates, then trim to top_k
    reranked = llm_rerank(code, candidates)
    final    = reranked[:top_k]

    return {"query_analysis": analysis, "results": final}


# ─── Pretty-print helper ────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "LOW":      "\033[92m",   # green
    "UNKNOWN":  "\033[90m",   # grey
}
RESET = "\033[0m"


def format_results(rag_output: dict, color: bool = True) -> str:
    analysis = rag_output["query_analysis"]
    results  = rag_output["results"]
    lines    = []

    # ── Detected patterns section ──────────────────────────
    if analysis["patterns"]:
        lines.append("┌─ Detected Security Patterns " + "─" * 42)
        for p in analysis["patterns"]:
            cwe_str = ", ".join(p["cwe_hints"]) or "—"
            lines.append(f"│  ▸ {p['label']}")
            lines.append(f"│    CWE hints: {cwe_str}")
        lines.append("└" + "─" * 70)
    else:
        lines.append("ℹ  No specific risky patterns detected — using semantic search only.")

    lines.append("")

    if not results:
        lines.append("⚠  No relevant CVEs found above the similarity threshold.")
        return "\n".join(lines)

    lines.append(f"Top {len(results)} Relevant CVEs  (vector search + LLM reranked)")
    lines.append("═" * 70)

    for r in results:
        sev       = r["severity"]
        col       = SEVERITY_COLOR.get(sev, "") if color else ""
        rst       = RESET if color else ""
        score_bar = "█" * int(r["score"] * 20) + "░" * (20 - int(r["score"] * 20))
        llm_str   = f"  LLM score: {r['llm_score']}/10" if r["llm_score"] is not None else ""

        lines.append(f"\n#{r['rank']}  {col}[{sev}]{rst}  {r['cve_id']}{llm_str}")
        lines.append(f"    Vector similarity: {score_bar} {r['score']:.4f}")
        if r["cvss_score"]:
            lines.append(f"    CVSS Score: {r['cvss_score']}")
        if r["cwe_ids"]:
            lines.append(f"    CWEs:       {', '.join(r['cwe_ids'])}")
        lines.append(f"    Published:  {r['published']}")

        # Wrap description at 80 chars
        words, line_buf, desc_lines = r["description"].split(), [], []
        for w in words:
            if sum(len(x) + 1 for x in line_buf) + len(w) > 80:
                desc_lines.append(" ".join(line_buf))
                line_buf = [w]
            else:
                line_buf.append(w)
        if line_buf:
            desc_lines.append(" ".join(line_buf))
        lines.append("    Description:")
        for dl in desc_lines:
            lines.append(f"      {dl}")

        if r["cpe"]:
            lines.append(f"    Affected:   {'; '.join(r['cpe'][:3])}")
        lines.append("    " + "─" * 66)

    return "\n".join(lines)