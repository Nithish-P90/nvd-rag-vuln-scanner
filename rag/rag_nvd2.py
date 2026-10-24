# rag/rag_nvd2.py
"""
Finding-driven RAG retrieval over the NVD collection in Qdrant.

For every vulnerability the ForensicsAgent reports, retrieve the top-k most
similar CVEs:

  forensics finding (+ CPG facts: function, taint source, sanitization)
      ↓  build_query()       – NVD-style natural-language description of the
                               finding (CVE descriptions are prose, so raw code
                               embeds poorly against them)
      ↓  ollama.embed()      – nomic-embed-text with the "search_query:" prefix
      ↓  Qdrant (2 searches) – dense search restricted to the finding's CWE
                               family + an unrestricted dense search (catches
                               CVEs NVD labelled with an unexpected CWE)
      ↓  fuse                – cosine + CWE-match bonus + lexical overlap of
                               API names / key terms, near-duplicates dropped
      ↓  rerank              – cross-encoder (if sentence-transformers is
                               installed) or a schema-constrained LLM judge,
                               blended with the retrieval score
      ↓  top-k per finding

Configuration (env vars):
  RAG_COLLECTION     Qdrant collection (default: nvd_schema.COLLECTION_NAME,
                     falls back to the legacy collection if missing)
  RAG_RERANKER       auto | cross-encoder | llm | none   (default: auto)
  RAG_CROSS_ENCODER  cross-encoder model (default: BAAI/bge-reranker-base)
  RAG_RERANK_MODEL   Ollama model for the LLM judge (default: llama3.2)
"""

import os
import re
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, field
from typing import Optional

import ollama
from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchAny, MatchValue, QueryRequest

try:
    from ollama_retry import with_retry
except ImportError:          # imported as the `rag` package
    from .ollama_retry import with_retry

try:
    from nvd_schema import (
        COLLECTION_NAME, LEGACY_COLLECTION, EMBED_MODEL, QUERY_PREFIX,
        CWE_INFO, cwe_family, cwe_label, normalize_cwe, normalize_payload,
    )
except ImportError:          # imported as the `rag` package
    from .nvd_schema import (
        COLLECTION_NAME, LEGACY_COLLECTION, EMBED_MODEL, QUERY_PREFIX,
        CWE_INFO, cwe_family, cwe_label, normalize_cwe, normalize_payload,
    )

# ─── Config ────────────────────────────────────────────────
DEFAULT_TOP_K      = 5
CANDIDATES_PER_ARM = 25     # hits fetched by each of the two searches
RERANK_POOL        = 12     # fused candidates passed to the reranker
DUPLICATE_JACCARD  = 0.8    # descriptions this similar count as one CVE

CWE_EXACT_BONUS    = 0.10   # added to cosine when the CVE has the finding's CWE
CWE_FAMILY_BONUS   = 0.05   # ... or a CWE from the same root-cause group
LEXICAL_WEIGHT     = 0.05   # times the fraction of key terms found in the CVE
RERANK_WEIGHT      = 0.7    # final = w * rerank + (1 - w) * normalized retrieval

RERANKER           = os.environ.get("RAG_RERANKER", "auto").lower()
CROSS_ENCODER      = os.environ.get("RAG_CROSS_ENCODER", "BAAI/bge-reranker-base")
RERANK_LLM         = os.environ.get("RAG_RERANK_MODEL", "llama3.2")
RERANK_CONCURRENCY = int(os.environ.get("LLM_CONCURRENCY", "4"))

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ─── Output schema ─────────────────────────────────────────
@dataclass
class CVEMatch:
    rank:            int
    cve_id:          str
    severity:        str
    cvss_score:      Optional[float]
    cvss_vector:     Optional[str]    # e.g. CVSS:3.1/AV:N/AC:L/...; filled lazily (cvss_lookup)
    score:           float            # final ranking score (0-1)
    vector_score:    float            # cosine similarity of query and CVE
    retrieval_score: float            # cosine + CWE bonus + lexical bonus
    rerank_score:    Optional[float]  # reranker relevance (0-1), None if not reranked
    llm_score:       Optional[int]    # LLM judge score (0-10), only with the LLM reranker
    cwe_match:       str              # "exact" | "family" | "none"
    explanation:     str
    cwe_ids:         list
    cpe:             list
    description:     str
    published:       str

    def to_dict(self):
        return asdict(self)


@dataclass
class FindingRetrieval:
    """Top-k similar CVEs for one forensics finding."""
    finding:               dict
    query:                 str
    cwe_family:            list
    cve_matches:           list = field(default_factory=list)   # CVEMatch dicts
    candidates_considered: int  = 0
    reranker:              str  = "none"
    collection:            str  = COLLECTION_NAME

    @property
    def highest_severity(self) -> str:
        return highest_severity(self.cve_matches)

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


def highest_severity(results: list) -> str:
    if not results:
        return "UNKNOWN"
    return max(results, key=lambda r: SEVERITY_ORDER.get(r["severity"], 0))["severity"]


# ─── Clients ───────────────────────────────────────────────
_qdrant_client: Optional[QdrantClient] = None
_collection:    Optional[str] = None


def get_qdrant_client(host: str = "localhost", port: int = 6333) -> QdrantClient:
    global _qdrant_client
    if _qdrant_client is None:
        _qdrant_client = QdrantClient(host=host, port=port)
    return _qdrant_client


def get_collection(client: QdrantClient) -> str:
    """Configured collection, or the legacy one if it has not been rebuilt yet."""
    global _collection
    if _collection is None:
        wanted = os.environ.get("RAG_COLLECTION", COLLECTION_NAME)
        if client.collection_exists(wanted):
            _collection = wanted
        elif client.collection_exists(LEGACY_COLLECTION):
            print(f"⚠️ Collection '{wanted}' not found — using '{LEGACY_COLLECTION}'. "
                  f"Run ingestion/reindex_qdrant.py for prefixed, CWE-named embeddings.")
            _collection = LEGACY_COLLECTION
        else:
            raise RuntimeError(f"No NVD collection in Qdrant ('{wanted}' / '{LEGACY_COLLECTION}')")
    return _collection


def embed_queries(texts: list) -> list:
    response = with_retry(ollama.embed, model=EMBED_MODEL, input=[QUERY_PREFIX + t for t in texts])
    return response["embeddings"]


# ─── Query construction ────────────────────────────────────
_STOPWORDS = {
    "the", "a", "an", "of", "in", "to", "and", "or", "with", "without", "via",
    "for", "is", "on", "by", "from", "into", "vulnerability", "potential",
    "possible", "insecure", "unsafe", "use", "code", "data",
}

_CALL_RE  = re.compile(r"\b([A-Za-z_][\w.]*)\s*\(")
_WORD_RE  = re.compile(r"[a-z][a-z0-9_]+")
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "def", "print"}


def _api_names(code: str) -> list:
    """Called function names in the affected statement: strcpy, os.system -> system."""
    names = []
    for m in _CALL_RE.finditer(code or ""):
        name = m.group(1).split(".")[-1]
        if name.lower() not in _KEYWORDS:
            names.append(name)
    return list(dict.fromkeys(names))


def finding_cwes(finding: dict) -> list:
    raw = finding.get("cwe_ids") or [finding.get("cwe_id")]
    if isinstance(raw, str):
        raw = [raw]
    return [c for c in (normalize_cwe(c) for c in raw) if c]


def build_query(finding: dict, language: str = "unknown", context: Optional[dict] = None) -> str:
    """
    Describe a forensics finding the way an NVD entry would, e.g.

      Buffer overflow (CWE-120 (Buffer Copy without Checking Size of Input)):
      data is copied into a fixed-size buffer without checking its length,
      causing a buffer overflow. In function login of a C program, the call
      strcpy(buf, username) uses network data with no sanitization.
    """
    context = context or {}
    vtype   = str(finding.get("vulnerability_type") or finding.get("category") or "security weakness").strip()
    cwes    = finding_cwes(finding)
    code    = " ".join(str(finding.get("affected_code") or finding.get("evidence") or "").split())[:200]

    parts = [vtype[:1].upper() + vtype[1:]]
    if cwes:
        parts[0] += " (" + ", ".join(cwe_label(c) for c in cwes) + ")"
        summary = CWE_INFO.get(cwes[0], (None, None))[1]
        if summary:
            parts[0] += f": {summary}"
    parts[0] += "."

    program  = f"a {language} program" if language and language != "unknown" else ""
    if context.get("function"):
        where = f"function {context['function']}" + (f" of {program}" if program else "")
    else:
        where = program
    sentence = f"In {where}, " if where else ""
    if code:
        sentence += f"the statement {code}"
        apis = _api_names(code)
        if apis:
            sentence += f" calls {', '.join(apis[:3])}"
    if context.get("source"):
        sentence += f" on {context['source']}"
        sentence += " that is sanitized" if context.get("sanitized") else " with no sanitization"
    if sentence:
        parts.append(sentence.strip().rstrip(".") + ".")
    if context.get("entry_point"):
        parts.append(f"Reachable from {context['entry_point']}, so input is attacker-controlled.")
    return " ".join(parts)


def _key_terms(finding: dict) -> set:
    """Terms whose presence in a CVE description is real evidence of a match."""
    code  = str(finding.get("affected_code") or finding.get("evidence") or "")
    terms = {a.lower() for a in _api_names(code) if len(a) > 2}
    vtype = str(finding.get("vulnerability_type") or finding.get("category") or "").lower()
    terms |= {w for w in _WORD_RE.findall(vtype) if w not in _STOPWORDS and len(w) > 2}
    return terms


# ─── Candidate scoring ─────────────────────────────────────
def _tokens(text: str) -> set:
    return set(_WORD_RE.findall((text or "").lower()))


def _score_candidate(cand: dict, cwes: list, family: set, terms: set) -> None:
    cve_cwes = set(cand["cwe_ids"])
    if cwes and cve_cwes.intersection(cwes):
        cand["cwe_match"], bonus = "exact", CWE_EXACT_BONUS
    elif cve_cwes.intersection(family):
        cand["cwe_match"], bonus = "family", CWE_FAMILY_BONUS
    else:
        cand["cwe_match"], bonus = "none", 0.0
    desc    = _tokens(cand["description"])
    lexical = len(terms & desc) / len(terms) if terms else 0.0
    cand["retrieval_score"] = round(cand["vector_score"] + bonus + LEXICAL_WEIGHT * lexical, 4)


def _drop_near_duplicates(cands: list) -> list:
    """NVD has many template descriptions (same vendor, same bug); keep the best of each."""
    kept, kept_tokens = [], []
    for c in cands:
        toks = _tokens(c["description"])
        if any(len(toks & t) / max(len(toks | t), 1) >= DUPLICATE_JACCARD for t in kept_tokens):
            continue
        kept.append(c)
        kept_tokens.append(toks)
    return kept


def _candidate(hit) -> dict:
    p = normalize_payload(hit.payload or {})
    return {
        "cve_id":       p.get("cve_id", "N/A"),
        "description":  p.get("description", ""),
        "severity":     p["severity"],
        "cvss_score":   p["cvss_score"],
        "cvss_vector":  p.get("cvss_vector"),
        "cwe_ids":      p["cwe_ids"],
        "cpe":          p.get("cpe", []),
        "published":    p.get("published", ""),
        "vector_score": round(hit.score, 4),
    }


# ─── Rerankers ─────────────────────────────────────────────
_cross_encoder = None


def _load_cross_encoder():
    global _cross_encoder
    if _cross_encoder is None:
        from sentence_transformers import CrossEncoder
        _cross_encoder = CrossEncoder(CROSS_ENCODER)
    return _cross_encoder


def _rerank_cross_encoder(query: str, cands: list) -> None:
    model  = _load_cross_encoder()
    scores = model.predict([(query, c["description"]) for c in cands])
    for c, s in zip(cands, scores):
        c["rerank_score"] = round(float(s), 4)


def _rerank_llm(query: str, cands: list) -> None:
    listing = "\n".join(
        f"{i}. [{', '.join(c['cwe_ids']) or 'no CWE'}] {c['description'][:350]}"
        for i, c in enumerate(cands, 1)       # 1-based: models number from 1 regardless
    )
    prompt = f"""You match a vulnerability found in source code to known CVEs.

Finding:
{query}

Candidate CVEs:
{listing}

For EACH candidate, score 0-10 how closely it describes the same weakness as the finding.
Judge the root cause and the kind of vulnerable operation; ignore vendor, product and version.
- 9-10: same root cause and same kind of operation (e.g. unchecked string copy into a fixed buffer)
- 6-8:  same vulnerability class, different mechanism
- 3-5:  related class (e.g. a different memory-safety bug)
- 0-2:  unrelated

Respond with a JSON array with one object per candidate: {{"id": <number>, "score": <0-10>, "reason": "<one short sentence>"}}"""

    schema = {
        "type": "array",
        "minItems": len(cands),
        "maxItems": len(cands),
        "items": {
            "type": "object",
            "properties": {
                "id":     {"type": "integer", "enum": list(range(1, len(cands) + 1))},
                "score":  {"type": "integer", "minimum": 0, "maximum": 10},
                "reason": {"type": "string"},
            },
            "required": ["id", "score", "reason"],
        },
    }
    response = with_retry(
        ollama.chat,
        model    = RERANK_LLM,
        messages = [{"role": "user", "content": prompt}],
        format   = schema,
        options  = {"temperature": 0, "num_predict": 1500},
    )
    parsed = json.loads(response["message"]["content"])
    by_id  = {int(r["id"]): r for r in parsed if isinstance(r, dict) and "id" in r}
    if len(by_id) < len(cands) // 2:
        raise ValueError(f"judge scored only {len(by_id)}/{len(cands)} candidates")
    for i, c in enumerate(cands, 1):
        r = by_id.get(i)
        if r is None:
            c["rerank_score"] = 0.5          # unjudged: neutral, keeps scores on one scale
            continue
        c["llm_score"]    = max(0, min(10, int(r.get("score", 0))))
        c["rerank_score"] = c["llm_score"] / 10
        c["explanation"]  = str(r.get("reason", ""))


def _choose_reranker(requested: Optional[str]) -> str:
    choice = (requested or RERANKER).lower()
    if choice == "auto":
        try:
            import sentence_transformers  # noqa: F401
            return "cross-encoder"
        except ImportError:
            return "llm"
    return choice


def _rerank(query: str, cands: list, reranker: str) -> str:
    """Scores cands in place; returns the reranker that actually ran."""
    for c in cands:
        c.setdefault("rerank_score", None)
        c.setdefault("llm_score", None)
        c.setdefault("explanation", "")
    if not cands or reranker == "none":
        return "none"
    try:
        if reranker == "cross-encoder":
            _rerank_cross_encoder(query, cands)
        else:
            _rerank_llm(query, cands)
        return reranker
    except Exception as e:
        print(f"⚠️ {reranker} rerank failed ({str(e)[:200]}) — using retrieval scores only.")
        return "none"


def _final_order(cands: list) -> list:
    lo = min(c["retrieval_score"] for c in cands)
    hi = max(c["retrieval_score"] for c in cands)
    for c in cands:
        norm = (c["retrieval_score"] - lo) / (hi - lo) if hi > lo else 1.0
        if c.get("rerank_score") is None:
            c["score"] = round(c["retrieval_score"], 4)
        else:
            c["score"] = round(RERANK_WEIGHT * c["rerank_score"] + (1 - RERANK_WEIGHT) * norm, 4)
    return sorted(cands, key=lambda c: c["score"], reverse=True)


# ─── Main retrieval entry-points ───────────────────────────
def retrieve_for_findings(
    findings: list,
    language: str = "unknown",
    contexts: Optional[list] = None,
    top_k: int = DEFAULT_TOP_K,
    score_threshold: float = 0.0,
    severity_filter: Optional[str] = None,
    reranker: Optional[str] = None,
    host: str = "localhost",
    port: int = 6333,
) -> list:
    """
    Top-k similar CVEs for each finding. Returns one FindingRetrieval per
    finding, in the same order.

    Args:
        findings:         ForensicsAgent signals ({vulnerability_type, cwe_id,
                          affected_code, ...}); categorized findings with
                          {category, cwe_ids, evidence} also work.
        contexts:         optional per-finding CPG facts for the query:
                          {function, source, sanitized, entry_point}.
        score_threshold:  minimum cosine similarity for a candidate.
        severity_filter:  optional CRITICAL | HIGH | MEDIUM | LOW.
        reranker:         auto | cross-encoder | llm | none (default: RAG_RERANKER).
    """
    if not findings:
        return []
    contexts   = contexts or [None] * len(findings)
    client     = get_qdrant_client(host, port)
    collection = get_collection(client)
    reranker   = _choose_reranker(reranker)

    queries = [build_query(f, language, ctx) for f, ctx in zip(findings, contexts)]
    vectors = embed_queries(queries)

    severity_cond = (
        [FieldCondition(key="severity", match=MatchValue(value=severity_filter.upper()))]
        if severity_filter else []
    )
    families, requests = [], []
    for finding, vector in zip(findings, vectors):
        family = cwe_family(finding_cwes(finding))
        families.append(family)
        # Arm 1: same root-cause family. Arm 2: unrestricted.
        # (Without a CWE, arm 1 is just a second unrestricted search.)
        cwe_cond = [FieldCondition(key="cwe_ids", match=MatchAny(any=family))] if family else []
        for must in (cwe_cond + severity_cond, severity_cond):
            requests.append(QueryRequest(
                query           = vector,
                limit           = CANDIDATES_PER_ARM,
                filter          = Filter(must=must) if must else None,
                score_threshold = score_threshold or None,
                with_payload    = True,
            ))
    responses = client.query_batch_points(collection_name=collection, requests=requests)

    pools, considered = [], []
    for i, finding in enumerate(findings):
        hits = responses[2 * i].points + responses[2 * i + 1].points
        cands, seen = [], set()
        for hit in hits:
            if hit.id in seen:
                continue
            seen.add(hit.id)
            cands.append(_candidate(hit))

        cwes, family = finding_cwes(finding), set(families[i])
        terms = _key_terms(finding)
        for c in cands:
            _score_candidate(c, cwes, family, terms)
        cands.sort(key=lambda c: c["retrieval_score"], reverse=True)
        pools.append(_drop_near_duplicates(cands)[:RERANK_POOL])
        considered.append(len(cands))

    # One rerank call per finding, issued concurrently.
    if len(findings) > 1 and reranker == "llm":
        with ThreadPoolExecutor(max_workers=min(RERANK_CONCURRENCY, len(findings))) as ex:
            used_by = list(ex.map(lambda i: _rerank(queries[i], pools[i], reranker), range(len(findings))))
    else:
        used_by = [_rerank(queries[i], pools[i], reranker) for i in range(len(findings))]

    results = []
    for i, finding in enumerate(findings):
        pool, used = pools[i], used_by[i]
        final = _final_order(pool)[:top_k] if pool else []

        results.append(FindingRetrieval(
            finding               = {k: v for k, v in finding.items() if k != "similar_cves"},
            query                 = queries[i],
            cwe_family            = families[i],
            cve_matches           = [CVEMatch(rank=r + 1, **c).to_dict() for r, c in enumerate(final)],
            candidates_considered = considered[i],
            reranker              = used,
            collection            = collection,
        ))
    return results


def retrieve_for_finding(finding: dict, language: str = "unknown",
                         context: Optional[dict] = None, **kwargs) -> FindingRetrieval:
    return retrieve_for_findings([finding], language, [context], **kwargs)[0]


# ─── Pretty-print ──────────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "UNKNOWN":  "\033[90m",
}
RESET = "\033[0m"


def format_results(results, color: bool = True) -> str:
    """Renders one FindingRetrieval or a list of them."""
    if isinstance(results, FindingRetrieval):
        results = [results]
    lines = []
    for res in results:
        f = res.finding
        lines.append("┌─ Finding " + "─" * 60)
        lines.append(f"│  {f.get('vulnerability_type') or f.get('category', '?')}"
                     f"  {f.get('cwe_id') or ', '.join(f.get('cwe_ids', []))}"
                     f"  line {f.get('line', '?')}")
        lines.append(f"│  Query: {res.query}")
        lines.append(f"│  CWE family searched: {', '.join(res.cwe_family) or '—'}")
        lines.append(f"│  {res.candidates_considered} candidates, reranker: {res.reranker}")
        lines.append("└" + "─" * 70)

        if not res.cve_matches:
            lines.append("⚠  No CVEs found. Check Qdrant has data:")
            lines.append(f"   curl http://localhost:6333/collections/{res.collection}")
            continue

        for r in res.cve_matches:
            sev = r["severity"]
            col = SEVERITY_COLOR.get(sev, "") if color else ""
            rst = RESET if color else ""
            rr  = f"  rerank {r['rerank_score']:.2f}" if r["rerank_score"] is not None else ""
            lines.append(f"\n#{r['rank']}  {col}[{sev}]{rst}  {r['cve_id']}"
                         f"  score {r['score']:.3f}  (cosine {r['vector_score']:.3f}{rr},"
                         f" CWE {r['cwe_match']})")
            if r["cvss_score"] is not None:
                lines.append(f"    CVSS: {r['cvss_score']}")
            if r["cwe_ids"]:
                lines.append(f"    CWEs: {', '.join(r['cwe_ids'])}")
            if r.get("explanation"):
                lines.append(f"    Why:  {r['explanation']}")
            desc = r["description"]
            lines.append(f"    {desc[:300]}{'...' if len(desc) > 300 else ''}")
        lines.append("")
    return "\n".join(lines)
