#!/usr/bin/env python3
# rag/demo_rag.py
"""
Interactive demo for the finding-driven NVD RAG.

Usage:
    python demo_rag.py                    # paste code; findings come from the ForensicsAgent
    python demo_rag.py --snippet FILE     # same, code loaded from a file
    python demo_rag.py --builtin          # retrieve for built-in example findings
    python demo_rag.py --builtin --reranker none   # compare without reranking
"""

import sys
import argparse
import traceback
from pathlib import Path

# ── Built-in findings, shaped like ForensicsAgent output ──────────────────
EXAMPLES = [
    {"title": "Classic Buffer Overflow (C)", "language": "c",
     "context": {"function": "copy_username", "source": "command-line argument"},
     "finding": {"vulnerability_type": "buffer overflow", "cwe_id": "CWE-120",
                 "affected_code": "strcpy(buf, input);", "confidence": "HIGH", "line": 3}},
    {"title": "Use-After-Free (C)", "language": "c",
     "finding": {"vulnerability_type": "use after free", "cwe_id": "CWE-416",
                 "affected_code": "printf(\"Value: %d\\n\", ptr[0]);", "confidence": "HIGH", "line": 4}},
    {"title": "Command Injection (C)", "language": "c",
     "context": {"function": "run_cmd", "source": "network data"},
     "finding": {"vulnerability_type": "OS command injection", "cwe_id": "CWE-78",
                 "affected_code": "system(cmd);", "confidence": "HIGH", "line": 4}},
    {"title": "Null Pointer Dereference (C++)", "language": "cpp",
     "finding": {"vulnerability_type": "null pointer dereference", "cwe_id": "CWE-476",
                 "affected_code": "return n->data;", "confidence": "MEDIUM", "line": 3}},
    {"title": "Integer Overflow (C)", "language": "c",
     "finding": {"vulnerability_type": "integer overflow leading to heap overflow", "cwe_id": "CWE-190",
                 "affected_code": "char *buf = malloc(len + 1);", "confidence": "MEDIUM", "line": 2}},
    {"title": "Format String (C)", "language": "c",
     "finding": {"vulnerability_type": "format string vulnerability", "cwe_id": "CWE-134",
                 "affected_code": "printf(user_input);", "confidence": "HIGH", "line": 2}},
    {"title": "SQL Injection (Python)", "language": "python",
     "context": {"function": "get_user", "source": "HTTP request data"},
     "finding": {"vulnerability_type": "SQL injection", "cwe_id": "CWE-89",
                 "affected_code": "cursor.execute(\"SELECT * FROM users WHERE name = '\" + username + \"'\")",
                 "confidence": "HIGH", "line": 3}},
    {"title": "Insecure Deserialization (Python)", "language": "python",
     "finding": {"vulnerability_type": "insecure deserialization", "cwe_id": "CWE-502",
                 "affected_code": "return pickle.loads(data)", "confidence": "HIGH", "line": 4}},
]

SEP = "─" * 72


def retrieve_and_print(findings, language, contexts, top_k, severity, reranker, verbose):
    from rag_nvd2 import retrieve_for_findings, format_results
    try:
        results = retrieve_for_findings(findings, language=language, contexts=contexts,
                                        top_k=top_k, severity_filter=severity, reranker=reranker)
    except Exception:
        print("\n❌  Error during retrieval:")
        traceback.print_exc()
        return
    print(format_results(results, color=True))
    if verbose:
        for r in results:
            print(r.to_json())


def findings_from_code(code: str):
    """Run the pipeline's CPG + Forensics agents to get real findings for `code`."""
    agents_dir = Path(__file__).resolve().parent.parent / "agents"
    sys.path.insert(0, str(agents_dir))
    from orchestrator2 import PipelineState, CPGAgent, ForensicsAgent, RAGQueryAgent

    state = ForensicsAgent().run(CPGAgent().run(PipelineState(code=code)))
    paths = []
    if state.cpg_extractor is not None:
        try:
            paths = state.cpg_extractor.profiler.taint_paths()
        except Exception:
            pass
    rag = RAGQueryAgent()
    contexts = [rag._finding_context(state, s, paths) for s in state.forensics_signals]
    return state.forensics_signals, state.language, contexts


def run_code(code, args):
    print(f"\n{SEP}\n► Code snippet submitted:\n{SEP}")
    for line in code.strip().splitlines():
        print(f"  {line}")
    print(SEP)
    findings, language, contexts = findings_from_code(code)
    if not findings:
        print("ℹ  ForensicsAgent reported no findings — nothing to retrieve.")
        return
    retrieve_and_print(findings, language, contexts, args.top_k, args.severity, args.reranker, args.verbose)


def interactive_mode(args):
    print("  Paste a code snippet; press ENTER on a blank line to submit. Type 'quit' to exit.\n")
    while True:
        print(SEP)
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                line = ""
            if line.strip().lower() == "quit":
                sys.exit(0)
            if line == "" and lines:
                break
            lines.append(line)
        code = "\n".join(lines).strip()
        if code:
            run_code(code, args)


def builtin_mode(args):
    for i, ex in enumerate(EXAMPLES, 1):
        print(f"\n{'═' * 72}\n  Example {i}/{len(EXAMPLES)}: {ex['title']}\n{'═' * 72}")
        retrieve_and_print([ex["finding"]], ex["language"], [ex.get("context")],
                           args.top_k, args.severity, args.reranker, args.verbose)


def main():
    parser = argparse.ArgumentParser(description="NVD RAG Demo — similar CVEs per finding")
    parser.add_argument("--snippet", metavar="FILE", help="Path to a source file to analyse")
    parser.add_argument("--builtin", action="store_true", help="Run the built-in example findings")
    parser.add_argument("--top-k", type=int, default=5, help="CVEs per finding (default: 5)")
    parser.add_argument("--severity", metavar="LEVEL", help="Filter: CRITICAL | HIGH | MEDIUM | LOW")
    parser.add_argument("--reranker", choices=["auto", "cross-encoder", "llm", "none"],
                        help="Override RAG_RERANKER")
    parser.add_argument("--verbose", action="store_true", help="Print full JSON per finding")
    args = parser.parse_args()

    if args.snippet:
        try:
            code = Path(args.snippet).read_text(encoding="utf-8", errors="ignore")
        except FileNotFoundError:
            sys.exit(f"❌  File not found: {args.snippet}")
        run_code(code, args)
    elif args.builtin:
        builtin_mode(args)
    else:
        interactive_mode(args)


if __name__ == "__main__":
    main()
