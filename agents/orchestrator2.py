# agents/orchestrator.py
"""
Sequential pipeline orchestrator for the NVD RAG vulnerability detection system.

Architecture:
  code input
      ↓  ParseAgent           – tree-sitter AST extraction (regex fallback)
      ↓  ForensicsAgent       – LLM analyses code for vulnerability signals
      ↓  RAGQueryAgent        – retrieves relevant CVEs from Qdrant
      ↓  CategorizationAgent  – categorizes and ranks findings
      ↓  ValidationAgent      – validates findings, filters false positives
      ↓  ExplainableAIAgent   – explains why each vulnerability exists
      ↓  AdvisoryAgent        – suggests specific code fixes
      ↓  DashboardFormatter   – structures final output

Run:
    python orchestrator.py                        # test with built-in snippet
    python orchestrator.py path/to/file.c         # analyse a file
    python orchestrator.py path/to/file.py --json # full JSON output
    python orchestrator.py --builtin              # run all built-in examples
"""

import json
import re
import traceback
import argparse
import sys
import textwrap
from dataclasses import dataclass, asdict, field, fields, is_dataclass
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
import os

import ollama
import sys
from pathlib import Path

# rag_nvd2.py lives in ../rag, not next to this file — this orchestrator is
# always launched from agents/, so rag_nvd2 is never importable without this.
_RAG_DIR = Path(__file__).resolve().parent.parent / "rag"
if str(_RAG_DIR) not in sys.path:
    sys.path.insert(0, str(_RAG_DIR))

# joern_cpg lives next to this file; make that explicit so imports also work
# when the module is loaded from elsewhere (webui, tests).
_AGENTS_DIR = Path(__file__).resolve().parent
if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))

from ollama_retry import with_retry
from validation_guardrails import assess, memory_safety_gate, fix_regressions
from risk_evidence import linked_signals
from joern_cpg import (
    ContextExtractor, ContextRequest, FACETS, JoernRunner, JoernUnavailable,
)


def asdict_value(v):
    """asdict() for a single field value (dataclass-aware, leaves the rest)."""
    return asdict(v) if is_dataclass(v) and not isinstance(v, type) else v


# ─── Risk scoring ──────────────────────────────────────────

RISK_DIMENSIONS = (
    "exploitability", "exposure", "attack_prerequisites",
    "confidentiality", "integrity", "availability",
)

# (upper bound, level) — scores are checked in order.
RISK_LEVELS = (
    (5.0,  "LOW"),        # monitor, patch in regular cycle
    (10.0, "MEDIUM"),     # patch within 30 days
    (16.0, "HIGH"),       # patch within 7 days
    (21.0, "CRITICAL"),   # patch within 48 hours
    (25.0, "EMERGENCY"),  # immediate action required
)

RISK_EMOJI = {
    "EMERGENCY": "🚨",
    "CRITICAL":  "🔴",
    "HIGH":      "🟠",
    "MEDIUM":    "🟡",
    "LOW":       "🟢",
}


def calculate_risk_score(
    exploitability: int,
    exposure: int,
    attack_prerequisites: int,
    confidentiality: int,
    integrity: int,
    availability: int,
) -> dict:
    """
    Pure risk score from six 1-5 dimension scores.

        likelihood = exploitability^0.4 * exposure^0.35 * attack_prerequisites^0.25
        impact     = 0.6 * max(C, I, A) + 0.4 * avg(C, I, A)
        risk_score = likelihood * impact          (1.0 - 25.0)

    risk_level: <=5 LOW, <=10 MEDIUM, <=16 HIGH, <=21 CRITICAL, else EMERGENCY.
    """
    likelihood = (
        exploitability ** 0.4
        * exposure ** 0.35
        * attack_prerequisites ** 0.25
    )
    cia    = (confidentiality, integrity, availability)
    impact = 0.6 * max(cia) + 0.4 * (sum(cia) / 3)
    risk   = round(min(25.0, max(1.0, likelihood * impact)), 2)
    level  = next(lvl for bound, lvl in RISK_LEVELS if risk <= bound)
    return {
        "exploitability":       exploitability,
        "exposure":             exposure,
        "attack_prerequisites": attack_prerequisites,
        "confidentiality":      confidentiality,
        "integrity":            integrity,
        "availability":         availability,
        "likelihood":           round(likelihood, 4),
        "impact":               round(impact, 4),
        "risk_score":           risk,
        "risk_level":           level,
    }


def _dimension_score(value, default: Optional[int] = 3) -> Optional[int]:
    """LLM-supplied dimension score as an int clamped to 1-5 (missing -> default)."""
    try:
        return max(1, min(5, int(round(float(value)))))
    except (TypeError, ValueError):
        return default

# ─── Config ────────────────────────────────────────────────
FORENSICS_MODEL    = "llama3.2"
CATEGORIZE_MODEL   = "llama3.2"
VALIDATION_MODEL   = "validation-agent"   # finetuned model
                                           # fallback: "llama3.2"
EXPLAINER_MODEL    = "llama3.2"
ADVISORY_MODEL     = "llama3.2"

# Max concurrent LLM calls issued by one agent (e.g. one per finding).
LLM_CONCURRENCY    = int(os.environ.get("LLM_CONCURRENCY", "4"))

# ─── JSON schemas for structured decoding ──────────────────
# Passed as Ollama's `format` param so the model is grammar-constrained to
# this exact shape at decode time, rather than just "some valid JSON" (which
# still let the model choose a bare object, or a dict keyed by id, instead
# of the requested array).

FORENSICS_ITEM_SCHEMA = {
        "type": "object",
        "properties": {
            "vulnerability_type": {"type": "string"},
            "affected_code":      {"type": "string"},
            "cwe_id":             {"type": "string"},
            "confidence":         {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
            "line":               {"type": "integer"},
        },
    "required": ["vulnerability_type", "affected_code", "cwe_id", "confidence", "line"],
}

CATEGORIZE_ITEM_SCHEMA = {
        "type": "object",
        "properties": {
            "category":        {"type": "string"},
            "severity":        {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "cwe_ids":         {"type": "array", "items": {"type": "string"}},
            "evidence":        {"type": "string"},
            "related_cves":    {"type": "array", "items": {"type": "string"}},
            "stride":          {"type": "array", "items": {"type": "string"}},
            "mitre_atlas":     {"type": "array", "items": {"type": "string"}},
            **{d: {"type": "integer", "minimum": 1, "maximum": 5} for d in RISK_DIMENSIONS},
        },
    "required": ["category", "severity", "cwe_ids", "evidence", "related_cves", *RISK_DIMENSIONS],
}


VALIDATION_ITEM_SCHEMA = {
        "type": "object",
        "properties": {
            "category":  {"type": "string"},
            "verdict":   {"type": "string", "enum": ["CONFIRMED", "FALSE_POSITIVE", "NEEDS_CONTEXT"]},
            "reasoning": {"type": "string"},
            "severity":  {"type": "string"},
        },
    "required": ["category", "verdict", "reasoning", "severity"],
}

EXPLAINER_ITEM_SCHEMA = {
        "type": "object",
        "properties": {
            "category":        {"type": "string"},
            "what_is_wrong":   {"type": "string"},
            "why_dangerous":   {"type": "string"},
            "attack_scenario": {"type": "string"},
            "cwe_explanation": {"type": "string"},
        },
    "required": ["category", "what_is_wrong", "why_dangerous", "attack_scenario", "cwe_explanation"],
}

ADVISORY_ITEM_SCHEMA = {
        "type": "object",
        "properties": {
            "category":        {"type": "string"},
            "fix_description": {"type": "string"},
            "fixed_code":      {"type": "string"},
            "references": {
                "type": "object",
                "properties": {
                    "cwe":  {"type": "string"},
                    "cves": {"type": "array", "items": {"type": "string"}},
                },
            },
            "libraries": {"type": "array", "items": {"type": "string"}},
        },
    "required": ["category", "fix_description", "fixed_code", "references", "libraries"],
}


# ─── Pipeline state ────────────────────────────────────────
# Single object passed through every agent.
# Each agent reads what it needs and writes its own output.
# Nothing is discarded between steps.

@dataclass
class PipelineState:

    # ── Input ──────────────────────────────────────────────
    code:               str
    language:           str = "unknown"

    # ── Step 1 — ParseAgent ────────────────────────────────
    ast_functions:      list = field(default_factory=list)
    ast_calls:          list = field(default_factory=list)
    parse_success:      bool = False
    cpg_backend:        str  = "none"        # "joern-project" | "joern" | "tree-sitter" | "regex"
    cpg_extractor:      Optional[object] = None   # joern_cpg.ContextExtractor
    # Set by ProjectScanner: {frontend: joern_cpg.CPG} for the whole project,
    # and this file's path relative to the project root. None = no project scan.
    project_cpgs:       Optional[dict] = None
    source_path:        Optional[str]  = None

    # ── Step 2 — ForensicsAgent ────────────────────────────
    forensics_signals:  list = field(default_factory=list)
    forensics_summary:  str  = ""
    security_context:   str  = ""        # CPG security context given to the LLM
    security_stats:     dict = field(default_factory=dict)

    # ── Step 3 — RAGQueryAgent ─────────────────────────────
    rag_result:         Optional[object] = None
    cve_matches:        list = field(default_factory=list)
    cwe_hints:          list = field(default_factory=list)
    cvss_prefetch:      Optional[object] = None   # Future -> {cve_id: CVSS vector}

    # ── Step 4 — CategorizationAgent ──────────────────────
    ranked_findings:    list = field(default_factory=list)
    risk_scores:        list = field(default_factory=list)   # [{category, risk_score, risk_level, likelihood, impact, ...dims}]

    # ── Step 5 — ValidationAgent ───────────────────────────
    validated_findings: list = field(default_factory=list)
    false_positives:    list = field(default_factory=list)
    needs_context_findings: list = field(default_factory=list)   # still undecided after feedback rounds
    feedback_rounds:    list = field(default_factory=list)       # log of NEEDS_CONTEXT -> forensics rounds
    is_clean:           bool = False

    # ── Step 6 — ExplainableAIAgent ────────────────────────
    explanations:       list = field(default_factory=list)

    # ── Step 7 — AdvisoryAgent ─────────────────────────────
    advisories:         list = field(default_factory=list)

    # ── Pipeline meta ──────────────────────────────────────
    errors:             list = field(default_factory=list)
    steps_completed:    list = field(default_factory=list)

    # Fields holding live objects (not JSON serializable, and asdict() would
    # deep-copy the whole CPG).
    _NON_SERIALIZABLE = ("rag_result", "cpg_extractor", "project_cpgs", "cvss_prefetch")

    def to_dict(self) -> dict:
        return {
            f.name: asdict_value(getattr(self, f.name))
            for f in fields(self)
            if f.name not in self._NON_SERIALIZABLE
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# ─── Base agent ────────────────────────────────────────────

class BaseAgent:
    name = "BaseAgent"

    def run(self, state: PipelineState) -> PipelineState:
        raise NotImplementedError

    def _log(self, msg: str):
        print(f"    [{self.name}] {msg}")

    def _error(self, state: PipelineState, msg: str) -> PipelineState:
        print(f"    [{self.name}] ❌ {msg}")
        state.errors.append({"agent": self.name, "error": msg})
        return state

    def _llm(
        self,
        prompt:      str,
        model:       str,
        temperature: float = 0,
        schema:      Optional[dict] = None,
    ) -> str:
        """
        Call Ollama and return the raw response string.

        `schema`, when given, is passed as Ollama's `format` param — this
        grammar-constrains decoding to that exact JSON shape, rather than
        just "valid JSON" (which still lets the model choose e.g. a bare
        object or an id-keyed dict instead of the requested array).
        `num_predict` is capped so a model that never emits a stop token
        fails fast instead of generating until the context window forces
        a truncation.
        """
        response = with_retry(
            ollama.chat,
            model    = model,
            messages = [{"role": "user", "content": prompt}],
            format   = schema if schema is not None else "json",
            options  = {"temperature": temperature, "num_predict": 2048},
        )
        return response["message"]["content"].strip()

    def _parse_json_array(self, raw: str) -> Optional[list]:
        """
        Robustly extract a JSON array from LLM output, tolerating shapes a
        schema doesn't fully rule out: a bare object where an array of one
        was meant, an id-keyed dict of items instead of a list, or several
        JSON documents concatenated back to back. Returns None only when no
        JSON can be recovered at all — never for a legitimately empty [].
        """
        raw = raw.strip()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            try:
                value, _ = json.JSONDecoder().raw_decode(raw)
            except json.JSONDecodeError:
                return None

        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for v in value.values():
                if isinstance(v, list):
                    return v
            if value and all(isinstance(v, dict) for v in value.values()):
                return list(value.values())
            return [value]
        return None

    def _parse_json_object(self, raw: str) -> Optional[dict]:
        """Robustly extract a JSON object from LLM output."""
        match = re.search(r"\{[\s\S]*\}", raw)
        if not match:
            return None
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            return None

    def _bounded_schema(self, item_schema: dict, count: int = None,
                         max_items: int = 10) -> dict:
        """
        Wraps an item schema in an array schema with minItems/maxItems.

        Ollama's json-schema-backed grammar enforces this at the token
        level, which matters beyond validation: under temperature=0 with a
        JSON-format response, the model can get stuck emitting the same
        array item over and over rather than closing the array (a
        repetition loop specific to grammar-constrained decoding). Capping
        maxItems makes that structurally impossible — the grammar forces
        `]` once the cap is hit — instead of relying on num_predict to cut
        it off mid-object.

        When `count` is known (one item per input finding), pin min==max to
        that exact count instead of an open-ended cap.
        """
        schema = {"type": "array", "items": item_schema}
        if count is not None:
            schema["minItems"] = count
            schema["maxItems"] = count
        else:
            schema["maxItems"] = max_items
        return schema


# ─── Step 1: Parse Agent ───────────────────────────────────

class ParseAgent(BaseAgent):
    """
    Extracts code structure using tree-sitter.
    Falls back to regex-based extraction if tree-sitter is not installed.

    Outputs:
        state.language       – detected language string
        state.ast_functions  – list of {name, body, start_line, end_line}
        state.ast_calls      – list of call expression strings
        state.parse_success  – True if tree-sitter succeeded
    """
    name = "ParseAgent"

    def _get_tree_sitter_parser(self, language: str):
        lang_key = (language or "unknown").lower()
        from tree_sitter import Language, Parser

        raw_lang = None
        if lang_key in ("c", "h"):
            import tree_sitter_c as mod
            raw_lang = mod.language()
        elif lang_key in ("cpp", "cc", "cxx", "hpp", "c++"):
            import tree_sitter_cpp as mod
            raw_lang = mod.language()
        elif lang_key in ("python", "py"):
            import tree_sitter_python as mod
            raw_lang = mod.language()
        elif lang_key in ("javascript", "js", "jsx", "mjs", "cjs"):
            import tree_sitter_javascript as mod
            raw_lang = mod.language()
        elif lang_key in ("typescript", "ts", "tsx"):
            import tree_sitter_typescript as mod
            raw_lang = mod.language_typescript()
        elif lang_key in ("java",):
            import tree_sitter_java as mod
            raw_lang = mod.language()
        elif lang_key in ("go",):
            import tree_sitter_go as mod
            raw_lang = mod.language()
        elif lang_key in ("rust", "rs"):
            import tree_sitter_rust as mod
            raw_lang = mod.language()
        elif lang_key in ("php",):
            import tree_sitter_php as mod
            raw_lang = mod.language_php()

        if raw_lang is not None:
            lang = Language(raw_lang)
            return Parser(lang)

        # Fallback to tree_sitter_languages if available
        try:
            import tree_sitter_languages
            lang = tree_sitter_languages.get_language(lang_key)
            p = Parser()
            if hasattr(p, "set_language"):
                p.set_language(lang)
            return p
        except Exception:
            return None

    def run(self, state: PipelineState) -> PipelineState:
        self._log("Parsing code structure...")

        if not state.language or state.language == "unknown":
            state.language = self._detect_language(state.code)
        self._log(f"Detected language: {state.language}")

        try:
            parser = self._get_tree_sitter_parser(state.language)
            if parser is None:
                raise ImportError(f"No tree-sitter parser available for '{state.language}'")

            tree = parser.parse(bytes(state.code, "utf-8"))

            state.ast_functions = self._extract_functions(tree, state.code)
            state.ast_calls     = self._extract_calls(tree, state.code)
            state.parse_success = True
            self._log(
                f"tree-sitter: {len(state.ast_functions)} functions, "
                f"{len(state.ast_calls)} calls"
            )

        except (ImportError, ModuleNotFoundError) as e:
            self._log(f"tree-sitter grammar missing ({e}) — using regex fallback")
            state.ast_functions = self._regex_functions(state.code)
            state.ast_calls     = self._regex_calls(state.code)
            state.parse_success = False
            self._log(
                f"regex fallback: {len(state.ast_functions)} functions, "
                f"{len(state.ast_calls)} calls"
            )

        except Exception as e:
            self._error(state, f"Parse failed: {e} — using regex fallback")
            state.ast_functions = self._regex_functions(state.code)
            state.ast_calls     = self._regex_calls(state.code)
            state.parse_success = False

        state.steps_completed.append(self.name)
        return state

    # ── Language detection ─────────────────────────────────

    def _detect_language(self, code: str) -> str:
        if re.search(r"#include|void\s+\w+\s*\(|int\s+main", code):
            return "c"
        if re.search(r"def\s+\w+\s*\(|import\s+\w+|print\s*\(", code):
            return "python"
        if re.search(r"function\s+\w+|const\s+\w+\s*=|document\.|console\.log", code):
            return "javascript"
        if re.search(r"public\s+class|System\.out|void\s+\w+\s*\(", code):
            return "java"
        if re.search(r"package\s+\w+|func\s+\w+\s*\(", code):
            return "go"
        if re.search(r"fn\s+\w+\s*\(|let\s+mut\s+", code):
            return "rust"
        if re.search(r"<\?php|\$\w+\s*=", code):
            return "php"
        return "unknown"


    # ── tree-sitter extractors ─────────────────────────────

    def _extract_functions(self, tree, code: str) -> list:
        functions = []

        def walk(node):
            if node.type in (
                "function_definition",
                "function_declaration",
                "method_declaration",
                "method_definition",
                "function_item",
                "arrow_function",
                "function_expression",
            ):
                start = node.start_byte
                end   = node.end_byte
                name = "anonymous"
                name_node = node.child_by_field_name("name")
                if name_node:
                    try:
                        name = name_node.text.decode("utf-8")
                    except Exception:
                        name = code[name_node.start_byte:name_node.end_byte]
                else:
                    name_part = code[start:min(start + 60, end)]
                    name_match = re.search(r"\b(\w+)\s*\(", name_part)
                    if name_match:
                        name = name_match.group(1)

                functions.append({
                    "name":       name,
                    "body":       code[start:end],
                    "start_line": node.start_point[0],
                    "end_line":   node.end_point[0],
                })
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return functions

    def _extract_calls(self, tree, code: str) -> list:
        calls = []

        def walk(node):
            if node.type in ("call_expression", "call"):
                start = node.start_byte
                end   = node.end_byte
                calls.append(code[start:min(start + 100, end)])
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return calls


    # ── Regex fallbacks ────────────────────────────────────

    def _regex_functions(self, code: str) -> list:
        pattern = (
            r"(?:def|void|int|char\s*\*?|static|public|private|protected)"
            r"\s+(\w+)\s*\([^)]*\)"
        )
        return [
            {"name": m.group(1), "body": "", "start_line": 0, "end_line": 0}
            for m in re.finditer(pattern, code)
        ]

    def _regex_calls(self, code: str) -> list:
        return re.findall(r"\b(\w+)\s*\([^)]*\)", code)


class CPGAgent(ParseAgent):
    """
    Builds a Joern Code Property Graph (AST + CFG + data dependence) and
    exposes a ContextExtractor over it for downstream agents.

    Falls back to ParseAgent (tree-sitter, then regex) when Joern is not
    installed / has no frontend for the language / fails. In that case the
    extractor still exists but serves plain source windows.

    Outputs (in addition to ParseAgent's):
        state.cpg_backend    – "joern" | "tree-sitter" | "regex"
        state.cpg_extractor  – ContextExtractor used by ValidationAgent
    """
    name = "CPGAgent"

    _runner: Optional[JoernRunner] = None
    _runner_failed = False

    @classmethod
    def _get_runner(cls) -> Optional[JoernRunner]:
        if cls._runner is None and not cls._runner_failed:
            try:
                cls._runner = JoernRunner()
            except JoernUnavailable:
                cls._runner_failed = True
        return cls._runner

    def _adopt(self, state: PipelineState, cpg, backend: str) -> PipelineState:
        """Expose a CPG (or file view of one) to the downstream agents."""
        state.ast_functions = [
            {
                "name":       m.name,
                "body":       "\n".join(cpg.source_lines[(m.line or 1) - 1:(m.end or 0)]),
                "start_line": (m.line or 1) - 1,
                "end_line":   (m.end or 1) - 1,
            }
            for m in cpg.methods.values()
        ]
        state.ast_calls = [
            c.get("code", "")[:100]
            for m in cpg.methods.values() for c in m.calls
            if not c.get("name", "").startswith("<operator>")
        ]
        state.parse_success = True
        state.cpg_backend   = backend
        state.cpg_extractor = ContextExtractor(cpg, state.code, language=state.language)
        self._log(
            f"{backend}: {len(cpg.methods)} methods in scope, "
            f"{len(cpg.ddg)} data-dependence edges"
        )
        state.steps_completed.append(self.name)
        return state

    def run(self, state: PipelineState) -> PipelineState:
        if not state.language or state.language == "unknown":
            state.language = self._detect_language(state.code)

        # 1. Project scan: the scanner built one CPG over the whole repo.
        #    Use this file's view of it, so cross-file callers/callees resolve.
        if state.project_cpgs is not None:
            frontend = JoernRunner.frontend_for(state.language)
            project  = state.project_cpgs.get(frontend) if frontend else None
            if project is not None and state.source_path:
                view = project.view(state.source_path, state.code)
                return self._adopt(state, view, "joern-project")
            # Joern disabled, failed, or no frontend: tree-sitter / regex only.
            # Per-file Joern runs would cost a JVM start per file, so none here.
            self._log("No project CPG for this file — falling back to tree-sitter")

        # 2. Single snippet (CLI / web UI): build a CPG for just this code.
        elif (runner := self._get_runner()) is not None and runner.supports(state.language):
            self._log(f"Building Joern CPG ({state.language})...")
            try:
                cpg = runner.build(state.code, state.language)
                return self._adopt(state, cpg, "joern")
            except Exception as e:
                self._log(f"Joern failed ({str(e)[:300]}) — falling back to tree-sitter")
        else:
            self._log("Joern unavailable for this input — falling back to tree-sitter")

        # Fallback path: ParseAgent appends its own step name; relabel it.
        state = super().run(state)
        if state.steps_completed and state.steps_completed[-1] == ParseAgent.name:
            state.steps_completed[-1] = self.name
        state.cpg_backend   = "tree-sitter" if state.parse_success else "regex"
        state.cpg_extractor = ContextExtractor(None, state.code, state.ast_functions,
                                               language=state.language)
        return state


# ─── Step 2: Forensics Agent ───────────────────────────────

class ForensicsAgent(BaseAgent):
    """
    LLM analyses the CPG-extracted security context of the file — not the raw
    file or the whole graph — to identify vulnerability signals before RAG
    retrieval.

    The context (joern_cpg.SecurityProfiler) covers: file metadata/location,
    security boundaries & entry points, sources, sinks, source->sink taint
    flows (interprocedural), sanitizers/validation checks, control flow &
    program dependencies, call graph, memory/resource management and
    security-sensitive operations, plus a line-numbered code slice.

    Outputs:
        state.forensics_signals  – list of {vulnerability_type, affected_code,
                                            cwe_id, confidence, line}
        state.forensics_summary  – plain-text summary for downstream agents
        state.security_context   – the rendered context given to the LLM
        state.security_stats     – counts (sinks, sources, taint paths, ...)
    """
    name = "ForensicsAgent"

    CONTEXT_CHARS = 3500     # structured sections
    CODE_CHARS    = 2500     # line-numbered code slice

    def _context(self, state: PipelineState) -> str:
        if state.cpg_extractor is None:
            return f"## Code\n{state.code[:self.CODE_CHARS]}"
        prof = state.cpg_extractor.profile(
            max_chars=self.CONTEXT_CHARS, code_chars=self.CODE_CHARS,
            backend=state.cpg_backend,
        )
        state.security_stats = prof.stats
        return prof.render()

    @staticmethod
    def _is_inert(state: PipelineState) -> bool:
        """
        True when the security profile shows nothing an attacker could abuse:
        no sinks, no sensitive operations (crypto, credentials, ...) and no
        memory/resource issues. Such files skip the LLM entirely, which on a
        real repo is most of them. Only trusted for languages the security
        catalog covers; FORENSICS_SKIP_INERT=0 disables it.
        """
        if os.environ.get("FORENSICS_SKIP_INERT", "1") == "0" or state.cpg_extractor is None:
            return False
        from joern_cpg.security_catalog import family_of
        if family_of(state.language) is None:      # no catalog: absence of matches means nothing
            return False
        stats = state.security_stats
        return bool(stats) and not any(stats.get(k) for k in ("sinks", "sensitive", "resource_issues"))

    def run(self, state: PipelineState) -> PipelineState:
        self._log("Extracting CPG security context...")
        try:
            context = self._context(state)
        except Exception as e:
            self._error(state, f"Context extraction failed ({e}) — using raw code")
            context = f"## Code\n{state.code[:self.CODE_CHARS]}"
        state.security_context = context
        if state.security_stats:
            self._log(
                "Context: " + ", ".join(f"{k}={v}" for k, v in state.security_stats.items())
                + f" ({len(context)} chars)"
            )

        if self._is_inert(state):
            self._log("No sinks, sensitive operations or resource issues — skipping LLM analysis")
            state.forensics_signals = []
            state.forensics_summary = "No security-relevant operations in this file"
            state.steps_completed.append(self.name)
            return state

        self._log("Analysing code for vulnerability signals...")

        prompt = f"""You are a security code analyst. Below is security context extracted from the code property graph (CPG) of a {state.language} file, followed by the relevant line-numbered code.

{context}

How to use the context:
- A taint flow marked "NO sanitizer on path" from an untrusted source into a sink is a strong vulnerability signal; one that is sanitized or checked needs a weaker confidence.
- A sink with no reaching source is only a vulnerability if the operation is unsafe on its own (e.g. hardcoded command, weak crypto).
- Entry points mean their parameters are attacker-controlled; a function reachable from an entry point inherits that.
- Memory & resource findings (use after release, double release, leaks, unchecked allocation) are vulnerabilities in their own right.
- Security-sensitive operations (weak crypto, disabled TLS checks, hardcoded credentials, debug mode) count even without taint.
- Only report issues supported by the context or the code shown.

For each vulnerability provide:
- vulnerability_type: the class of vulnerability (e.g. buffer overflow, SQL injection)
- affected_code:      the exact vulnerable statement, copied from the code
- cwe_id:             the single most relevant CWE ID (e.g. CWE-120)
- confidence:         HIGH, MEDIUM, or LOW
- line:               the line number of affected_code

Respond ONLY with a JSON array. If no vulnerabilities found, respond with [].

Example:
[
  {{
    "vulnerability_type": "buffer overflow",
    "affected_code":      "strcpy(buf, input)",
    "cwe_id":             "CWE-120",
    "confidence":         "HIGH",
    "line":               12
  }}
]"""

        try:
            raw    = self._llm(prompt, FORENSICS_MODEL,
                            schema=self._bounded_schema(FORENSICS_ITEM_SCHEMA, max_items=10))
            parsed = self._parse_json_array(raw)

            if parsed is not None:
                state.forensics_signals = parsed
                self._log(f"Found {len(parsed)} vulnerability signals")
            else:
                state.forensics_signals = []
                self._log("No signals detected (parse failed)")

            if state.forensics_signals:
                types = [s.get("vulnerability_type", "unknown")
                         for s in state.forensics_signals]
                state.forensics_summary = (
                    f"Detected {len(types)} potential vulnerabilities: "
                    + ", ".join(types)
                )
            else:
                state.forensics_summary = "No vulnerabilities detected in forensic analysis"

        except Exception as e:
            self._error(state, f"Forensics LLM call failed: {e}")
            state.forensics_signals = []
            state.forensics_summary = "Forensics unavailable"

        state.steps_completed.append(self.name)
        return state


    # ── NEEDS_CONTEXT feedback ─────────────────────────────
    REEXAMINE_CHARS = 4500
    # Always added on a re-examination: the validator could not decide with
    # what it had, so give forensics the widest view of the finding.
    REEXAMINE_FACETS = ["full_function", "callers", "data_flow", "taint", "guards", "sanitizers"]

    REEXAMINE_SCHEMA = {
        "type": "object",
        "properties": {
            "still_vulnerable":   {"type": "boolean"},
            "vulnerability_type": {"type": "string"},
            "affected_code":      {"type": "string"},
            "cwe_id":             {"type": "string"},
            "confidence":         {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
            "line":               {"type": "integer"},
            "rationale":          {"type": "string"},
        },
        "required": ["still_vulnerable", "vulnerability_type", "affected_code",
                     "cwe_id", "confidence", "line", "rationale"],
    }

    def reexamine(self, state: PipelineState, findings: list) -> tuple:
        """
        Second look at findings the ValidationAgent could not decide. For each,
        re-extract a wider CPG slice (the validator's last request + the
        REEXAMINE_FACETS) and ask the forensics model to settle it with the
        validator's doubt in view: refine the finding (precise statement,
        line, CWE, evidence) or withdraw it.

        Returns (refined forensics signals, withdrawn findings, findings that
        could not be re-examined and stay undecided).
        """
        if state.cpg_extractor is None or not findings:
            return [], [], list(findings)

        def one(finding: dict):
            req = finding.get("context_request") or {}
            request = ContextRequest(**{k: list(req.get(k, [])) for k in ("facets", "symbols")})
            request = request.merge(ContextRequest(facets=self.REEXAMINE_FACETS))
            ctx = state.cpg_extractor.extract(finding, request, max_chars=self.REEXAMINE_CHARS)

            prompt = f"""You are a security code analyst. You earlier flagged a possible vulnerability in this {state.language} file, but the reviewer could not confirm or reject it with the context they had.

Finding:
{json.dumps({k: finding.get(k) for k in ("category", "cwe_ids", "evidence", "severity")}, indent=2)}

Why the reviewer could not decide:
{finding.get("reasoning") or "not stated"}

Expanded context from the code property graph (whole function, callers, data flow, taint paths, guards):
{ctx.render(with_facts=True)}

Re-examine the finding using ONLY this code and these facts.
- still_vulnerable: true only if the code shown really allows it (e.g. untrusted data reaches the operation with no adequate check); false if the context shows it is guarded, unreachable, or was a misreading.
- If true: give the exact vulnerable statement copied from the code (affected_code), its line, the single most accurate CWE, and in rationale cite the specific lines/facts that make it exploitable.
- If false: in rationale cite what rules it out; the other fields may repeat the original values.
Respond with one JSON object."""
            try:
                parsed = self._parse_json_object(
                    self._llm(prompt, FORENSICS_MODEL, schema=self.REEXAMINE_SCHEMA))
            except Exception as e:
                self._log(f"Re-examination failed for '{finding.get('category')}': {e}")
                return finding, None
            return finding, parsed

        if len(findings) > 1:
            with ThreadPoolExecutor(max_workers=min(LLM_CONCURRENCY, len(findings))) as pool:
                results = list(pool.map(one, findings))
        else:
            results = [one(findings[0])]

        refined, withdrawn, unchanged = [], [], []
        for finding, parsed in results:
            if not parsed:
                unchanged.append(finding)
                continue
            if parsed.get("still_vulnerable"):
                refined.append({
                    "vulnerability_type": parsed.get("vulnerability_type") or finding.get("category"),
                    "affected_code":      parsed.get("affected_code") or finding.get("evidence", ""),
                    "cwe_id":             parsed.get("cwe_id") or (finding.get("cwe_ids") or [""])[0],
                    "confidence":         parsed.get("confidence", "MEDIUM"),
                    "line":               parsed.get("line") or 0,
                    "rationale":          parsed.get("rationale", ""),
                    "refined_from":       finding.get("category"),
                })
            else:
                withdrawn.append({**finding, "verdict": "FALSE_POSITIVE",
                                  "reasoning": "Withdrawn on forensic re-examination: "
                                               + str(parsed.get("rationale", ""))})
        return refined, withdrawn, unchanged


# ─── Step 3: RAG Query Agent ───────────────────────────────

class RAGQueryAgent(BaseAgent):
    """
    Retrieves the top-k most similar NVD CVEs for EACH forensics finding.
    The query describes the finding (type, CWE, affected statement) plus CPG
    facts about it (enclosing function, taint source, sanitization).

    Outputs:
        state.forensics_signals[i]["similar_cves"] – top-k CVE dicts for signal i
        state.rag_result   – list of rag_nvd2.FindingRetrieval, one per signal
        state.cve_matches  – union of all per-finding matches (best score kept)
        state.cwe_hints    – CWE IDs of the findings
    """
    name = "RAGQueryAgent"

    def __init__(self, top_k: int = 5, score_threshold: float = 0.3):
        self.top_k           = top_k
        self.score_threshold = score_threshold

    def _finding_context(self, state: PipelineState, signal: dict, paths: list) -> dict:
        """CPG facts about the finding's line, used to phrase the RAG query."""
        try:
            line = int(signal.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        ctx = {}
        if not line:
            return ctx
        fn = next((f for f in state.ast_functions
                   if f["start_line"] + 1 <= line <= f["end_line"] + 1
                   and f["name"] not in ("anonymous", "<global>")), None)
        if fn:
            ctx["function"] = fn["name"]
        path = next((p for p in paths if abs(p["sink_line"] - line) <= 1), None)
        if path:
            ctx["source"]    = path["source"]
            ctx["sanitized"] = bool(path["sanitized_by"] or path["checks"])
        return ctx

    # Background pool for NVD CVSS lookups (network-bound), shared by all files.
    _prefetch_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cvss")

    def _prefetch_cvss(self, state: PipelineState, signals: list):
        """
        Start fetching CVSS vectors for the matched CVEs now, so the NVD round
        trips overlap with the CategorizationAgent's LLM call that needs them.
        """
        similar = [c for s in signals for c in (s.get("similar_cves") or [])]
        ids     = list(dict.fromkeys(c["cve_id"] for c in similar))
        known   = {c["cve_id"]: c["cvss_vector"] for c in similar if c.get("cvss_vector")}
        if not ids or len(known) == len(ids):
            return
        try:
            from cvss_lookup import get_cvss_vectors
            state.cvss_prefetch = self._prefetch_pool.submit(get_cvss_vectors, ids, known)
        except Exception as e:
            self._log(f"CVSS prefetch unavailable ({e})")

    def run(self, state: PipelineState) -> PipelineState:
        signals = [s for s in state.forensics_signals if isinstance(s, dict)]
        if not signals:
            self._log("No forensics findings — nothing to retrieve")
            state.steps_completed.append(self.name)
            return state

        self._log(f"Retrieving top-{self.top_k} similar CVEs for {len(signals)} finding(s)...")
        try:
            from rag_nvd2 import retrieve_for_findings, finding_cwes

            paths = []
            if state.cpg_extractor is not None:
                try:
                    paths = state.cpg_extractor.profiler.taint_paths()
                except Exception as e:
                    self._log(f"Taint paths unavailable for queries ({e})")

            results = retrieve_for_findings(
                signals,
                language        = state.language,
                contexts        = [self._finding_context(state, s, paths) for s in signals],
                top_k           = self.top_k,
                score_threshold = self.score_threshold,
            )
            best = {}
            for signal, res in zip(signals, results):
                signal["similar_cves"] = res.cve_matches
                for c in res.cve_matches:
                    if c["cve_id"] not in best or c["score"] > best[c["cve_id"]]["score"]:
                        best[c["cve_id"]] = c
                self._log(
                    f"{signal.get('vulnerability_type', '?')} ({signal.get('cwe_id', '?')}): "
                    f"{', '.join(c['cve_id'] for c in res.cve_matches) or 'no matches'} "
                    f"[{res.reranker}]"
                )

            state.rag_result  = results
            state.cve_matches = sorted(best.values(), key=lambda c: c["score"], reverse=True)
            self._prefetch_cvss(state, signals)
            state.cwe_hints   = sorted({c for s in signals for c in finding_cwes(s)})

        except ImportError as e:
            self._error(state, f"rag_nvd2 import failed ({e}) — expected at {_RAG_DIR / 'rag_nvd2.py'}")
        except Exception as e:
            self._error(state, f"RAG query failed: {e}")
            state.cve_matches = []

        state.steps_completed.append(self.name)
        return state


# ─── Step 4: Categorization Agent ─────────────────────────

class CategorizationAgent(BaseAgent):
    """
    Combines forensics signals + CVE matches to produce a ranked,
    deduplicated, and normalized list of vulnerability categories with:
      1. STRIDE threat classification (Spoofing, Tampering, Repudiation,
         Information Disclosure, Denial of Service, Elevation of Privilege)
      2. MITRE ATLAS technique mapping for applicable AI/ML threats
      3. Preserved CWE IDs and verified related CVEs
      4. Supporting code evidence and severity ranking

    Outputs:
        state.ranked_findings – list of {category, severity, cwe_ids,
                                         evidence, related_cves,
                                         stride, mitre_atlas}
    """
    name = "CategorizationAgent"

    # Authoritative STRIDE threat categories
    VALID_STRIDE = {
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege",
    }

    # Authoritative MITRE ATLAS verified techniques for AI/ML security
    VERIFIED_ATLAS = {
        "AML.T0000": "ML Model Inversion",
        "AML.T0001": "Data Extraction / Reconstruction",
        "AML.T0010": "ML Model Backdooring",
        "AML.T0015": "Evade ML Model",
        "AML.T0018": "Backdoor ML Model via Dependency / Supply Chain",
        "AML.T0020": "Poison Training Data",
        "AML.T0024": "Exfiltration via ML Inference API",
        "AML.T0025": "Insecure Output Handling",
        "AML.T0031": "LLM Hallucination Exploitation",
        "AML.T0035": "ML Artifact Extraction",
        "AML.T0040": "ML Intellectual Property Theft",
        "AML.T0043": "Craft Adversarial Data",
        "AML.T0047": "ML Model Denial of Service",
        "AML.T0051": "LLM Prompt Injection",
        "AML.T0054": "LLM Jailbreak",
    }

    # AI/ML keywords to detect if finding operates in an AI/ML context
    AI_ML_KEYWORDS = (
        "prompt", "llm", "langchain", "openai", "ollama", "transformer",
        "model", "weights", "pytorch", "torch", "tensorflow", "keras",
        "onnx", "huggingface", "embedding", "vector", "inference",
        "fine-tune", "finetune", "dataset", "agentic", "jailbreak"
    )

    def _infer_stride(self, category: str, cwe_ids: list, evidence: str) -> list:
        """Infer applicable STRIDE categories based on threat scenario & impact."""
        text = f"{category} {' '.join(cwe_ids)} {evidence}".lower()
        cats = set()

        # Elevation of Privilege
        if any(k in text for k in ("overflow", "cwe-120", "cwe-121", "cwe-787", "command injection", "cwe-78", "deserialization", "cwe-502", "exec", "system(", "privilege", "rce", "cwe-287", "cwe-306")):
            cats.add("Elevation of Privilege")

        # Tampering
        if any(k in text for k in ("overflow", "cwe-120", "cwe-787", "memory corruption", "sql", "cwe-89", "tamper", "injection", "cwe-78", "deserialization", "cwe-502", "format string", "cwe-134", "uaf", "use-after-free", "cwe-416", "cwe-415", "xss", "cwe-79", "csrf", "cwe-352", "prompt injection", "aml.t0051", "poison", "aml.t0020")):
            cats.add("Tampering")

        # Information Disclosure
        if any(k in text for k in ("leak", "disclosure", "path traversal", "cwe-22", "sql", "cwe-89", "read", "secret", "hardcoded", "cwe-798", "cwe-312", "use-after-free", "cwe-416", "uninitialized", "cwe-457", "inversion", "aml.t0000", "exfiltration", "aml.t0024")):
            cats.add("Information Disclosure")

        # Denial of Service
        if any(k in text for k in ("dos", "denial of service", "null pointer", "cwe-476", "null dereference", "infinite loop", "cwe-835", "exhaustion", "cwe-400", "buffer overflow", "double free", "cwe-415", "resource", "crash", "aml.t0047")):
            cats.add("Denial of Service")

        # Spoofing
        if any(k in text for k in ("spoof", "authentication", "cwe-287", "cwe-306", "credential", "impersonat", "cwe-798", "csrf", "cwe-352")):
            cats.add("Spoofing")

        # Repudiation
        if any(k in text for k in ("repudiation", "audit", "logging", "cwe-778", "log forging")):
            cats.add("Repudiation")

        res = [c for c in ("Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege") if c in cats]
        return res if res else ["Not applicable"]

    def _infer_atlas(self, category: str, cwe_ids: list, evidence: str, code_snippet: str = "") -> list:
        """Map finding to verified MITRE ATLAS technique if in AI/ML threat context; otherwise return Not applicable."""
        combined = f"{category} {' '.join(cwe_ids)} {evidence} {code_snippet}".lower()

        is_ai_context = any(kw in combined for kw in self.AI_ML_KEYWORDS)
        if not is_ai_context:
            return ["Not applicable"]

        atlas_matches = set()

        if any(k in combined for k in ("prompt injection", "system prompt", "indirect prompt", "cwe-1426")):
            atlas_matches.add("AML.T0051: LLM Prompt Injection")
        if any(k in combined for k in ("jailbreak", "adversarial prompt", "dan prompt", "guardrail bypass")):
            atlas_matches.add("AML.T0054: LLM Jailbreak")
        if any(k in combined for k in ("insecure output", "llm output", "output handling", "generated code execution")):
            atlas_matches.add("AML.T0025: Insecure Output Handling")
        if any(k in combined for k in ("pickle.load", "torch.load", "model weights", "deserialization", "cwe-502")) and any(k in combined for k in ("model", "weights", "checkpoint", "torch", "keras")):
            atlas_matches.add("AML.T0010: ML Model Backdooring")
        if any(k in combined for k in ("poison", "training data", "label flip", "backdoor data")):
            atlas_matches.add("AML.T0020: Poison Training Data")
        if any(k in combined for k in ("model inversion", "reconstruct data", "membership inference")):
            atlas_matches.add("AML.T0000: ML Model Inversion")
        if any(k in combined for k in ("exfiltration", "extract embeddings", "inference query abuse")):
            atlas_matches.add("AML.T0024: Exfiltration via ML Inference API")
        if any(k in combined for k in ("adversarial perturbation", "adversarial example", "craft adversarial")):
            atlas_matches.add("AML.T0043: Craft Adversarial Data")
        if any(k in combined for k in ("sponge example", "energy latency attack", "model dos")):
            atlas_matches.add("AML.T0047: ML Model Denial of Service")

        return sorted(list(atlas_matches)) if atlas_matches else ["Not applicable"]

    def _normalize_and_deduplicate(self, raw_findings: list, cve_matches: list, code: str = "") -> list:
        """
        Normalizes findings, validates STRIDE & MITRE ATLAS, validates CWE vs CVE distinction,
        merges duplicate categories, and sorts by severity.
        """
        valid_matched_cve_ids = {
            c.get("cve_id").upper() for c in cve_matches
            if c.get("cve_id") and c.get("cve_id").upper().startswith("CVE-")
        }

        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        merged_map = {}

        for item in raw_findings:
            if not isinstance(item, dict):
                continue

            cat = str(item.get("category") or "Unknown Vulnerability").strip()
            cat_key = cat.lower()

            # Severity normalization
            sev = str(item.get("severity") or "MEDIUM").upper().strip()
            if sev not in severity_rank:
                sev = "MEDIUM"

            # CWE normalization
            raw_cwes = item.get("cwe_ids") or []
            if isinstance(raw_cwes, str):
                raw_cwes = [raw_cwes]
            cwe_list = []
            for c in raw_cwes:
                c_str = str(c).strip().upper()
                if not c_str:
                    continue
                if not c_str.startswith("CWE-") and c_str.isdigit():
                    c_str = f"CWE-{c_str}"
                if c_str.startswith("CWE-"):
                    cwe_list.append(c_str)

            # CVE normalization & strict CWE/CVE separation
            raw_cves = item.get("related_cves") or []
            if isinstance(raw_cves, str):
                raw_cves = [raw_cves]
            cve_list = []
            for c in raw_cves:
                c_str = str(c).strip().upper()
                if c_str.startswith("CWE-"):
                    # Move misplaced CWE to cwe_list
                    if c_str not in cwe_list:
                        cwe_list.append(c_str)
                    continue
                if c_str.startswith("CVE-") and (not valid_matched_cve_ids or c_str in valid_matched_cve_ids):
                    cve_list.append(c_str)

            # If no related CVEs were provided by LLM, correlate from verified matched CVEs
            if not cve_list and valid_matched_cve_ids:
                for cve in cve_matches:
                    cve_cwes = [cw.upper() for cw in cve.get("cwe_ids", [])]
                    if any(cw in cwe_list for cw in cve_cwes):
                        cve_list.append(cve["cve_id"].upper())

            evidence = str(item.get("evidence") or "").strip()

            # STRIDE normalization
            raw_stride = item.get("stride") or []
            if isinstance(raw_stride, str):
                raw_stride = [raw_stride]
            stride_filtered = [
                s.strip() for s in raw_stride
                if s.strip() in self.VALID_STRIDE
            ]
            if not stride_filtered:
                stride_filtered = self._infer_stride(cat, cwe_list, evidence)

            # MITRE ATLAS normalization
            raw_atlas = item.get("mitre_atlas") or []
            if isinstance(raw_atlas, str):
                raw_atlas = [raw_atlas]
            atlas_filtered = []
            for a in raw_atlas:
                a_str = str(a).strip()
                if a_str in ("Not applicable", "None", "N/A", ""):
                    continue
                # Check if matches verified technique
                for tid, tname in self.VERIFIED_ATLAS.items():
                    if tid in a_str.upper():
                        atlas_filtered.append(f"{tid}: {tname}")
                        break
            if not atlas_filtered:
                atlas_filtered = self._infer_atlas(cat, cwe_list, evidence, code)

            # LLM risk dimensions (1-5); missing or invalid -> None (resolved in _apply_risk)
            dims = {d: _dimension_score(item.get(d), default=None) for d in RISK_DIMENSIONS}

            # Deduplication / Merging into merged_map
            if cat_key not in merged_map:
                merged_map[cat_key] = {
                    "category": cat,
                    "severity": sev,
                    "cwe_ids": list(dict.fromkeys(cwe_list)),
                    "evidence": evidence,
                    "related_cves": list(dict.fromkeys(cve_list)),
                    "stride": list(dict.fromkeys(stride_filtered)),
                    "mitre_atlas": list(dict.fromkeys(atlas_filtered)),
                    **dims,
                }
            else:
                existing = merged_map[cat_key]
                # Upgrade severity if higher
                if severity_rank[sev] > severity_rank[existing["severity"]]:
                    existing["severity"] = sev
                # Keep the worse (higher) score per risk dimension
                for d in RISK_DIMENSIONS:
                    scores = [s for s in (existing[d], dims[d]) if s is not None]
                    existing[d] = max(scores) if scores else None
                # Merge lists
                existing["cwe_ids"] = list(dict.fromkeys(existing["cwe_ids"] + cwe_list))
                existing["related_cves"] = list(dict.fromkeys(existing["related_cves"] + cve_list))
                existing["stride"] = list(dict.fromkeys(existing["stride"] + stride_filtered))
                existing["mitre_atlas"] = list(dict.fromkeys(existing["mitre_atlas"] + atlas_filtered))
                if evidence and evidence not in existing["evidence"]:
                    existing["evidence"] += f" | {evidence}"

        # Sort ranked findings by severity descending
        ranked = sorted(
            list(merged_map.values()),
            key=lambda x: severity_rank.get(x["severity"], 0),
            reverse=True,
        )
        return ranked

    # Matched CVEs per finding whose CVSS vectors feed the risk baselines.
    CVSS_EVIDENCE_CVES = 5

    def _cvss_ids(self, finding: dict, linked: list) -> tuple:
        """(CVE ids whose CVSS vectors feed this finding's risk, vectors already known)."""
        similar = [c for s in linked for c in (s.get("similar_cves") or [])]
        similar.sort(key=lambda c: c.get("score", 0), reverse=True)
        ids   = list(dict.fromkeys(c["cve_id"] for c in similar))[:self.CVSS_EVIDENCE_CVES]
        ids  += [c for c in finding.get("related_cves", []) if c not in ids][:2]
        known = {c["cve_id"]: c["cvss_vector"] for c in similar if c.get("cvss_vector")}
        return ids, known

    def _lookup_cvss(self, state: PipelineState, ids: list, known: dict) -> dict:
        """One batched (parallel, cached) lookup for every finding's CVEs."""
        if state.cvss_prefetch is not None:
            try:
                known = {**known, **state.cvss_prefetch.result(timeout=60)}
            except Exception as e:
                self._log(f"CVSS prefetch failed ({str(e)[:120]})")
        if not ids or all(c in known for c in ids):
            return known
        try:
            from cvss_lookup import get_cvss_vectors
            return get_cvss_vectors(ids, known)
        except Exception as e:
            self._log(f"CVSS lookup unavailable ({str(e)[:120]}) — no CVE evidence for risk")
            return known

    def _apply_risk(self, state: PipelineState, findings: list) -> list:
        """
        Scores each finding's six dimensions from evidence, lets the LLM's
        score shift CWE/CVSS baselines by at most ±1 (CPG baselines are fixed), then attaches
        calculate_risk_score() output. Records a summary in state.risk_scores
        and returns findings sorted by risk_score (descending).

        Per finding:
          llm_dimensions – the LLM's raw scores (None where it gave none)
          risk_evidence  – {dim: {score, source, basis, llm, final}}
        """
        from risk_evidence import evidence_baselines, blend, linked_signals

        profiler = getattr(state.cpg_extractor, "profiler", None)
        per_finding, all_ids, known = [], [], {}
        for f in findings:
            ids, kn = self._cvss_ids(f, linked_signals(f, state.forensics_signals))
            per_finding.append(ids)
            all_ids += ids
            known.update(kn)
        vectors = self._lookup_cvss(state, list(dict.fromkeys(all_ids)), known)

        for f, ids in zip(findings, per_finding):
            baselines = evidence_baselines(f, state.forensics_signals, profiler,
                                           [vectors[c] for c in ids if c in vectors])
            llm       = {d: f.get(d) for d in RISK_DIMENSIONS}
            evidence  = {}
            for d in RISK_DIMENSIONS:
                final, _ = blend(baselines.get(d), llm[d])
                f[d] = final
                evidence[d] = {**(baselines.get(d) or {"score": None, "source": "llm",
                                                       "basis": "no evidence — LLM score"}),
                               "llm": llm[d], "final": final}
            f["llm_dimensions"] = llm
            f["risk_evidence"]  = evidence
            f.update(calculate_risk_score(**{d: f[d] for d in RISK_DIMENSIONS}))
        findings.sort(key=lambda f: f["risk_score"], reverse=True)
        state.risk_scores = [
            {"category": f["category"],
             **{k: f[k] for k in ("risk_score", "risk_level", "likelihood", "impact",
                                  *RISK_DIMENSIONS, "risk_evidence")}}
            for f in findings
        ]
        return findings

    def run(self, state: PipelineState) -> PipelineState:
        self._log("Categorizing and ranking findings (with STRIDE & MITRE ATLAS)...")

        if not state.cve_matches and not state.forensics_signals:
            self._log("No findings to categorize")
            state.ranked_findings = []
            state.steps_completed.append(self.name)
            return state

        signals = state.forensics_signals[:10]
        forensics_str = (
            json.dumps([{k: v for k, v in s.items() if k != "similar_cves"} for s in signals], indent=2)
            if signals
            else "None"
        )

        # Each finding's own top-k similar CVEs from the RAG step.
        cve_blocks = []
        for i, s in enumerate(signals, 1):
            similar = s.get("similar_cves") or []
            if not similar:
                continue
            cve_blocks.append(f"Finding {i} ({s.get('vulnerability_type', '?')}, {s.get('cwe_id', '?')}):")
            cve_blocks.extend(
                f"  - [{c['cve_id']}] [{c['severity']}] "
                f"CWEs: {', '.join(c['cwe_ids'])} — "
                f"{c['description'][:150]}"
                for c in similar
            )
        cve_str = "\n".join(cve_blocks) or "None"

        prompt = f"""You are a senior cybersecurity expert. Analyze these findings from static analysis and threat intelligence:

Forensic signals detected in the code:
{forensics_str}

Most similar CVEs from the NVD threat database, per finding:
{cve_str}

Produce a ranked, deduplicated list of vulnerability categories present in this code.
Rank from most to least severe.

For each category provide:
- category:     vulnerability category name (e.g. "Buffer Overflow", "SQL Injection", "Prompt Injection")
- severity:     CRITICAL | HIGH | MEDIUM | LOW
- cwe_ids:      list of relevant CWE IDs (e.g. ["CWE-120", "CWE-787"])
- evidence:     what specific code pattern supports this finding
- related_cves: list of relevant CVE IDs from the matches (do NOT put CWEs here)
- stride:       list of applicable STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), or ["Not applicable"] if none apply
- mitre_atlas:  list of applicable MITRE ATLAS techniques (e.g. ["AML.T0051: LLM Prompt Injection"]) ONLY if this finding involves an AI/ML system or model threat; otherwise ["Not applicable"]

Also score each category on these six risk dimensions, each an integer from 1 to 5, using exactly these criteria:

exploitability:
  1 = Requires physical access or extremely complex multi-step exploitation
  2 = Requires authenticated access + specific non-default configuration
  3 = Requires authenticated access OR specific configuration (not both)
  4 = Remotely exploitable, low complexity, requires some user interaction
  5 = Remotely exploitable, no auth, no user interaction, public exploit exists

exposure:
  1 = Internal only, isolated network, not reachable from outside
  2 = Internal network, limited access, behind multiple security layers
  3 = Internal but accessible to many users, or internet-facing with auth
  4 = Internet-facing with minimal auth, or exposed API endpoint
  5 = Fully public-facing, no auth required, directly reachable

attack_prerequisites:
  1 = Requires deep system knowledge, specific timing, or vulnerability chaining
  2 = Requires knowledge of internal code structure or specific environment
  3 = Requires some target knowledge but achievable with reconnaissance
  4 = Minimal prerequisites, standard tools sufficient
  5 = No prerequisites, trivial to exploit with public tools or PoC

confidentiality:
  1 = No data exposure
  2 = Minimal exposure of non-sensitive metadata or configuration
  3 = Partial exposure of user data or non-critical records
  4 = Significant exposure of PII, credentials, or financial data
  5 = Complete exposure of all data, credentials, or encryption keys

integrity:
  1 = No data modification possible
  2 = Minor modification, limited scope, easily detectable
  3 = Partial modification of some records, may go undetected
  4 = Significant modification of critical records, difficult to detect
  5 = Complete compromise, arbitrary write, or full code execution

availability:
  1 = No availability impact
  2 = Minor degradation, negligible impact
  3 = Partial disruption of specific functionality, recoverable
  4 = Significant disruption for many users, requires manual recovery
  5 = Complete denial of service, data loss, requires full rebuild

Respond ONLY with a JSON array:
[
  {{
    "category":             "Buffer Overflow",
    "severity":             "CRITICAL",
    "cwe_ids":              ["CWE-120", "CWE-787"],
    "evidence":             "strcpy called with unsanitized user input into fixed buffer",
    "related_cves":         ["CVE-2026-6691"],
    "stride":               ["Tampering", "Elevation of Privilege", "Denial of Service"],
    "mitre_atlas":          ["Not applicable"],
    "exploitability":       <1-5>,
    "exposure":             <1-5>,
    "attack_prerequisites": <1-5>,
    "confidentiality":      <1-5>,
    "integrity":            <1-5>,
    "availability":         <1-5>
  }}
]

Score every dimension independently for each category from the code and evidence; do not reuse the same numbers across different categories unless the criteria really match."""

        try:
            raw    = self._llm(prompt, CATEGORIZE_MODEL,
                            schema=self._bounded_schema(CATEGORIZE_ITEM_SCHEMA, max_items=10))
            parsed = self._parse_json_array(raw)

            if parsed is not None and len(parsed) > 0:
                normalized = self._normalize_and_deduplicate(parsed, state.cve_matches, state.code)
                state.ranked_findings = normalized
                self._log(f"Categorized into {len(normalized)} finding groups (with STRIDE & ATLAS mapping)")
            else:
                # Fallback: construct from forensic signals
                fallback_items = []
                for s in state.forensics_signals:
                    fallback_items.append({
                        "category": str(s.get("vulnerability_type", "Security Finding")).title(),
                        "severity": str(s.get("confidence", "MEDIUM")),
                        "cwe_ids": [s.get("cwe_id")] if s.get("cwe_id") else [],
                        "evidence": str(s.get("affected_code", "")),
                        "related_cves": [],
                        "stride": [],
                        "mitre_atlas": [],
                    })
                normalized = self._normalize_and_deduplicate(fallback_items, state.cve_matches, state.code)
                state.ranked_findings = normalized
                self._log(f"Categorized {len(normalized)} findings via deterministic fallback")

        except Exception as e:
            self._error(state, f"Categorization LLM failed: {e} — using heuristic fallback")
            fallback_items = []
            for s in state.forensics_signals:
                fallback_items.append({
                    "category": str(s.get("vulnerability_type", "Security Finding")).title(),
                    "severity": str(s.get("confidence", "MEDIUM")),
                    "cwe_ids": [s.get("cwe_id")] if s.get("cwe_id") else [],
                    "evidence": str(s.get("affected_code", "")),
                    "related_cves": [],
                    "stride": [],
                    "mitre_atlas": [],
                })
            state.ranked_findings = self._normalize_and_deduplicate(fallback_items, state.cve_matches, state.code)

        # Risk formula on every path (fallback findings have no LLM scores -> all 3s).
        state.ranked_findings = self._apply_risk(state, state.ranked_findings)
        if state.ranked_findings:
            top = state.ranked_findings[0]
            self._log(f"Ranked by risk score — top: {top['category']} "
                      f"{top['risk_score']}/25 ({top['risk_level']})")

        state.steps_completed.append(self.name)
        return state



# ─── Step 5: Validation Agent ──────────────────────────────

class ValidationAgent(BaseAgent):
    """
    Independently verifies each finding — filters out false positives
    and confirms which vulnerabilities are genuinely exploitable.

    Uses the finetuned 'validation-agent' model if available,
    falls back to llama3.2 if not.

    Outputs:
        state.validated_findings – confirmed exploitable vulnerabilities
        state.false_positives    – findings ruled out as false positives
        state.is_clean           – True if no findings confirmed
    """
    name = "ValidationAgent"

    def _get_model(self) -> str:
        """Use finetuned model if available, fall back to llama3.2."""
        try:
            # ollama-python >= 0.4 lists models under "model" (older: "name").
            models = [getattr(m, "model", None) or m.get("name", "") for m in ollama.list()["models"]]
            if any("validation-agent" in m for m in models):
                return VALIDATION_MODEL
            self._log(
                f"'{VALIDATION_MODEL}' not found in Ollama — "
                f"falling back to llama3.2"
            )
            return "llama3.2"
        except Exception:
            return "llama3.2"

    # Training truncated code at 1200 chars (build_dataset.MAX_CODE_LENGTH).
    # The finetuned model never saw more than that, so match it here.
    FT_CODE_LIMIT = 1200

    def _finetuned_prompt(self, code: str, finding: dict) -> str:
        """
        Exact prompt format from build_dataset.make_example(). The finetuned
        model was trained one-finding-at-a-time on this template — feeding it
        the batch prompt below instead puts it off-distribution and it will
        emit a single object where an array is expected.
        """
        return f"""You are a senior security engineer performing validation review.

Code:
```
{code}
```

Finding to validate:
{json.dumps(finding, indent=2)}

Determine if this finding is:
- CONFIRMED: genuinely present and exploitable in this specific code
- FALSE_POSITIVE: pattern matched but not actually exploitable in context
- NEEDS_CONTEXT: might be vulnerable but requires more context to confirm

Respond with a JSON object:
{{"verdict": "CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT", "reasoning": "one sentence"}}"""

    def _llm_raw(self, prompt: str, model: str) -> str:
        """
        Raw completion using the Alpaca training format.

        Ollama otherwise applies the Llama-3.2 chat template embedded in the
        GGUF, which prepends a "Cutting Knowledge Date" system header the
        finetuned model never saw. That pushes it off-distribution and it
        answers in prose instead of the JSON verdict.
        """
        response = with_retry(
            ollama.generate,
            model   = model,
            prompt  = "### Instruction:\n" + prompt + "\n\n### Response:\n",
            raw     = True,
            options = {"temperature": 0},
        )
        return response["response"].strip()

    def _validate_finetuned(self, state: PipelineState, model: str) -> list:
        """One call per finding, matching the finetuning format."""
        code     = state.code[:self.FT_CODE_LIMIT]
        verdicts = []

        for finding in state.ranked_findings:
            try:
                raw    = self._llm_raw(self._finetuned_prompt(code, finding), model)
                parsed = self._parse_json_object(raw)
            except Exception as e:
                self._log(f"Validation call failed for one finding: {e}")
                parsed = None

            if parsed is None:
                # Unparseable — keep the finding rather than silently dropping it.
                self._log("Could not parse verdict — defaulting to NEEDS_CONTEXT")
                parsed = {"verdict": "NEEDS_CONTEXT",
                          "reasoning": "validator response could not be parsed"}

            merged = dict(finding)
            merged["verdict"]   = str(parsed.get("verdict", "NEEDS_CONTEXT")).upper()
            merged["reasoning"] = parsed.get("reasoning", "")
            verdicts.append(merged)

        return verdicts

    # ── CPG-grounded validation with context re-extraction ──
    # Char budget per round: round 0 matches the finetuned model's training
    # window; later rounds only happen when the model said NEEDS_CONTEXT.
    CONTEXT_BUDGETS    = (1200, 2400, 4000)
    MAX_CONTEXT_ROUNDS = 2

    # Deterministic escalation used when the model's own request is empty
    # or adds nothing new.
    CONTEXT_LADDER = (
        {"facets": ["data_flow", "guards", "taint", "sanitizers"], "symbols": []},
        {"facets": ["callers", "callees", "boundaries", "resources", "sensitive",
                    "declarations", "full_function"], "symbols": []},
    )

    VERDICT_SCHEMA = {
        "type": "object",
        "properties": {
            "verdict":   {"type": "string", "enum": ["CONFIRMED", "FALSE_POSITIVE", "NEEDS_CONTEXT"]},
            "reasoning": {"type": "string"},
        },
        "required": ["verdict", "reasoning"],
    }

    CONTEXT_REQUEST_SCHEMA = {
        "type": "object",
        "properties": {
            "facets":  {"type": "array", "maxItems": len(FACETS),
                        "items": {"type": "string", "enum": list(FACETS)}},
            "symbols": {"type": "array", "maxItems": 5, "items": {"type": "string"}},
        },
        "required": ["facets", "symbols"],
    }

    def _judge(self, ctx, finding: dict, model: str, finetuned: bool, first_round: bool) -> dict:
        # Round 0 feeds only the code slice (same shape as training data);
        # later rounds add the structural facts the model asked for.
        code   = ctx.render(with_facts=not first_round)
        prompt = self._finetuned_prompt(code, finding)
        try:
            if finetuned:
                parsed = self._parse_json_object(self._llm_raw(prompt, model))
            else:
                parsed = self._parse_json_object(
                    self._llm(prompt, model, schema=self.VERDICT_SCHEMA))
        except Exception as e:
            self._log(f"Validation call failed for one finding: {e}")
            parsed = None
        if parsed is None:
            return {"verdict": "NEEDS_CONTEXT",
                    "reasoning": "validator response could not be parsed"}
        parsed["verdict"] = str(parsed.get("verdict", "NEEDS_CONTEXT")).upper()
        return parsed

    @staticmethod
    def _symbols_in_code(symbols: list, code: str) -> list:
        """
        Keep only identifiers that occur in the file. The model otherwise asks
        for names it read in the matched CVEs' descriptions (product names,
        'ScadaBR_version_1.2.0', ...), which cannot be found and waste a round.
        """
        keywords = {"pub", "def", "int", "char", "void", "const", "let", "var", "return", "self",
                    "this", "class", "struct", "function", "import", "from", "static", "public",
                    "private", "String", "None", "null", "true", "false", "async", "await"}
        idents = set(re.findall(r"[A-Za-z_]\w*", code)) - keywords
        out = []
        for sym in symbols:
            for tok in re.findall(r"[A-Za-z_]\w*", str(sym)):
                if len(tok) > 2 and tok in idents and tok not in out:
                    out.append(tok)
        return out[:5]

    def _request_context(self, finding: dict, reasoning: str, round_idx: int,
                         have: "ContextRequest", code: str = "") -> "ContextRequest":
        """Ask a general model *what* extra CPG context would settle the verdict."""
        menu = (
            "- data_flow: full backward/forward data-dependence slice of the flagged statement\n"
            "- guards: every branch/loop that checks variables involved (bounds/null/auth checks)\n"
            "- callers: call sites of this function (shows what arguments arrive)\n"
            "- callees: bodies of in-file functions called by the flagged code\n"
            "- declarations: file-level #defines, typedefs, structs, globals\n"
            "- full_function: the entire enclosing function\n"
            "- taint: source -> sink paths reaching the flagged code, incl. across functions/files\n"
            "- sanitizers: sanitizers and validation checks in the enclosing function\n"
            "- resources: memory/resource issues (use after free, double free, leaks, unchecked alloc)\n"
            "- boundaries: whether an entry point (HTTP route, main, CLI) reaches this function\n"
            "- sensitive: crypto / credential / privileged API use in the function"
        )
        prompt = f"""A security reviewer could not decide on this finding.

Finding:
{json.dumps({k: finding.get(k) for k in ("category", "cwe_ids", "evidence")}, indent=2)}

Reviewer's reasoning: {reasoning}

Which extra code-property-graph context would let them decide? Choose from:
{menu}

Also list up to 5 variable/function names whose every use should be shown (symbols).
Respond with JSON: {{"facets": [...], "symbols": [...]}}"""
        wanted = ContextRequest()
        try:
            parsed = self._parse_json_object(
                self._llm(prompt, "llama3.2", schema=self.CONTEXT_REQUEST_SCHEMA))
            if parsed:
                wanted = ContextRequest(
                    facets  = [f for f in parsed.get("facets", []) if f in FACETS],
                    symbols = self._symbols_in_code([s for s in parsed.get("symbols", []) if s], code),
                )
        except Exception as e:
            self._log(f"Context request failed ({e}) — using escalation ladder")

        merged = have.merge(wanted)
        if merged.facets == have.facets and merged.symbols == have.symbols:
            step   = self.CONTEXT_LADDER[min(round_idx, len(self.CONTEXT_LADDER) - 1)]
            merged = have.merge(ContextRequest(**step))
        return merged

    def _validate_with_context(self, state: PipelineState, model: str) -> list:
        """
        One call per finding. The code the model sees is a CPG slice, not the
        whole file. On NEEDS_CONTEXT the validator's request is turned into
        a bigger ContextRequest and the slice is re-extracted from the CPG
        (no Joern re-run) and the finding re-judged, up to MAX_CONTEXT_ROUNDS.
        """
        extractor = state.cpg_extractor
        finetuned = (model == VALIDATION_MODEL)

        def validate_one(finding: dict) -> dict:
            request, history, prev_view, ctx = ContextRequest(), [], None, None
            result = {"verdict": "NEEDS_CONTEXT", "reasoning": ""}

            for rnd in range(self.MAX_CONTEXT_ROUNDS + 1):
                ctx  = extractor.extract(finding, request, max_chars=self.CONTEXT_BUDGETS[rnd])
                view = (ctx.code, ctx.facts)
                if view == prev_view:
                    # The model's request added nothing; try the fixed ladder
                    # before giving up.
                    step    = self.CONTEXT_LADDER[min(rnd - 1, len(self.CONTEXT_LADDER) - 1)]
                    request = request.merge(ContextRequest(**step))
                    ctx     = extractor.extract(finding, request, max_chars=self.CONTEXT_BUDGETS[rnd])
                    view    = (ctx.code, ctx.facts)
                if view == prev_view:
                    self._log("Re-extraction added nothing new — stopping")
                    break
                prev_view = view

                result = self._judge(ctx, finding, model, finetuned, first_round=(rnd == 0))
                history.append({
                    "round":   rnd,
                    "facets":  list(request.facets),
                    "symbols": list(request.symbols),
                    "lines":   len(ctx.code.splitlines()),
                    "source":  ctx.source,
                    "verdict": result["verdict"],
                })
                if result["verdict"] != "NEEDS_CONTEXT" or rnd == self.MAX_CONTEXT_ROUNDS:
                    break

                request = self._request_context(
                    finding, result.get("reasoning", ""), rnd, request, state.code)
                self._log(
                    f"NEEDS_CONTEXT for '{finding.get('category')}' — re-extracting "
                    f"{request.facets} {request.symbols}"
                )

            merged = dict(finding)
            merged["verdict"]        = result["verdict"]
            merged["reasoning"]      = result.get("reasoning", "")
            merged["context_rounds"] = history

            # Guardrails: fixed taxonomy + evidence-based score decide the
            # final verdict; the LLM's verdict is one of the parameters.
            try:
                g = assess(finding, state.code, extractor.profiler,
                           list(ctx.anchors) if ctx is not None else [],
                           linked_signals(finding, state.forensics_signals),
                           result["verdict"], result.get("reasoning", ""))
                merged["llm_verdict"]     = result["verdict"]
                merged["verdict"]         = g["verdict"]
                merged["threat_category"] = g["threat_category"]
                merged["validation"]      = g
                if g["verdict"] != result["verdict"]:
                    merged["reasoning"] = (f"{merged['reasoning']} [guardrail: {g['rule']}; "
                                           f"validator said {result['verdict']}]").strip()
            except Exception as e:
                # Without the evidence check the LLM alone may not confirm.
                if merged["verdict"] == "CONFIRMED":
                    merged["verdict"] = "NEEDS_CONTEXT"
                self._log(f"Guardrails failed for '{finding.get('category')}' ({e}) — "
                          f"LLM verdict kept, but not as CONFIRMED")
            # What was extracted last; the forensics feedback round re-extracts it.
            merged["context_request"] = request.to_dict()
            return merged

        # Findings are independent; judge them concurrently (Ollama serves
        # parallel requests, so the rounds of different findings overlap).
        if len(state.ranked_findings) <= 1:
            return [validate_one(f) for f in state.ranked_findings]
        with ThreadPoolExecutor(max_workers=min(LLM_CONCURRENCY, len(state.ranked_findings))) as pool:
            return list(pool.map(validate_one, state.ranked_findings))

    def _validate_batch(self, state: PipelineState, model: str):
        """Single batched call — used for the generic llama3.2 fallback."""
        findings_str = json.dumps(state.ranked_findings, indent=2)

        prompt = f"""You are a senior security engineer performing a second-opinion review.

Code being reviewed:
```
{state.code[:1000]}
```

Findings to validate:
{findings_str}

For each finding determine if it is:
- CONFIRMED:      genuinely present and exploitable in this specific code
- FALSE_POSITIVE: pattern matched but not actually exploitable in context
- NEEDS_CONTEXT:  might be vulnerable but requires more context to confirm

Respond ONLY with a JSON array, one object per finding:
[
  {{
    "category":  "Buffer Overflow",
    "verdict":   "CONFIRMED",
    "reasoning": "strcpy with external input into fixed-size stack buffer is directly exploitable",
    "severity":  "CRITICAL"
  }}
]"""

        raw = self._llm(prompt, model,
                        schema=self._bounded_schema(VALIDATION_ITEM_SCHEMA,
                                                    count=len(state.ranked_findings)))
        return self._parse_json_array(raw)

    @staticmethod
    def _mark_unverified(state: PipelineState, why: str):
        state.validated_findings     = []
        state.needs_context_findings = [
            {**f, "verdict": "NEEDS_CONTEXT",
             "reasoning": f"{f.get('reasoning', '')} [not verified: {why}]".strip()}
            for f in state.ranked_findings
        ]
        state.is_clean = False

    def run(self, state: PipelineState) -> PipelineState:
        self._log("Validating findings...")

        if not state.ranked_findings:
            self._log("No findings to validate — marking as clean")
            state.is_clean           = True
            state.validated_findings = []
            state.steps_completed.append(self.name)
            return state

        model = self._get_model()

        try:
            if state.cpg_extractor is not None:
                parsed = self._validate_with_context(state, model)
            elif model == VALIDATION_MODEL:
                parsed = self._validate_finetuned(state, model)
            else:
                parsed = self._validate_batch(state, model)

            if parsed is not None:
                for v in parsed:
                    reason = memory_safety_gate(v, state.language, state.code)
                    if reason and v.get("verdict") != "FALSE_POSITIVE":
                        v["llm_verdict"] = v.get("llm_verdict", v.get("verdict"))
                        v["verdict"]     = "FALSE_POSITIVE"
                        v["reasoning"]   = f"{v.get('reasoning', '')} [guardrail: {reason}]".strip()
                        if isinstance(v.get("validation"), dict):
                            v["validation"].update(verdict="FALSE_POSITIVE", rule=reason)
                state.validated_findings = [
                    v for v in parsed
                    if v.get("verdict") == "CONFIRMED"
                ]
                state.false_positives = [
                    v for v in parsed
                    if v.get("verdict") == "FALSE_POSITIVE"
                ]
                # Undecided findings are kept (not dropped as if clean); the
                # orchestrator sends them back to the ForensicsAgent.
                state.needs_context_findings = [
                    v for v in parsed
                    if v.get("verdict") not in ("CONFIRMED", "FALSE_POSITIVE")
                ]
                state.is_clean = not state.validated_findings and not state.needs_context_findings
                self._log(
                    f"Confirmed: {len(state.validated_findings)}, "
                    f"False positives: {len(state.false_positives)}, "
                    f"Needs context: "
                    f"{len(parsed) - len(state.validated_findings) - len(state.false_positives)}"
                )
            else:
                # Parse failed — nothing was verified, so nothing is confirmed;
                # the findings are reported as unresolved for manual review.
                self._log("Could not parse validation response — marking all unresolved")
                self._mark_unverified(state, "validation response could not be parsed")

        except Exception as e:
            self._error(state, f"Validation failed: {e}")
            self._mark_unverified(state, f"validation failed: {e}")

        state.steps_completed.append(self.name)
        return state


# ─── Step 6: Explainable AI Agent ─────────────────────────

class ExplainableAIAgent(BaseAgent):
    """
    Generates developer-friendly explanations for each confirmed
    vulnerability — explains root cause and concrete attack scenario.

    Outputs:
        state.explanations – list of {category, what_is_wrong,
                                      why_dangerous, attack_scenario,
                                      cwe_explanation}
    """
    name = "ExplainableAIAgent"

    def run(self, state: PipelineState) -> PipelineState:
        if state.is_clean or not state.validated_findings:
            self._log("Code is clean — no explanations needed")
            state.steps_completed.append(self.name)
            return state

        self._log(
            f"Generating explanations for "
            f"{len(state.validated_findings)} findings..."
        )

        findings_str = json.dumps(state.validated_findings, indent=2)

        cve_context = "\n".join([
            f"- [{c['cve_id']}] {c['description'][:200]}"
            for c in state.cve_matches[:5]
        ]) if state.cve_matches else "No CVE context available"

        prompt = f"""You are a security educator explaining vulnerabilities to a developer.

Code:
```
{state.code[:1000]}
```

Confirmed vulnerabilities:
{findings_str}

Related real-world CVEs for context:
{cve_context}

For each confirmed vulnerability write a developer-friendly explanation.
Cover:
- what_is_wrong:      one sentence describing the exact problem in the code
- why_dangerous:      one sentence explaining how an attacker could exploit it
- attack_scenario:    a concrete example of how this could be exploited
- cwe_explanation:    what the CWE means in plain English

Respond ONLY with a JSON array:
[
  {{
    "category":        "Buffer Overflow",
    "what_is_wrong":   "strcpy copies user input into a 64-byte buffer with no size check",
    "why_dangerous":   "An attacker can supply input longer than 64 bytes to overwrite the return address",
    "attack_scenario": "Passing a 200-character username causes buf to overflow into the stack frame, allowing control of the return address and arbitrary code execution",
    "cwe_explanation": "CWE-120: The program copies data into a buffer without checking that the buffer is large enough to hold the data"
  }}
]"""

        try:
            raw    = self._llm(prompt, EXPLAINER_MODEL,
                            schema=self._bounded_schema(EXPLAINER_ITEM_SCHEMA,
                                                        count=len(state.validated_findings)))
            parsed = self._parse_json_array(raw)

            if parsed is not None:
                state.explanations = parsed
                self._log(f"Generated {len(parsed)} explanations")
            else:
                state.explanations = []
                self._log("Could not parse explanation response")

        except Exception as e:
            self._error(state, f"Explanation generation failed: {e}")
            state.explanations = []

        state.steps_completed.append(self.name)
        return state


# ─── Step 7: Advisory Refactoring Agent ───────────────────

class AdvisoryAgent(BaseAgent):
    """
    Generates specific code fixes for each confirmed vulnerability,
    referencing the relevant CVE and CWE as justification.

    Outputs:
        state.advisories – list of {category, fix_description,
                                    fixed_code, references, libraries}
    """
    name = "AdvisoryAgent"

    def _withhold_regressions(self, state: PipelineState, advisories: list) -> list:
        """
        Suggested code that adds a sink kind the flagged statement did not
        have (e.g. turning image bytes into a file path) is moved out of
        fixed_code so reports never present it as the fix.
        """
        by_category = {f.get("category"): f for f in state.validated_findings}
        for idx, adv in enumerate(advisories):
            if not isinstance(adv, dict) or not adv.get("fixed_code"):
                continue
            finding = by_category.get(adv.get("category")) or (
                state.validated_findings[idx] if idx < len(state.validated_findings) else {})
            original = "\n".join([str(finding.get("evidence", ""))] + [
                str(s.get("affected_code", ""))
                for s in linked_signals(finding, state.forensics_signals)])
            added = fix_regressions(original, str(adv["fixed_code"]), state.language)
            if added:
                adv["rejected_fixed_code"] = adv.pop("fixed_code")
                adv["fix_warning"] = ("Suggested code withheld: it adds " + ", ".join(added)
                                      + " that the flagged code did not have.")
                self._log(f"Withheld fix for '{adv.get('category')}': adds {', '.join(added)}")
        return advisories

    def run(self, state: PipelineState) -> PipelineState:
        if state.is_clean or not state.validated_findings:
            self._log("Code is clean — no advisories needed")
            state.steps_completed.append(self.name)
            return state

        self._log(
            f"Generating fix advisories for "
            f"{len(state.validated_findings)} findings..."
        )

        findings_str     = json.dumps(state.validated_findings, indent=2)
        explanations_str = (
            json.dumps(state.explanations, indent=2)
            if state.explanations
            else "Not available"
        )

        prompt = f"""You are a secure coding expert. Provide specific fixes for these vulnerabilities.

Vulnerable code:
```
{state.code[:1000]}
```

Confirmed vulnerabilities:
{findings_str}

Explanations:
{explanations_str}

For each vulnerability provide a concrete fix.
The fix must keep what the code does and must not add new file, network or command operations.
For path traversal, normalising (os.path.normpath / abspath) alone is not a fix: resolve the path and
check it stays inside the allowed base directory.

- category:         the vulnerability category
- fix_description:  one sentence describing what to change
- fixed_code:       the corrected code snippet (just the fixed lines)
- references:       relevant CWE ID and any related CVE IDs
- libraries:        secure libraries or functions to use instead

Respond ONLY with a JSON array:
[
  {{
    "category":        "Buffer Overflow",
    "fix_description": "Replace strcpy with strncpy and explicitly null-terminate",
    "fixed_code":      "strncpy(buf, username, sizeof(buf) - 1);\\nbuf[sizeof(buf) - 1] = '\\\\0';",
    "references":      {{"cwe": "CWE-120", "cves": ["CVE-2026-6691"]}},
    "libraries":       ["Use strncpy, strlcpy, or snprintf instead of strcpy"]
  }}
]"""

        try:
            raw    = self._llm(prompt, ADVISORY_MODEL,
                            schema=self._bounded_schema(ADVISORY_ITEM_SCHEMA,
                                                        count=len(state.validated_findings)))
            parsed = self._parse_json_array(raw)

            if parsed is not None:
                state.advisories = self._withhold_regressions(state, parsed)
                self._log(f"Generated {len(parsed)} advisories")
            else:
                state.advisories = []
                self._log("Could not parse advisory response")

        except Exception as e:
            self._error(state, f"Advisory generation failed: {e}")
            state.advisories = []

        state.steps_completed.append(self.name)
        return state


# ─── Step 8: Dashboard Formatter ──────────────────────────

class DashboardFormatter(BaseAgent):
    """
    Structures the final pipeline output for display.
    Produces both a human-readable terminal report and a JSON
    payload ready for a web dashboard or further processing.
    """
    name = "DashboardFormatter"

    def run(self, state: PipelineState) -> PipelineState:
        self._log("Formatting final report...")
        state.steps_completed.append(self.name)
        return state

    @staticmethod
    def _risk_for(state: PipelineState, finding: dict) -> Optional[dict]:
        """Risk fields of a finding, looked up by category when validation dropped them."""
        if "risk_score" in finding:
            return finding
        cat = str(finding.get("category", "")).strip().lower()
        return next((r for r in state.risk_scores
                     if str(r.get("category", "")).strip().lower() == cat), None)

    def format_report(self, state: PipelineState) -> str:
        SEP  = "═" * 72
        sep  = "─" * 72
        lines = []

        # ── Header ────────────────────────────────────────
        lines.append(f"\n{SEP}")
        lines.append("  VULNERABILITY ANALYSIS REPORT")
        lines.append(SEP)
        lines.append(f"  Language:  {state.language.upper()}")
        lines.append(
            f"  Pipeline:  "
            + " → ".join(state.steps_completed)
        )
        if state.errors:
            lines.append(
                f"  Warnings:  {len(state.errors)} agent(s) reported errors"
            )
        lines.append(sep)

        # ── Clean result ──────────────────────────────────
        if state.is_clean:
            lines.append(
                "\n  ✅  No vulnerabilities confirmed.\n"
                "      Code appears safe based on available threat intelligence.\n"
            )
            if state.false_positives:
                lines.append(
                    f"  ℹ️   {len(state.false_positives)} pattern(s) detected "
                    f"but ruled out as false positives:"
                )
                for fp in state.false_positives:
                    lines.append(
                        f"       • {fp.get('category','?')} — "
                        f"{fp.get('reasoning','')}"
                    )
            lines.append(f"\n{SEP}\n")
            return "\n".join(lines)

        # ── Summary ───────────────────────────────────────
        lines.append(
            f"\n  ⚠️   {len(state.validated_findings)} "
            f"vulnerability/ies confirmed\n"
        )

        # ── Risk summary ──────────────────────────────────
        risks = [r for r in (self._risk_for(state, f) for f in state.validated_findings) if r]
        if risks:
            top = max(risks, key=lambda r: r["risk_score"])
            counts = {lvl: 0 for _, lvl in reversed(RISK_LEVELS)}
            for r in risks:
                counts[r["risk_level"]] += 1
            lines.append("┌─ Risk Summary " + "─" * 57)
            lines.append(
                f"│  Highest risk: {RISK_EMOJI[top['risk_level']]} "
                f"{top['risk_score']:.2f}/25  ({top['risk_level']})"
            )
            lines.append("│  " + "  ".join(f"{n} {lvl}" for lvl, n in counts.items()))
            lines.append("└" + "─" * 70)

        # ── Confirmed findings ────────────────────────────
        if state.validated_findings:
            lines.append("┌─ Confirmed Vulnerabilities " + "─" * 44)
            for f in state.validated_findings:
                sev = f.get("severity", "UNKNOWN")
                lines.append(
                    f"│  [{sev:8}]  {f.get('category', 'Unknown')}"
                )
                lines.append(
                    f"│             {f.get('reasoning', f.get('evidence', ''))}"
                )
                if f.get("cwe_ids"):
                    lines.append(
                        f"│             CWEs: {', '.join(f['cwe_ids'])}"
                    )
                v = f.get("validation")
                if v:
                    p = v["parameters"]
                    lines.append(
                        f"│             Threat:     {v['category_name']} [{v['threat_category']}]  "
                        f"validation {v['score']}/100 ({v['rule']})"
                    )
                    lines.append(
                        f"│             Checks:     operation={'yes' if p['operation_evidence']['value'] else 'no'}  "
                        f"attacker={p['attacker_control']['value']}  mitigation={p['mitigation']['value']}  "
                        f"validator={p['llm_verdict']['value']}"
                        + (" (contradicted itself)" if p['llm_verdict']['contradiction'] else "")
                    )
                r = self._risk_for(state, f)
                if r:
                    lines.append(
                        f"│             Risk Score: {RISK_EMOJI[r['risk_level']]} "
                        f"{r['risk_score']:.2f}/25  ({r['risk_level']})"
                    )
                    lines.append(
                        f"│             Likelihood: {r['likelihood']:.4f}   "
                        f"Impact: {r['impact']:.4f}"
                    )
                    lines.append(
                        f"│             Dimensions: Exploitability={r['exploitability']}  "
                        f"Exposure={r['exposure']}  Prerequisites={r['attack_prerequisites']}"
                    )
                    lines.append(
                        f"│                         Confidentiality={r['confidentiality']}  "
                        f"Integrity={r['integrity']}  Availability={r['availability']}"
                    )
                    ev = r.get("risk_evidence") or {}
                    if ev:
                        short = {"exploitability": "Exploitability", "exposure": "Exposure",
                                 "attack_prerequisites": "Prerequisites", "confidentiality": "C",
                                 "integrity": "I", "availability": "A"}
                        by_src = {}
                        for d in RISK_DIMENSIONS:
                            by_src.setdefault(ev[d]["source"], []).append(short[d])
                        lines.append("│             Evidence:   " + "   ".join(
                            f"{src.upper()}: {','.join(ds)}" for src, ds in by_src.items()))
                        for d in ("exposure", "exploitability"):
                            if ev[d]["source"] == "cpg":
                                lines.append(f"│               {d}: {ev[d]['basis']}")
            lines.append("└" + "─" * 70)

        # ── False positives ───────────────────────────────
        if state.false_positives:
            lines.append(f"\n  ℹ️   False positives filtered out:")
            for fp in state.false_positives:
                lines.append(
                    f"       • {fp.get('category','?')} — "
                    f"{fp.get('reasoning','')}"
                )

        # ── Unresolved (still NEEDS_CONTEXT after feedback) ─
        if state.needs_context_findings:
            lines.append(f"\n  ❔  Unresolved — needs manual review "
                         f"({len(state.feedback_rounds)} forensics feedback round(s) tried):")
            for nc in state.needs_context_findings:
                lines.append(
                    f"       • {nc.get('category','?')} — "
                    f"{nc.get('reasoning','')}"
                )

        # ── Explanations ──────────────────────────────────
        if state.explanations:
            lines.append(f"\n{sep}")
            lines.append("  EXPLANATIONS")
            lines.append(sep)
            for ex in state.explanations:
                lines.append(f"\n  [{ex.get('category', 'Unknown')}]")
                lines.append(
                    f"  Problem:   {ex.get('what_is_wrong', '')}"
                )
                lines.append(
                    f"  Risk:      {ex.get('why_dangerous', '')}"
                )
                lines.append(
                    f"  Scenario:  {ex.get('attack_scenario', '')}"
                )
                if ex.get("cwe_explanation"):
                    lines.append(
                        f"  CWE note:  {ex['cwe_explanation']}"
                    )

        # ── Advisories ────────────────────────────────────
        if state.advisories:
            lines.append(f"\n{sep}")
            lines.append("  RECOMMENDED FIXES")
            lines.append(sep)
            for adv in state.advisories:
                lines.append(f"\n  [{adv.get('category', 'Unknown')}]")
                lines.append(
                    f"  Fix:       {adv.get('fix_description', '')}"
                )
                if adv.get("fixed_code"):
                    lines.append("  Code:")
                    for line in adv["fixed_code"].splitlines():
                        lines.append(f"    {line}")
                refs = adv.get("references", {})
                if refs.get("cwe"):
                    lines.append(f"  Reference: {refs['cwe']}")
                if refs.get("cves"):
                    lines.append(
                        f"  CVEs:      {', '.join(refs['cves'])}"
                    )
                for lib in adv.get("libraries", []):
                    lines.append(f"  ℹ️  {lib}")

        # ── Matched CVEs ──────────────────────────────────
        if state.cve_matches:
            lines.append(f"\n{sep}")
            lines.append("  MATCHED CVEs FROM THREAT DATABASE")
            lines.append(sep)
            for c in state.cve_matches[:5]:
                llm  = c.get("llm_score")
                llm_str = f"LLM: {llm}/10  " if llm is not None else ""
                lines.append(
                    f"  [{c.get('severity','?'):8}]  "
                    f"{c['cve_id']}  "
                    f"{llm_str}"
                    f"— {c['description'][:100]}..."
                )
                if c.get("explanation"):
                    lines.append(
                        f"             Why: {c['explanation']}"
                    )

        lines.append(f"\n{SEP}\n")
        return "\n".join(lines)


# ─── Orchestrator ──────────────────────────────────────────

class VulnerabilityOrchestrator:
    """
    Runs the full sequential pipeline.
    Each agent receives the full PipelineState and returns it enriched.
    A single agent failure never crashes the pipeline — it is logged
    and execution continues with the next agent.
    """

    def __init__(self, top_k: int = 5, score_threshold: float = 0.3):
        self.agents = [
            CPGAgent(),
            ForensicsAgent(),
            RAGQueryAgent(top_k=top_k, score_threshold=score_threshold),
            CategorizationAgent(),
            ValidationAgent(),
            ExplainableAIAgent(),
            AdvisoryAgent(),
            DashboardFormatter(),
        ]
        self.formatter = DashboardFormatter()

    def run(
        self,
        code: str,
        language: Optional[str] = None,
        source_path: Optional[str] = None,
        project_cpgs: Optional[dict] = None,
        on_step=None,
    ) -> PipelineState:
        """
        Analyse one snippet. For a project scan pass `language` (from the file
        extension), `source_path` (relative to the project root) and
        `project_cpgs` ({frontend: CPG}) so the whole-repo CPG is reused.
        `on_step(agent_name)` is called after each agent finishes (progress UIs).
        """
        print("\n🚀 Starting vulnerability analysis pipeline...\n")
        state = PipelineState(
            code=code,
            language=language or "unknown",
            source_path=source_path,
            project_cpgs=project_cpgs,
        )

        for agent in self.agents:
            print(f"  ▶ {agent.name}")
            state = self._run_agent(agent, state)
            if isinstance(agent, ValidationAgent):
                self._needs_context_feedback(state)
            if on_step:
                on_step(agent.name)

        print("\n✅ Pipeline complete.\n")
        return state

    @staticmethod
    def _run_agent(agent: BaseAgent, state: PipelineState) -> PipelineState:
        try:
            return agent.run(state)
        except Exception as e:
            print(f"  ❌ {agent.name} crashed unexpectedly: {e}")
            traceback.print_exc()
            state.errors.append({"agent": agent.name, "error": str(e)})
            return state      # continue to next agent regardless

    # NEEDS_CONTEXT -> ForensicsAgent -> RAG -> Categorization -> Validation
    MAX_FEEDBACK_ROUNDS = int(os.environ.get("MAX_FEEDBACK_ROUNDS", "1"))

    def _needs_context_feedback(self, state: PipelineState):
        """
        Findings the validator could not decide go back to the ForensicsAgent
        with the wider CPG context the validator asked for. Refined findings
        are re-run through RAG, categorization and validation; withdrawn ones
        become false positives. Whatever is still undecided after
        MAX_FEEDBACK_ROUNDS stays in state.needs_context_findings and is
        reported as unresolved instead of being dropped.
        """
        forensics = next(a for a in self.agents if isinstance(a, ForensicsAgent))
        rerun     = [a for a in self.agents
                     if isinstance(a, (RAGQueryAgent, CategorizationAgent, ValidationAgent))]

        for rnd in range(1, self.MAX_FEEDBACK_ROUNDS + 1):
            pending = state.needs_context_findings
            if not pending:
                return
            print(f"  ↺ NEEDS_CONTEXT feedback round {rnd}: {len(pending)} finding(s) back to {forensics.name}")
            try:
                refined, withdrawn, unchanged = forensics.reexamine(state, pending)
            except Exception as e:
                state.errors.append({"agent": forensics.name, "error": f"re-examination failed: {e}"})
                return

            sub = PipelineState(
                code=state.code, language=state.language, source_path=state.source_path,
                ast_functions=state.ast_functions, ast_calls=state.ast_calls,
                parse_success=state.parse_success, cpg_backend=state.cpg_backend,
                cpg_extractor=state.cpg_extractor, forensics_signals=refined,
            )
            if refined:
                for agent in rerun:
                    sub = self._run_agent(agent, sub)

            tag = {"feedback_round": rnd}
            state.validated_findings     += [{**f, **tag} for f in sub.validated_findings]
            state.false_positives        += [{**f, **tag} for f in sub.false_positives + withdrawn]
            state.needs_context_findings  = [{**f, **tag} for f in sub.needs_context_findings + unchanged]
            state.forensics_signals      += refined
            state.risk_scores            += sub.risk_scores
            seen = {c["cve_id"] for c in state.cve_matches}
            state.cve_matches            += [c for c in sub.cve_matches if c["cve_id"] not in seen]
            state.errors                 += sub.errors
            state.is_clean = not state.validated_findings and not state.needs_context_findings
            state.feedback_rounds.append({
                "round":       rnd,
                "sent":        [f.get("category") for f in pending],
                "refined":     len(refined),
                "withdrawn":   len(withdrawn),
                "confirmed":   len(sub.validated_findings),
                "unresolved":  len(sub.needs_context_findings),
            })
            print(f"    refined {len(refined)}, withdrawn {len(withdrawn)} → confirmed "
                  f"{len(sub.validated_findings)}, false positive {len(sub.false_positives) + len(withdrawn)}, "
                  f"still unresolved {len(sub.needs_context_findings)}")
            if not refined:
                return

    def run_and_report(self, code: str) -> tuple:
        """
        Convenience method — runs pipeline and returns
        (formatted_report_string, pipeline_state).
        """
        state  = self.run(code)
        report = self.formatter.format_report(state)
        return report, state


# ─── Built-in test cases ───────────────────────────────────

BUILTIN_EXAMPLES = [
    {
        "title": "Buffer Overflow (C)",
        "code": textwrap.dedent("""\
            void login(char *username) {
                char buf[64];
                strcpy(buf, username);
                printf("Welcome %s\\n", buf);
            }
        """),
    },
    {
        "title": "SQL Injection (Python)",
        "code": textwrap.dedent("""\
            def get_user(username):
                query = "SELECT * FROM users WHERE name = '" + username + "'"
                cursor.execute(query)
                return cursor.fetchall()
        """),
    },
    {
        "title": "Command Injection (Python)",
        "code": textwrap.dedent("""\
            import os

            def ping_host(host):
                os.system("ping -c 4 " + host)
        """),
    },
    {
        "title": "Use-After-Free (C)",
        "code": textwrap.dedent("""\
            void process() {
                char *data = (char *)malloc(256);
                strcpy(data, "sensitive");
                free(data);
                printf("Data: %s\\n", data);
            }
        """),
    },
    {
        "title": "Insecure Deserialization (Python)",
        "code": textwrap.dedent("""\
            import pickle

            def load_session(data):
                return pickle.loads(data)
        """),
    },
    {
        "title": "Safe Code (should be clean)",
        "code": textwrap.dedent("""\
            def calculate_total(items: list) -> float:
                total = 0.0
                for item in items:
                    total += item["price"] * item["quantity"]
                return round(total, 2)
        """),
    },
]


# ─── Entry point ───────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NVD RAG Vulnerability Orchestrator & Project Scanner"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to source file, project directory, ZIP archive, or Git repository URL",
    )
    parser.add_argument(
        "--dir",
        dest="directory",
        help="Path to project directory to scan recursively",
    )
    parser.add_argument(
        "--repo",
        dest="repo_url",
        help="Git repository URL to clone and scan (e.g. https://github.com/org/repo.git)",
    )
    parser.add_argument(
        "--branch",
        help="Git branch to clone (optional)",
    )
    parser.add_argument(
        "--zip",
        dest="zip_path",
        help="Path to project ZIP archive to scan",
    )
    parser.add_argument(
        "--builtin",
        action="store_true",
        help="Run all built-in test examples",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON output to stdout",
    )
    parser.add_argument(
        "--output-json",
        help="Save full scan results to a JSON file",
    )
    parser.add_argument(
        "--output-html",
        help="Save interactive HTML audit report to a file",
    )
    parser.add_argument(
        "--output-md",
        help="Save Markdown audit summary to a file",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        help="Maximum number of files to scan in directory/repo",
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Skip the dependency check (sends package names/versions to OSV.dev)",
    )
    parser.add_argument(
        "--ext",
        help="Comma-separated list of file extensions to include (e.g. .c,.py,.js)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=5,
        help="Number of CVEs to retrieve (default: 5)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.3,
        help="Minimum vector similarity threshold (default: 0.3)",
    )
    args = parser.parse_args()

    orchestrator = VulnerabilityOrchestrator(
        top_k          = args.top_k,
        score_threshold = args.threshold,
    )

    from project_scanner import ProjectScanner, ProjectReportFormatter

    # Parse custom extensions if provided
    custom_extensions = None
    if args.ext:
        ext_list = [e.strip() if e.strip().startswith(".") else f".{e.strip()}" for e in args.ext.split(",")]
        custom_extensions = {e: e.lstrip(".") for e in ext_list}

    scanner = ProjectScanner(
        orchestrator=orchestrator,
        top_k=args.top_k,
        score_threshold=args.threshold,
        supported_extensions=custom_extensions,
        max_files=args.max_files,
        dependency_scan=not args.no_deps,
    )

    def print_progress(idx, total, rel_path, res):
        if res is None:
            print(f"  [{idx}/{total}] 🔍 Scanning {rel_path}...", end="\r", flush=True)
        else:
            if res.is_clean:
                status = "✅ Clean"
            else:
                status = f"⚠️ {res.findings_count} Finding(s)"
            print(f"  [{idx}/{total}] {status} — {rel_path} ({res.scan_duration_sec}s)")

    # ── Built-in mode ──────────────────────────────────────
    if args.builtin:
        print(f"\n  Running {len(BUILTIN_EXAMPLES)} built-in examples...\n")
        for i, ex in enumerate(BUILTIN_EXAMPLES, 1):
            print(f"\n{'═'*72}")
            print(f"  Example {i}/{len(BUILTIN_EXAMPLES)}: {ex['title']}")
            print(f"{'═'*72}")
            report, state = orchestrator.run_and_report(ex["code"])
            print(report)
            if args.json:
                print(state.to_json())
            if i < len(BUILTIN_EXAMPLES):
                try:
                    input("  Press ENTER for next example...")
                except EOFError:
                    pass
        return

    # Determine target mode
    target = args.target or args.directory or args.repo_url or args.zip_path

    if target:
        is_git_url = target.startswith("http://") or target.startswith("https://") or target.startswith("git@")
        
        # ── Git repository mode ────────────────────────────
        if is_git_url or args.repo_url:
            repo_url = args.repo_url or target
            print(f"\n🚀 Scanning Git Repository: {repo_url}\n")
            result = scanner.scan_git_repo(repo_url, branch=args.branch, progress_callback=print_progress)
            report = ProjectReportFormatter.format_terminal(result)
            print(report)

            if args.json:
                print(result.to_json())
            if args.output_json:
                Path(args.output_json).write_text(result.to_json(), encoding="utf-8")
                print(f"💾 JSON report saved to {args.output_json}")
            if args.output_html:
                Path(args.output_html).write_text(ProjectReportFormatter.format_html(result), encoding="utf-8")
                print(f"💾 HTML report saved to {args.output_html}")
            if args.output_md:
                Path(args.output_md).write_text(ProjectReportFormatter.format_markdown(result), encoding="utf-8")
                print(f"💾 Markdown report saved to {args.output_md}")
            return

        # ── ZIP archive mode ───────────────────────────────
        if args.zip_path or (target.endswith(".zip") and Path(target).is_file()):
            zip_path = args.zip_path or target
            print(f"\n🚀 Scanning ZIP Archive: {zip_path}\n")
            result = scanner.scan_zip(zip_path, progress_callback=print_progress)
            report = ProjectReportFormatter.format_terminal(result)
            print(report)

            if args.json:
                print(result.to_json())
            if args.output_json:
                Path(args.output_json).write_text(result.to_json(), encoding="utf-8")
                print(f"💾 JSON report saved to {args.output_json}")
            if args.output_html:
                Path(args.output_html).write_text(ProjectReportFormatter.format_html(result), encoding="utf-8")
                print(f"💾 HTML report saved to {args.output_html}")
            if args.output_md:
                Path(args.output_md).write_text(ProjectReportFormatter.format_markdown(result), encoding="utf-8")
                print(f"💾 Markdown report saved to {args.output_md}")
            return

        target_path = Path(target)

        # ── Directory mode ─────────────────────────────────
        if target_path.is_dir() or args.directory:
            dir_path = str(target_path) if target_path.is_dir() else args.directory
            print(f"\n🚀 Scanning Project Directory: {dir_path}\n")
            result = scanner.scan_directory(dir_path, progress_callback=print_progress)
            report = ProjectReportFormatter.format_terminal(result)
            print(report)

            if args.json:
                print(result.to_json())
            if args.output_json:
                Path(args.output_json).write_text(result.to_json(), encoding="utf-8")
                print(f"💾 JSON report saved to {args.output_json}")
            if args.output_html:
                Path(args.output_html).write_text(ProjectReportFormatter.format_html(result), encoding="utf-8")
                print(f"💾 HTML report saved to {args.output_html}")
            if args.output_md:
                Path(args.output_md).write_text(ProjectReportFormatter.format_markdown(result), encoding="utf-8")
                print(f"💾 Markdown report saved to {args.output_md}")
            return

        # ── Single file mode ───────────────────────────────
        if target_path.is_file():
            try:
                code = target_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                print(f"❌ Could not read file: {target_path} ({e})")
                sys.exit(1)

            report, state = orchestrator.run_and_report(code)
            print(report)
            if args.json:
                print(state.to_json())
            if args.output_json:
                Path(args.output_json).write_text(state.to_json(), encoding="utf-8")
                print(f"💾 JSON state saved to {args.output_json}")
            return

        print(f"❌ Target not found: {target}")
        sys.exit(1)

    # ── Default — built-in buffer overflow snippet ─────────
    default_code = textwrap.dedent("""\
        void login(char *username) {
            char buf[64];
            strcpy(buf, username);
            printf("Welcome %s\\n", buf);
        }
    """)

    print(
        "\nNo target specified — running default buffer overflow test.\n"
        "Usage examples:\n"
        "  python orchestrator2.py path/to/project_dir/     # Scan entire project folder\n"
        "  python orchestrator2.py --repo https://github.com/user/repo.git # Scan Git repo\n"
        "  python orchestrator2.py path/to/file.c          # Scan single file\n"
        "  python orchestrator2.py --builtin               # Run built-in examples\n"
    )
    report, state = orchestrator.run_and_report(default_code)
    print(report)
    if args.json:
        print(state.to_json())


if __name__ == "__main__":
    main()
