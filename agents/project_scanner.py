# agents/project_scanner.py
"""
Project and Repository Scanner for the NVD RAG Vulnerability Analysis Pipeline.

Supports:
  1. Local project directory scanning (recursive, with smart ignore filters)
  2. Remote Git repository scanning (clones via git and scans)
  3. ZIP archive scanning (extracts safely and scans)
  4. Multi-format reporting (Terminal dashboard, JSON, Markdown, HTML)
"""

import os
import sys
import json
import time
import shutil
import tempfile
import zipfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any

# Ensure agents and rag directories are importable
_AGENTS_DIR = Path(__file__).resolve().parent
_RAG_DIR = _AGENTS_DIR.parent / "rag"

if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))
if str(_RAG_DIR) not in sys.path:
    sys.path.insert(0, str(_RAG_DIR))

import orchestrator2 as pipeline
from orchestrator2 import VulnerabilityOrchestrator, PipelineState, BUILTIN_EXAMPLES
from joern_cpg import JoernRunner, JoernUnavailable
from joern_cpg.security_catalog import family_of
from dependency_scanner import scan_dependencies
from collections import defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed



# ─── File Extension Mappings & Defaults ──────────────────────

SUPPORTED_EXTENSIONS = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".sql": "sql",
    ".sol": "solidity",
}

DEFAULT_IGNORE_DIRS = {
    ".git", ".svn", ".hg", ".bzr", ".cvs",
    "node_modules", "bower_components", "vendor", "packages", "site-packages",
    "venv", ".venv", "env", ".env", "virtualenv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", ".nox",
    "build", "dist", "out", "target", "bin", "obj", "release", "debug",
    ".vscode", ".idea", ".vs", ".settings", ".project", ".classpath",
    "qdrant_storage", "unsloth_compiled_cache", ".gemini", "coverage",
    ".next", ".nuxt", ".cache", ".turbo", ".gradle", ".cargo", "logs",
}

DEFAULT_IGNORE_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
    "poetry.lock", "Pipfile.lock", "composer.lock", "go.sum",
}

MAX_FILE_BYTES = 200_000  # 200 KB per file limit for LLM security analysis


# ─── Data Structures ─────────────────────────────────────────

@dataclass
class FileScanResult:
    filepath: str
    relative_path: str
    language: str
    size_bytes: int
    lines_of_code: int
    is_clean: bool
    findings_count: int
    severity_breakdown: Dict[str, int]
    validated_findings: List[Dict[str, Any]]
    false_positives: List[Dict[str, Any]]
    explanations: List[Dict[str, Any]]
    advisories: List[Dict[str, Any]]
    cve_matches: List[Dict[str, Any]]
    errors: List[Dict[str, Any]]
    scan_duration_sec: float
    raw_state: Optional[Dict[str, Any]] = None
    # Findings still NEEDS_CONTEXT after the forensics feedback round(s)
    needs_context: List[Dict[str, Any]] = field(default_factory=list)
    # vulnerable / unresolved / incomplete / clean (see file_status)
    status: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def file_status(f: FileScanResult) -> str:
    """
    One status per file, so every file lands in exactly one report bucket:
      vulnerable  at least one confirmed finding
      unresolved  findings the validator could not decide (manual review)
      incomplete  not analysed to a verdict (skipped, crashed); see errors
      clean       analysed, nothing found
    """
    if f.findings_count:
        return "vulnerable"
    if f.needs_context:
        return "unresolved"
    if not f.is_clean:
        return "incomplete"
    return "clean"


@dataclass
class ProjectScanResult:
    project_name: str
    source_type: str  # "directory", "git_repo", "zip", "file_list"
    source_path: str
    scan_start_time: str
    scan_duration_sec: float
    total_files_found: int
    total_files_scanned: int
    total_files_skipped: int
    total_lines_of_code: int
    total_vulnerabilities: int
    severity_counts: Dict[str, int]
    clean_files_count: int
    vulnerable_files_count: int
    false_positives_filtered: int
    security_score: int
    security_grade: str
    top_cwes: List[Dict[str, Any]]
    top_cves: List[Dict[str, Any]]
    files: List[FileScanResult] = field(default_factory=list)
    # {language: file count} for files not analysed (no CPG / catalog support)
    skipped_unsupported: Dict[str, int] = field(default_factory=dict)
    unresolved_count: int = 0          # findings still NEEDS_CONTEXT after feedback
    unresolved_files_count: int = 0
    incomplete_files_count: int = 0
    # dependency_scanner.scan_dependencies() output ({} when disabled)
    dependencies: Dict[str, Any] = field(default_factory=dict)
    # Vulnerable runtime packages by their highest advisory severity
    dependency_severity_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ─── Git Helper ──────────────────────────────────────────────

def clone_git_repo(repo_url: str, target_dir: str, branch: Optional[str] = None) -> bool:
    """Clone a remote Git repository with depth 1 for scanning."""
    # core.longpaths: Windows otherwise fails checkout past 260-char paths.
    cmd = ["git", "-c", "core.longpaths=true", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, target_dir])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Git clone failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("❌ Git executable not found in PATH.")
        return False


# ─── Project Scanner Engine ──────────────────────────────────

class ProjectScanner:
    """
    Scans entire codebases, directories, ZIP archives, or Git repositories.
    """

    def __init__(
        self,
        orchestrator: Optional[VulnerabilityOrchestrator] = None,
        top_k: int = 5,
        score_threshold: float = 0.3,
        supported_extensions: Optional[Dict[str, str]] = None,
        ignore_dirs: Optional[set] = None,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_files: Optional[int] = None,
        exclude_paths: Optional[List[str]] = None,
        use_cpg: bool = True,
        workers: Optional[int] = None,
        on_event: Optional[Callable[[dict], None]] = None,
        include_unsupported: bool = False,
        dependency_scan: bool = True,
    ):
        self.orchestrator = orchestrator or VulnerabilityOrchestrator(
            top_k=top_k,
            score_threshold=score_threshold,
        )
        self.supported_extensions = supported_extensions or SUPPORTED_EXTENSIONS
        self.ignore_dirs = set(ignore_dirs) if ignore_dirs else DEFAULT_IGNORE_DIRS
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        # Project-relative path prefixes to skip, e.g. "finetune/data".
        self.exclude_paths = [
            p.replace("\\", "/").strip("/").lstrip("./")
            for p in (exclude_paths or []) if p.strip("/. ")
        ]
        self.use_cpg = use_cpg
        # Files in languages without CPG/catalog support are counted, not scanned.
        self.include_unsupported = include_unsupported
        self.unsupported_counts: Dict[str, int] = defaultdict(int)
        # Pinned dependencies checked against OSV.dev (package names/versions only).
        self.dependency_scan = dependency_scan and os.environ.get("DEPENDENCY_SCAN", "1") != "0"
        # Files are independent, so several run through the pipeline at once.
        # Ollama serves concurrent requests, which keeps the GPU busy instead of
        # idling between one small sequential call and the next.
        self.workers = workers or int(os.environ.get("SCAN_WORKERS", "4"))
        # on_event(dict): progress for UIs, e.g. {"stage": "pipeline", "agent": ..., "done": 3, "total": 10}
        self.on_event = on_event
        self._event_lock = threading.Lock()

    def _emit(self, stage: str, **fields):
        if self.on_event:
            with self._event_lock:
                try:
                    self.on_event({"stage": stage, **fields})
                except Exception:
                    pass

    def _should_ignore_dir(self, dir_name: str) -> bool:
        return dir_name in self.ignore_dirs or dir_name.startswith(".")

    def _is_excluded(self, rel_path: str) -> bool:
        return any(rel_path == e or rel_path.startswith(e + "/") for e in self.exclude_paths)

    def discover_files(self, base_dir: Path) -> List[Path]:
        """Discover all eligible source code files in a directory tree."""
        discovered: List[Path] = []
        base_dir = base_dir.resolve()
        self.unsupported_counts = defaultdict(int)

        # Read .gitignore if present
        gitignore_patterns = []
        gitignore_file = base_dir / ".gitignore"
        if gitignore_file.exists():
            try:
                for line in gitignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        gitignore_patterns.append(line)
            except Exception:
                pass

        for root, dirs, files in os.walk(base_dir):
            rel_root = Path(root).relative_to(base_dir).as_posix()
            rel_root = "" if rel_root == "." else rel_root + "/"
            # Modify dirs in-place to prevent os.walk from entering ignored directories
            dirs[:] = [
                d for d in dirs
                if not self._should_ignore_dir(d)
                and not self._is_excluded(rel_root + d)
            ]

            for file_name in files:
                if file_name in DEFAULT_IGNORE_FILES or file_name.endswith(".min.js") or file_name.endswith(".min.css"):
                    continue

                file_path = Path(root) / file_name
                ext = file_path.suffix.lower()
                language = self.supported_extensions.get(ext)
                if language is None:
                    continue

                # Only languages the pipeline can analyse (Joern frontend +
                # security catalog). Others would reach the LLM as raw text
                # with no structural facts, which produces invented findings.
                if not self.include_unsupported and family_of(language) is None:
                    self.unsupported_counts[language] += 1
                elif not self.max_files or len(discovered) < self.max_files:
                    discovered.append(file_path)

        return discovered

    def _build_project_cpgs(self, base_dir: Path, files: List[Path]) -> Dict[str, Any]:
        """
        One Joern CPG per frontend (c, python, js, ...) covering every selected
        file of the project, so calls resolve across files.

        Returns {} when CPG is disabled or Joern is unavailable/fails; the
        pipeline then uses tree-sitter per file.
        """
        if not self.use_cpg or not files:
            return {}
        try:
            runner = JoernRunner()
        except JoernUnavailable as e:
            print(f"⚠️  {e}\n   Continuing with tree-sitter per file.", file=sys.stderr)
            return {}

        groups: Dict[str, List[str]] = defaultdict(list)
        for f in files:
            frontend = JoernRunner.frontend_for(self.supported_extensions.get(f.suffix.lower()))
            if frontend:
                groups[frontend].append(f.relative_to(base_dir).as_posix())

        # One Joern JVM per language, all at once: each run is mostly JVM
        # startup + single-threaded import, so running them side by side
        # costs about as long as the slowest one.
        def build(frontend: str, rels: List[str]):
            print(f"Building project CPG [{frontend}]: {len(rels)} file(s)...", file=sys.stderr)
            t0 = time.time()
            cpg = runner.build_project(base_dir, rels, frontend)
            print(f"   [{frontend}] {len(cpg.project_methods)} methods, "
                  f"{len(cpg.project_ddg)} data-flow edges ({time.time() - t0:.1f}s)", file=sys.stderr)
            return cpg

        cpgs: Dict[str, Any] = {}
        if not groups:          # no file has a Joern frontend (e.g. all Rust)
            self._emit("cpg", status="skipped", done=0, total=0)
            return cpgs
        with ThreadPoolExecutor(max_workers=len(groups)) as pool:
            futures = {pool.submit(build, fe, rels): fe for fe, rels in groups.items()}
            for fut in as_completed(futures):
                frontend = futures[fut]
                try:
                    cpgs[frontend] = fut.result()
                except Exception as e:
                    print(f"   Joern [{frontend}] failed: {str(e)[:400]} — tree-sitter for these files",
                          file=sys.stderr)
                self._emit("cpg", language=frontend, ok=frontend in cpgs,
                           done=len([f for f in futures if f.done()]), total=len(groups))
        return cpgs

    def scan_single_file(
        self,
        file_path: Path,
        relative_to: Path,
        project_cpgs: Optional[Dict[str, Any]] = None,
        on_step: Optional[Callable[[str], None]] = None,
    ) -> FileScanResult:
        """Scan a single source code file with the VulnerabilityOrchestrator."""
        start_time = time.time()
        rel_path = str(file_path.relative_to(relative_to)).replace("\\", "/")
        ext = file_path.suffix.lower()
        language = self.supported_extensions.get(ext, "unknown")

        try:
            raw_bytes = file_path.read_bytes()
            size_bytes = len(raw_bytes)

            if size_bytes > self.max_file_bytes:
                return FileScanResult(
                    filepath=str(file_path),
                    relative_path=rel_path,
                    language=language,
                    size_bytes=size_bytes,
                    lines_of_code=0,
                    is_clean=False,     # not analysed: must not count as clean
                    findings_count=0,
                    severity_breakdown={},
                    validated_findings=[],
                    false_positives=[],
                    explanations=[],
                    advisories=[],
                    cve_matches=[],
                    errors=[{"agent": "ProjectScanner", "error": f"File skipped: size {size_bytes} exceeds {self.max_file_bytes} bytes limit"}],
                    scan_duration_sec=round(time.time() - start_time, 2),
                )

            try:
                code = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                code = raw_bytes.decode("latin-1", errors="ignore")

            lines = code.count("\n") + (1 if code else 0)

            if not code.strip():
                return FileScanResult(
                    filepath=str(file_path),
                    relative_path=rel_path,
                    language=language,
                    size_bytes=size_bytes,
                    lines_of_code=0,
                    is_clean=True,
                    findings_count=0,
                    severity_breakdown={},
                    validated_findings=[],
                    false_positives=[],
                    explanations=[],
                    advisories=[],
                    cve_matches=[],
                    errors=[{"agent": "ProjectScanner", "error": "File is empty"}],
                    scan_duration_sec=round(time.time() - start_time, 2),
                )

            # Run through VulnerabilityOrchestrator. With project_cpgs set (even
            # {}), the CPG agent never starts Joern per file.
            state: PipelineState = self.orchestrator.run(
                code,
                language=language,
                source_path=rel_path,
                project_cpgs=project_cpgs if project_cpgs is not None else {},
                on_step=on_step,
            )

            # Determine severity counts for this file
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for finding in state.validated_findings:
                sev = (finding.get("severity") or "LOW").upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["LOW"] += 1

            return FileScanResult(
                filepath=str(file_path),
                relative_path=rel_path,
                language=state.language or language,
                size_bytes=size_bytes,
                lines_of_code=lines,
                is_clean=state.is_clean,
                findings_count=len(state.validated_findings),
                severity_breakdown=sev_counts,
                validated_findings=state.validated_findings,
                false_positives=state.false_positives,
                explanations=state.explanations,
                advisories=state.advisories,
                cve_matches=state.cve_matches,
                errors=state.errors,
                scan_duration_sec=round(time.time() - start_time, 2),
                raw_state=state.to_dict(),
                needs_context=state.needs_context_findings,
            )

        except Exception as e:
            return FileScanResult(
                filepath=str(file_path),
                relative_path=rel_path,
                language=language,
                size_bytes=0,
                lines_of_code=0,
                is_clean=False,     # not analysed: must not count as clean
                findings_count=0,
                severity_breakdown={},
                validated_findings=[],
                false_positives=[],
                explanations=[],
                advisories=[],
                cve_matches=[],
                errors=[{"agent": "ProjectScanner", "error": f"Crash scanning file: {str(e)}"}],
                scan_duration_sec=round(time.time() - start_time, 2),
            )

    def scan_directory(
        self,
        directory_path: str,
        project_name: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str, Optional[FileScanResult]], None]] = None,
    ) -> ProjectScanResult:
        """Scan all eligible source files in a local directory."""
        start_time = time.time()
        start_iso = time.strftime("%Y-%m-%d %H:%M:%S")
        base_dir = Path(directory_path).resolve()

        if not base_dir.exists() or not base_dir.is_dir():
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        name = project_name or base_dir.name
        self._emit("discover", status="running")
        files_to_scan = self.discover_files(base_dir)
        total_found = len(files_to_scan)
        skipped = dict(sorted(self.unsupported_counts.items(), key=lambda kv: -kv[1]))
        if skipped:
            print("Not analysed (unsupported language): "
                  + ", ".join(f"{n} {lang}" for lang, n in skipped.items()), file=sys.stderr)
        self._emit("discover", status="done", total=total_found, skipped_unsupported=skipped)

        # The dependency check is network-bound, so it runs while the code is analysed.
        dep_pool = ThreadPoolExecutor(max_workers=1) if self.dependency_scan else None
        dep_future = dep_pool.submit(self._scan_dependencies, base_dir) if dep_pool else None

        # Whole-project CPGs first; every file then reuses them.
        self._emit("cpg", status="running", done=0, total=0)
        project_cpgs = self._build_project_cpgs(base_dir, files_to_scan)
        self._emit("cpg", status="done")

        # Per-agent completion counts across files, for progress events.
        agent_done: Dict[str, int] = defaultdict(int)

        def on_step(agent_name: str):
            with self._event_lock:
                agent_done[agent_name] += 1
                done = agent_done[agent_name]
            self._emit("pipeline", agent=agent_name, done=done, total=total_found)

        cb_lock = threading.Lock()
        started = [0]

        def run_one(file_path: Path) -> FileScanResult:
            rel = str(file_path.relative_to(base_dir)).replace("\\", "/")
            if progress_callback:
                with cb_lock:
                    started[0] += 1
                    progress_callback(started[0], total_found, rel, None)
            return self.scan_single_file(file_path, base_dir, project_cpgs=project_cpgs,
                                         on_step=on_step)

        # Files run concurrently; results keep discovery order.
        results_by_path: Dict[Path, FileScanResult] = {}
        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as pool:
            futures = {pool.submit(run_one, fp): fp for fp in files_to_scan}
            for n, fut in enumerate(as_completed(futures), 1):
                fp = futures[fut]
                results_by_path[fp] = fut.result()
                if progress_callback:
                    with cb_lock:
                        progress_callback(n, total_found,
                                          str(fp.relative_to(base_dir)).replace("\\", "/"),
                                          results_by_path[fp])
                self._emit("files", done=n, total=total_found)

        file_results: List[FileScanResult] = []
        cwe_counter: Dict[str, int] = {}
        cve_map: Dict[str, Dict[str, Any]] = {}

        for file_path in files_to_scan:
            rel_path = str(file_path.relative_to(base_dir)).replace("\\", "/")
            res = results_by_path[file_path]
            res.status = file_status(res)
            file_results.append(res)

            # Aggregate CWEs
            for finding in res.validated_findings:
                for cwe in finding.get("cwe_ids", []):
                    cwe_counter[cwe] = cwe_counter.get(cwe, 0) + 1

            # Aggregate CVEs
            for cve in res.cve_matches:
                cve_id = cve.get("cve_id")
                if cve_id:
                    if cve_id not in cve_map:
                        cve_map[cve_id] = {
                            "cve_id": cve_id,
                            "severity": cve.get("severity", "UNKNOWN"),
                            "description": cve.get("description", ""),
                            "files": [rel_path],
                        }
                    else:
                        if rel_path not in cve_map[cve_id]["files"]:
                            cve_map[cve_id]["files"].append(rel_path)

        # Totals and metrics
        total_loc = sum(f.lines_of_code for f in file_results)
        total_vulns = sum(f.findings_count for f in file_results)
        clean_count = sum(1 for f in file_results if f.status == "clean")
        vuln_count = sum(1 for f in file_results if f.status == "vulnerable")
        unresolved_files = sum(1 for f in file_results if f.status == "unresolved")
        incomplete_files = sum(1 for f in file_results if f.status == "incomplete")
        unresolved_count = sum(len(f.needs_context) for f in file_results)
        fp_count = sum(len(f.false_positives) for f in file_results)

        sev_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in file_results:
            for k, v in f.severity_breakdown.items():
                if k in sev_summary:
                    sev_summary[k] += v

        dependencies = dep_future.result() if dep_future else {}
        if dep_pool:
            dep_pool.shutdown()
        # A vulnerable runtime package counts once, at its worst advisory.
        # Dev-only packages (build tooling) are reported but not scored.
        dep_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for pkg in dependencies.get("vulnerable", []):
            if not pkg["dev"]:
                sev = pkg["severity"] if pkg["severity"] in dep_sev else "MEDIUM"
                dep_sev[sev] += 1

        # Calculate Security Score (0 to 100)
        # Deduct 25 per critical, 15 per high, 5 per medium, 2 per low
        # (confirmed code findings + vulnerable runtime dependencies)
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}
        score_penalty = sum(w * (sev_summary[k] + dep_sev[k]) for k, w in weights.items())
        security_score = max(0, min(100, 100 - score_penalty))

        # Letter grade
        if security_score >= 90:
            grade = "A"
        elif security_score >= 75:
            grade = "B"
        elif security_score >= 60:
            grade = "C"
        elif security_score >= 40:
            grade = "D"
        else:
            grade = "F"

        top_cwes = [
            {"cwe_id": cwe, "count": count}
            for cwe, count in sorted(cwe_counter.items(), key=lambda x: x[1], reverse=True)
        ]

        top_cves = sorted(
            list(cve_map.values()),
            key=lambda x: len(x["files"]),
            reverse=True
        )

        return ProjectScanResult(
            project_name=name,
            source_type="directory",
            source_path=str(base_dir),
            scan_start_time=start_iso,
            scan_duration_sec=round(time.time() - start_time, 2),
            total_files_found=total_found,
            total_files_scanned=len(file_results),
            total_files_skipped=total_found - len(file_results),
            total_lines_of_code=total_loc,
            total_vulnerabilities=total_vulns,
            severity_counts=sev_summary,
            clean_files_count=clean_count,
            vulnerable_files_count=vuln_count,
            false_positives_filtered=fp_count,
            security_score=security_score,
            security_grade=grade,
            top_cwes=top_cwes,
            top_cves=top_cves,
            files=file_results,
            skipped_unsupported=skipped,
            unresolved_count=unresolved_count,
            unresolved_files_count=unresolved_files,
            incomplete_files_count=incomplete_files,
            dependencies=dependencies,
            dependency_severity_counts=dep_sev,
        )

    def _scan_dependencies(self, base_dir: Path) -> Dict[str, Any]:
        self._emit("dependencies", status="running")
        try:
            deps = scan_dependencies(base_dir, skip_dir=self._should_ignore_dir,
                                     is_excluded=self._is_excluded)
        except Exception as e:
            deps = {"source": "OSV.dev", "manifests": [], "packages_checked": 0, "vulnerable": [],
                    "unpinned": [], "errors": [f"dependency scan failed: {e}"]}
        self._emit("dependencies", status="done", vulnerable=len(deps["vulnerable"]))
        return deps

    def scan_git_repo(
        self,
        repo_url: str,
        branch: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str, Optional[FileScanResult]], None]] = None,
    ) -> ProjectScanResult:
        """Clone a remote Git repository into a temporary folder and scan it."""
        temp_dir = tempfile.mkdtemp(prefix="nvd_scan_repo_")
        try:
            print(f"Cloning {repo_url} into temporary directory...")
            self._emit("clone", status="running", repo=repo_url)
            ok = clone_git_repo(repo_url, temp_dir, branch=branch)
            if not ok:
                self._emit("clone", status="failed", repo=repo_url)
                raise RuntimeError(f"Failed to clone git repository: {repo_url}")
            self._emit("clone", status="done", repo=repo_url)

            repo_name = repo_url.rstrip("/").split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]

            result = self.scan_directory(
                directory_path=temp_dir,
                project_name=repo_name,
                progress_callback=progress_callback,
            )
            result.source_type = "git_repo"
            result.source_path = repo_url
            return result
        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    def scan_zip(
        self,
        zip_path: str,
        progress_callback: Optional[Callable[[int, int, str, Optional[FileScanResult]], None]] = None,
    ) -> ProjectScanResult:
        """Extract a ZIP archive of a project to a temporary folder and scan it."""
        temp_dir = tempfile.mkdtemp(prefix="nvd_scan_zip_")
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)

            zip_name = Path(zip_path).stem
            result = self.scan_directory(
                directory_path=temp_dir,
                project_name=zip_name,
                progress_callback=progress_callback,
            )
            result.source_type = "zip"
            result.source_path = zip_path
            return result
        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass


# ─── Multi-Format Project Report Formatter ───────────────────

class ProjectReportFormatter:
    """Formats ProjectScanResult into Terminal, JSON, Markdown, and HTML reports."""

    @staticmethod
    def format_terminal(result: ProjectScanResult) -> str:
        sep = "═" * 78
        sub_sep = "─" * 78
        lines = []

        lines.append(f"\n{sep}")
        lines.append(f"  🛡️  PROJECT VULNERABILITY AUDIT REPORT")
        lines.append(f"{sep}")
        lines.append(f"  Project:        {result.project_name}")
        lines.append(f"  Source:         [{result.source_type.upper()}] {result.source_path}")
        lines.append(f"  Timestamp:      {result.scan_start_time}")
        lines.append(f"  Scan Duration:  {result.scan_duration_sec}s")
        lines.append(f"  Files Scanned:  {result.total_files_scanned} ({result.total_lines_of_code} total lines)")
        if result.skipped_unsupported:
            lines.append("  Not analysed:   " + ", ".join(
                f"{n} {lang}" for lang, n in result.skipped_unsupported.items()) + " (unsupported language)")
        lines.append(f"  Security Score: {result.security_score}/100 [Grade: {result.security_grade}]")
        lines.append(sub_sep)

        # Severity breakdown
        sc = result.severity_counts
        lines.append(
            f"  Vulnerabilities Found: {result.total_vulnerabilities} "
            f"(🔴 CRITICAL: {sc.get('CRITICAL', 0)} | "
            f"🟠 HIGH: {sc.get('HIGH', 0)} | "
            f"🟡 MEDIUM: {sc.get('MEDIUM', 0)} | "
            f"🟢 LOW: {sc.get('LOW', 0)})"
        )
        lines.append(
            f"  Status Summary:        "
            f"{result.vulnerable_files_count} Vulnerable Files | "
            f"{result.unresolved_files_count} Need Review | "
            f"{result.incomplete_files_count} Not Analysed | "
            f"{result.clean_files_count} Clean Files | "
            f"{result.false_positives_filtered} False Positives Filtered"
        )
        if result.dependencies:
            vuln = result.dependencies.get("vulnerable", [])
            ds = result.dependency_severity_counts
            lines.append(
                f"  Dependencies:          {sum(1 for p in vuln if not p['dev'])} vulnerable runtime "
                f"(🔴 {ds.get('CRITICAL', 0)} | 🟠 {ds.get('HIGH', 0)} | 🟡 {ds.get('MEDIUM', 0)} | "
                f"🟢 {ds.get('LOW', 0)}), {sum(1 for p in vuln if p['dev'])} dev-only, "
                f"{result.dependencies.get('packages_checked', 0)} checked via {result.dependencies.get('source')}"
            )
        lines.append(sep)

        review = [f for f in result.files if f.status in ("unresolved", "incomplete")]
        if review:
            lines.append("\n┌─ NEEDS MANUAL REVIEW " + "─" * 55)
            for f in review:
                what = (f"{len(f.needs_context)} unresolved finding(s)" if f.status == "unresolved"
                        else "not analysed: " + "; ".join(str(e.get("error")) for e in f.errors[:2]))
                lines.append(f"│ 📄 {f.relative_path} ({f.language}) — {what}")
            lines.append("└" + "─" * 76)

        deps = result.dependencies or {}
        runtime = [p for p in deps.get("vulnerable", []) if not p["dev"]]
        if runtime:
            lines.append(f"\n{sub_sep}")
            lines.append("  VULNERABLE DEPENDENCIES (runtime)")
            lines.append(sub_sep)
            for p in runtime:
                top = p["advisories"][0]
                lines.append(f"  • [{p['severity']:8}] {p['name']} {p['version']} — {len(p['advisories'])} advisories, "
                             f"upgrade to {p['fixed_version'] or 'n/a'} ({top['id']}: {top['summary'][:60]})")
        if deps.get("errors"):
            lines.append("  ⚠️  Dependency check: " + "; ".join(deps["errors"][:3]))

        # Vulnerable files table
        vulnerable_files = [f for f in result.files if not f.is_clean and f.findings_count > 0]
        if vulnerable_files:
            lines.append("\n┌─ VULNERABLE FILES SUMMARY " + "─" * 50)
            for f in vulnerable_files:
                sev_str = ", ".join([f"{k}: {v}" for k, v in f.severity_breakdown.items() if v > 0])
                lines.append(f"│ 📄 {f.relative_path} ({f.language}) — {f.findings_count} finding(s) [{sev_str}]")
                for finding in f.validated_findings:
                    s = finding.get("severity", "UNKNOWN")
                    cat = finding.get("category", "Unknown")
                    cwe = ", ".join(finding.get("cwe_ids", []))
                    cwe_str = f" ({cwe})" if cwe else ""
                    lines.append(f"│    • [{s:8}] {cat}{cwe_str}")
                    if finding.get("reasoning"):
                        lines.append(f"│      Reason: {finding['reasoning']}")
                lines.append("│")
            lines.append("└" + "─" * 76)
        else:
            lines.append("\n  ✅ No vulnerabilities confirmed across any scanned files in this project!\n")

        # Top CWEs
        if result.top_cwes:
            lines.append(f"\n{sub_sep}")
            lines.append("  TOP IDENTIFIED WEAKNESS TYPES (CWE)")
            lines.append(sub_sep)
            for cwe_info in result.top_cwes[:6]:
                lines.append(f"  • {cwe_info['cwe_id']:<10} — {cwe_info['count']} occurrence(s)")

        # Matched CVEs
        if result.top_cves:
            lines.append(f"\n{sub_sep}")
            lines.append("  MATCHED NVD THREAT INTELLIGENCE (CVEs)")
            lines.append(sub_sep)
            for cve in result.top_cves[:5]:
                files_str = ", ".join(cve["files"][:3])
                if len(cve["files"]) > 3:
                    files_str += f" (+{len(cve['files']) - 3} more)"
                lines.append(f"  • [{cve['severity']:8}] {cve['cve_id']} — Affected: {files_str}")
                lines.append(f"    {cve['description'][:110]}...")

        # Actionable Advisories
        advisories_found = []
        for f in vulnerable_files:
            for adv in f.advisories:
                advisories_found.append((f.relative_path, adv))

        if advisories_found:
            lines.append(f"\n{sub_sep}")
            lines.append("  PRIORITY REMEDIATION ADVICE")
            lines.append(sub_sep)
            for file_path, adv in advisories_found[:5]:
                lines.append(f"\n  [{adv.get('category', 'Fix')}] in {file_path}")
                lines.append(f"  Fix: {adv.get('fix_description', '')}")
                if adv.get("fixed_code"):
                    lines.append("  Suggested Code:")
                    for line in adv["fixed_code"].splitlines()[:5]:
                        lines.append(f"    {line}")
                if adv.get("libraries"):
                    lines.append(f"  Recommended Library: {', '.join(adv['libraries'])}")

        lines.append(f"\n{sep}\n")
        return "\n".join(lines)

    @staticmethod
    def _dependency_markdown(deps: Dict[str, Any]) -> List[str]:
        if not deps:
            return []
        md = ["## 📦 Dependencies\n",
              f"{deps['packages_checked']} pinned package(s) in {len(deps['manifests'])} manifest(s) checked "
              f"against {deps['source']}. These versions have known advisories; whether the code reaches the "
              f"vulnerable feature is not analysed. Dev-only packages are listed but not scored.\n"]
        if deps.get("vulnerable"):
            md.append("| Package | Version | Scope | Severity | Advisories | Upgrade to | Top advisory |")
            md.append("|---|---|---|---|---|---|---|")
            for p in deps["vulnerable"]:
                top = p["advisories"][0]
                md.append(f"| {p['name']} ({p['ecosystem']}) | {p['version']} | {'dev' if p['dev'] else 'runtime'} "
                          f"| **{p['severity']}** | {len(p['advisories'])} | {p['fixed_version'] or 'no fix yet'} "
                          f"| [{top['id']}]({top['url']}) {top['summary'].replace('|', chr(92) + '|')} |")
            md.append("")
        if deps.get("unpinned"):
            md.append("- **Unpinned (not checked):** " + ", ".join(
                f"{u['name']} ({u['manifest']})" for u in deps["unpinned"]))
        if deps.get("errors"):
            md.append("- **Warnings:** " + "; ".join(deps["errors"]))
        md.append("")
        return md

    @staticmethod
    def format_markdown(result: ProjectScanResult) -> str:
        md = []
        md.append(f"# 🛡️ Vulnerability Audit Report — {result.project_name}\n")
        md.append(f"- **Source:** `{result.source_path}` ({result.source_type})")
        md.append(f"- **Scan Date:** {result.scan_start_time}")
        md.append(f"- **Duration:** {result.scan_duration_sec} seconds")
        md.append(f"- **Total Files Scanned:** {result.total_files_scanned} ({result.total_lines_of_code:,} LOC)")
        md.append(f"- **Security Score:** **{result.security_score}/100** (Grade: `{result.security_grade}`)\n")

        # Summary Table
        sc = result.severity_counts
        md.append("## 📊 Executive Summary\n")
        md.append("| Metric | Value |")
        md.append("|---|---|")
        md.append(f"| **Total Confirmed Vulnerabilities** | **{result.total_vulnerabilities}** |")
        md.append(f"| 🔴 Critical | {sc.get('CRITICAL', 0)} |")
        md.append(f"| 🟠 High | {sc.get('HIGH', 0)} |")
        md.append(f"| 🟡 Medium | {sc.get('MEDIUM', 0)} |")
        md.append(f"| 🟢 Low | {sc.get('LOW', 0)} |")
        md.append(f"| Vulnerable Files | {result.vulnerable_files_count} |")
        md.append(f"| Files Needing Manual Review | {result.unresolved_files_count} |")
        md.append(f"| Files Not Analysed | {result.incomplete_files_count} |")
        md.append(f"| Clean Files | {result.clean_files_count} |")
        if result.dependencies:
            vuln = result.dependencies.get("vulnerable", [])
            md.append(f"| Vulnerable Runtime Dependencies | {sum(1 for p in vuln if not p['dev'])} |")
            md.append(f"| Vulnerable Dev Dependencies (not scored) | {sum(1 for p in vuln if p['dev'])} |")
        md.append(f"| Filtered False Positives | {result.false_positives_filtered} |\n")

        # Vulnerable Files Section
        vulnerable_files = [f for f in result.files if not f.is_clean and f.findings_count > 0]
        if vulnerable_files:
            md.append("## 🚨 Vulnerable Files Detail\n")
            for f in vulnerable_files:
                md.append(f"### 📄 `{f.relative_path}` ({f.language.upper()})")
                md.append(f"- **Findings:** {f.findings_count}")
                for idx, finding in enumerate(f.validated_findings):
                    sev = finding.get("severity", "UNKNOWN")
                    cat = finding.get("category", "Unknown")
                    cwe = ", ".join(finding.get("cwe_ids", []))
                    md.append(f"\n#### [{sev}] {cat} {f'({cwe})' if cwe else ''}")
                    md.append(f"- **Reasoning:** {finding.get('reasoning', '')}")

                    # Explanation
                    if idx < len(f.explanations):
                        ex = f.explanations[idx]
                        if ex.get("what_is_wrong"):
                            md.append(f"- **Problem:** {ex['what_is_wrong']}")
                        if ex.get("why_dangerous"):
                            md.append(f"- **Risk:** {ex['why_dangerous']}")
                        if ex.get("attack_scenario"):
                            md.append(f"- **Attack Scenario:** {ex['attack_scenario']}")

                    # Advisory
                    if idx < len(f.advisories):
                        adv = f.advisories[idx]
                        if adv.get("fix_description"):
                            md.append(f"- **Remediation:** {adv['fix_description']}")
                        if adv.get("fixed_code"):
                            md.append(f"```\n{adv['fixed_code']}\n```")
                        if adv.get("fix_warning"):
                            md.append(f"- **Fix Check:** {adv['fix_warning']}")
                md.append("\n---\n")
        elif not any(f.status in ("unresolved", "incomplete") for f in result.files):
            md.append("## ✅ All Scanned Files Are Clean\nNo security vulnerabilities were confirmed.\n")

        # Files without a verdict: never silently counted as clean
        review = [f for f in result.files if f.status in ("unresolved", "incomplete")]
        if review:
            md.append("## ⚠️ Needs Manual Review\n")
            for f in review:
                md.append(f"### 📄 `{f.relative_path}` ({f.language.upper()})")
                if f.status == "incomplete":
                    md.append("- **Not analysed to a verdict.**")
                for u in f.needs_context:
                    md.append(f"- **{u.get('category', 'Finding')}** [{u.get('severity', 'UNKNOWN')}]: "
                              f"{u.get('reasoning', '')}")
                if f.errors:
                    md.append("- **Warnings:** " + "; ".join(f"{e.get('agent')}: {e.get('error')}" for e in f.errors))
                md.append("")

        md += ProjectReportFormatter._dependency_markdown(result.dependencies)

        # Top Matched CVEs
        if result.top_cves:
            md.append("## 🔍 Matched NVD Threat Intelligence (CVEs)\n")
            md.append("| CVE ID | Severity | Affected Files | Description |")
            md.append("|---|---|---|---|")
            for cve in result.top_cves[:10]:
                files_str = ", ".join(cve["files"][:2])
                if len(cve["files"]) > 2:
                    files_str += f" (+{len(cve['files']) - 2})"
                desc = cve["description"][:120].replace("|", "\\|") + "..."
                md.append(f"| `{cve['cve_id']}` | **{cve['severity']}** | `{files_str}` | {desc} |")
            md.append("\n")

        return "\n".join(md)

    @staticmethod
    def format_html(result: ProjectScanResult) -> str:
        """Generate standalone HTML report."""
        # "</" would end the inline <script> early; scanned code and LLM text are untrusted.
        data_json = result.to_json().replace("</", "<\\/")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Audit — {result.project_name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --panel-hover: #1f242c; --border: #30363d;
    --text: #c9d1d9; --text-bright: #f0f6fc; --muted: #8b949e; --accent: #58a6ff;
    --critical: #f85149; --high: #ff9d5c; --medium: #f0d264; --low: #7ee787;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text); font-family: var(--sans); line-height: 1.5; }}
  .container {{ max-width: 1140px; margin: 0 auto; padding: 32px 24px; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 24px; }}
  h1 {{ margin: 0 0 8px; font-size: 26px; color: var(--text-bright); }}
  .meta {{ font-size: 13px; color: var(--muted); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .badge.CRITICAL {{ background: rgba(248,81,73,0.2); color: var(--critical); border: 1px solid var(--critical); }}
  .badge.HIGH {{ background: rgba(255,157,92,0.2); color: var(--high); border: 1px solid var(--high); }}
  .badge.MEDIUM {{ background: rgba(240,210,100,0.2); color: var(--medium); border: 1px solid var(--medium); }}
  .badge.LOW {{ background: rgba(126,231,135,0.2); color: var(--low); border: 1px solid var(--low); }}
  .score-card {{ text-align: center; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 24px; min-width: 140px; }}
  .score-num {{ font-size: 36px; font-weight: 800; color: var(--text-bright); }}
  .score-grade {{ font-size: 14px; font-weight: 600; color: var(--accent); }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .kpi-box {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }}
  .kpi-val {{ font-size: 24px; font-weight: 700; color: var(--text-bright); margin-bottom: 4px; }}
  .kpi-lbl {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; }}
  .card-header {{ padding: 14px 18px; background: #1c2128; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
  .card-title {{ font-family: var(--mono); font-size: 14px; font-weight: 600; color: var(--text-bright); }}
  .card-body {{ padding: 20px; }}
  pre.code {{ background: #0a0d12; border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: var(--mono); font-size: 13px; overflow-x: auto; white-space: pre-wrap; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ {result.project_name} — Security Audit</h1>
      <div class="meta">
        <strong>Source:</strong> {result.source_path} ({result.source_type}) &bull;
        <strong>Scanned:</strong> {result.scan_start_time} ({result.scan_duration_sec}s) &bull;
        <strong>LOC:</strong> {result.total_lines_of_code:,}
      </div>
    </div>
    <div class="score-card">
      <div class="score-num">{result.security_score}</div>
      <div class="score-grade">GRADE: {result.security_grade}</div>
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-box"><div class="kpi-val">{result.total_files_scanned}</div><div class="kpi-lbl">Files Scanned</div></div>
    <div class="kpi-box"><div class="kpi-val" style="color:var(--critical);">{result.severity_counts.get('CRITICAL', 0)}</div><div class="kpi-lbl">Critical</div></div>
    <div class="kpi-box"><div class="kpi-val" style="color:var(--high);">{result.severity_counts.get('HIGH', 0)}</div><div class="kpi-lbl">High</div></div>
    <div class="kpi-box"><div class="kpi-val" style="color:var(--medium);">{result.severity_counts.get('MEDIUM', 0)}</div><div class="kpi-lbl">Medium</div></div>
    <div class="kpi-box"><div class="kpi-val" style="color:var(--medium);">{result.unresolved_files_count + result.incomplete_files_count}</div><div class="kpi-lbl">Need Review</div></div>
    <div class="kpi-box"><div class="kpi-val" style="color:var(--low);">{result.clean_files_count}</div><div class="kpi-lbl">Clean Files</div></div>
    <div class="kpi-box"><div class="kpi-val" style="color:var(--high);">{sum(1 for p in (result.dependencies or {}).get('vulnerable', []) if not p['dev'])}</div><div class="kpi-lbl">Vulnerable Deps</div></div>
  </div>

  <h2>🚨 Scanned Files Analysis</h2>
  <div id="fileCards"></div>
  <div id="depCards"></div>
</div>

<script>
const reportData = {data_json};
const container = document.getElementById('fileCards');
// Everything below comes from scanned code or model output: escape before HTML.
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({{'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}}[c]));
const sevClass = s => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s) ? s : 'LOW';
const line = (label, text, color) => text ? `<div style="font-size:13px; margin-bottom:6px;${{color ? ' color:' + color + ';' : ''}}"><strong>${{label}}:</strong> ${{esc(text)}}</div>` : '';

reportData.files.forEach(f => {{
  const card = document.createElement('div');
  card.className = 'card';
  const unresolved = f.needs_context || [];
  let badgeHtml = '<span class="badge LOW">Clean</span>';
  if (f.status === 'incomplete') badgeHtml = '<span class="badge HIGH">Not analysed</span>';
  if (f.findings_count > 0) badgeHtml = '<span class="badge CRITICAL">' + f.findings_count + ' Vulnerabilities</span>';
  if (unresolved.length) badgeHtml += ' <span class="badge MEDIUM">' + unresolved.length + ' Unresolved</span>';

  let findingsHtml = '';
  (f.validated_findings || []).forEach((v, idx) => {{
    const ex = (f.explanations && f.explanations[idx]) || {{}};
    const adv = (f.advisories && f.advisories[idx]) || {{}};
    findingsHtml += `
      <div style="margin-bottom:16px; padding:12px; background:#1c2128; border-radius:8px;">
        <div style="margin-bottom:8px;">
          <span class="badge ${{sevClass(v.severity)}}">${{esc(v.severity || 'UNKNOWN')}}</span>
          <strong style="margin-left:8px; color:var(--text-bright);">${{esc(v.category || 'Finding')}}</strong>
          ${{v.cwe_ids ? '<span style="color:var(--muted); font-size:12px; margin-left:8px;">CWE: ' + esc(v.cwe_ids.join(', ')) + '</span>' : ''}}
        </div>
        ${{line('Why flagged', v.reasoning || ' ')}}
        ${{line('Problem', ex.what_is_wrong)}}
        ${{line('Risk', ex.why_dangerous)}}
        ${{line('Fix', adv.fix_description, 'var(--low)')}}
        ${{adv.fixed_code ? '<pre class="code">' + esc(adv.fixed_code) + '</pre>' : ''}}
        ${{line('Fix check', adv.fix_warning, 'var(--high)')}}
      </div>
    `;
  }});
  if (unresolved.length) {{
    findingsHtml += '<div style="font-size:13px; color:var(--medium); margin-bottom:8px;"><strong>Needs manual review:</strong> ' +
      unresolved.map(u => esc((u.category || 'Finding') + ': ' + (u.reasoning || ''))).join(' | ') + '</div>';
  }}
  if (f.errors && f.errors.length) {{
    findingsHtml += line('Warnings', f.errors.map(e => e.agent + ': ' + e.error).join('; '), 'var(--critical)');
  }}
  if (!findingsHtml) {{
    findingsHtml = '<div style="color:var(--low);">✓ No security vulnerabilities confirmed in this file.</div>';
  }}

  card.innerHTML = `
    <div class="card-header">
      <span class="card-title">${{esc(f.relative_path)}} (${{esc(f.language)}})</span>
      <div>${{badgeHtml}}</div>
    </div>
    <div class="card-body">
      ${{findingsHtml}}
    </div>
  `;
  container.appendChild(card);
}});

const deps = reportData.dependencies || {{}};
if (deps.source) {{
  const vuln = deps.vulnerable || [];
  let html = `<h2>📦 Dependencies</h2><p style="color:var(--muted); font-size:13px;">${{deps.packages_checked}} pinned package(s) checked against ${{esc(deps.source)}}. ` +
    'Known-vulnerable versions; reachability from the code is not analysed. Dev-only packages are not scored.' +
    ((deps.errors || []).length ? ' Warnings: ' + esc(deps.errors.join('; ')) : '') + '</p>';
  vuln.forEach(p => {{
    html += `<div class="card"><div class="card-header">
        <span class="card-title">${{esc(p.name)}} ${{esc(p.version)}} (${{esc(p.ecosystem)}}${{p.dev ? ', dev' : ''}})</span>
        <div><span class="badge ${{sevClass(p.severity)}}">${{esc(p.severity)}}</span></div></div>
      <div class="card-body" style="font-size:13px;">
        <div style="margin-bottom:8px;">${{p.advisories.length}} advisories · upgrade to ${{esc(p.fixed_version || 'n/a')}} · ${{esc(p.manifest)}}</div>
        ${{p.advisories.map(a => `<div style="margin-bottom:4px;"><span class="badge ${{sevClass(a.severity)}}">${{esc(a.severity)}}</span>
          <a href="${{esc(a.url)}}" style="color:#93c5fd;">${{esc(a.id)}}</a> ${{esc(a.cves.join(', '))}} ${{esc(a.summary)}}</div>`).join('')}}
      </div></div>`;
  }});
  document.getElementById('depCards').innerHTML = html;
}}
</script>
</body>
</html>"""

# ─── CLI ─────────────────────────────────────────────────────

def main():
    import argparse

    p = argparse.ArgumentParser(description="NVD RAG project vulnerability scanner")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--dir", help="Local project directory")
    src.add_argument("--repo", help="Git repository URL")
    src.add_argument("--zip", help="Path to a ZIP archive")
    p.add_argument("--branch", help="Git branch (with --repo)")
    p.add_argument("--format", choices=["terminal", "json", "markdown", "html"], default="terminal")
    p.add_argument("--output", "-o", help="Write report to this file instead of stdout")
    p.add_argument("--max-files", type=int, help="Limit number of files scanned")
    p.add_argument("--top-k", type=int, default=5)
    p.add_argument("--threshold", type=float, default=0.3)
    p.add_argument("--exclude", action="append", default=[],
                   help="Project-relative path to skip, e.g. finetune/data (repeatable)")
    p.add_argument("--no-cpg", action="store_true",
                   help="Skip Joern; use tree-sitter per file")
    p.add_argument("--no-deps", action="store_true",
                   help="Skip the dependency check (sends package names/versions to OSV.dev)")
    args = p.parse_args()

    scanner = ProjectScanner(
        top_k=args.top_k,
        score_threshold=args.threshold,
        max_files=args.max_files,
        exclude_paths=args.exclude,
        use_cpg=not args.no_cpg,
        dependency_scan=not args.no_deps,
    )

    def progress(idx, total, path, res):
        if res is None:
            print(f"[{idx}/{total}] Scanning {path} ...", file=sys.stderr)

    if args.dir:
        result = scanner.scan_directory(args.dir, progress_callback=progress)
    elif args.repo:
        result = scanner.scan_git_repo(args.repo, branch=args.branch, progress_callback=progress)
    else:
        result = scanner.scan_zip(args.zip, progress_callback=progress)

    fmt = ProjectReportFormatter
    report = {
        "terminal": fmt.format_terminal,
        "json": lambda r: r.to_json(),
        "markdown": fmt.format_markdown,
        "html": fmt.format_html,
    }[args.format](result)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()