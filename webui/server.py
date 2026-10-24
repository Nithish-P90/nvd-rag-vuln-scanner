# webui/server.py
"""
FastAPI backend for Vulnerability Analysis & Project Scanner UI.

Wraps:
  - agents.orchestrator2.VulnerabilityOrchestrator
  - agents.project_scanner.ProjectScanner

Scans run as background jobs so the UI can show live pipeline progress:
  POST /api/scan/repo     {repo_url, branch?, max_files?}  -> {job_id}
  POST /api/scan/upload   multipart files (folder upload)  -> {job_id}
  GET  /api/jobs/{job_id}                                  -> progress (+ result when done)

Also:
  POST /api/analyze       one-shot analysis of uploaded snippets (no job)
  GET  /api/examples      built-in example snippets

Run:
    python server.py
    (or) uvicorn server:app --host 0.0.0.0 --port 8000
"""

import sys
import time
import uuid
import shutil
import tempfile
import threading
import traceback
from pathlib import Path, PurePosixPath
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

_AGENTS_DIR = Path(__file__).resolve().parent.parent / "agents"
_RAG_DIR = Path(__file__).resolve().parent.parent / "rag"

if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))
if str(_RAG_DIR) not in sys.path:
    sys.path.insert(0, str(_RAG_DIR))

import orchestrator2 as pipeline
from project_scanner import ProjectScanner, MAX_FILE_BYTES

app = FastAPI(title="NVD RAG Vulnerability Analysis & Project Scanner")

_orchestrator = pipeline.VulnerabilityOrchestrator(top_k=5, score_threshold=0.3)


# ─── Scan jobs ───────────────────────────────────────────────

# Pipeline steps in display order: (key, label). Keys are the scanner's
# progress stages and the orchestrator's agent names.
STAGES = [
    ("clone",               "Clone repository"),
    ("discover",            "Discover source files"),
    ("cpg",                 "Build code property graph"),
    ("CPGAgent",            "Context extraction"),
    ("ForensicsAgent",      "Code forensics"),
    ("RAGQueryAgent",       "NVD similarity search"),
    ("CategorizationAgent", "Categorize & risk score"),
    ("ValidationAgent",     "Validation"),
    ("ExplainableAIAgent",  "Explainable report"),
    ("AdvisoryAgent",       "Advisory fixes"),
    ("report",              "Final report"),
]
_PIPELINE_AGENTS = {k for k, _ in STAGES[3:10]}

_jobs: dict = {}
_jobs_lock = threading.Lock()
# One scan at a time: a scan already saturates Ollama with parallel requests.
_job_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scan-job")


class Job:
    def __init__(self, kind: str, source: str):
        self.id       = uuid.uuid4().hex[:12]
        self.kind     = kind
        self.source   = source
        self.status   = "queued"          # queued | running | done | failed
        self.created  = time.time()
        self.started: Optional[float]  = None
        self.finished: Optional[float] = None
        self.error: Optional[str]      = None
        self.result: Optional[dict]    = None
        self.files_total = 0
        self.files_done  = 0
        self.stages = {k: {"key": k, "label": label, "status": "pending", "done": 0, "total": 0}
                       for k, label in STAGES}
        if kind != "repo":
            self.stages["clone"]["status"] = "skipped"
        self.lock = threading.Lock()

    def on_event(self, ev: dict):
        """ProjectScanner progress event -> stage state."""
        with self.lock:
            stage = ev.get("stage")
            if stage in ("clone", "discover", "cpg"):
                st = self.stages[stage]
                if ev.get("status") in ("running", "done", "failed", "skipped") \
                        and not (st["status"] == "skipped" and ev["status"] == "done"):
                    st["status"] = ev["status"]
                if stage == "discover" and ev.get("status") == "done":
                    self.files_total = ev.get("total", 0)
                    for k in _PIPELINE_AGENTS:
                        self.stages[k]["total"] = self.files_total
                if stage == "cpg" and "total" in ev and ev.get("total"):
                    st["done"], st["total"] = ev.get("done", 0), ev["total"]
            elif stage == "pipeline" and ev.get("agent") in _PIPELINE_AGENTS:
                st = self.stages[ev["agent"]]
                st["done"], st["total"] = ev.get("done", 0), ev.get("total", 0)
                st["status"] = "done" if st["done"] >= st["total"] else "running"
            elif stage == "files":
                self.files_done = ev.get("done", 0)

    def to_dict(self, with_result: bool = True) -> dict:
        with self.lock:
            now = self.finished or time.time()
            out = {
                "job_id":      self.id,
                "kind":        self.kind,
                "source":      self.source,
                "status":      self.status,
                "error":       self.error,
                "elapsed_sec": round(now - (self.started or now), 1),
                "files_total": self.files_total,
                "files_done":  self.files_done,
                "stages":      [dict(self.stages[k]) for k, _ in STAGES],
            }
            if with_result and self.status == "done":
                out["result"] = self.result
            return out


def _start_job(job: Job, work, cleanup_dir: Optional[str] = None) -> str:
    """Queue `work(scanner) -> ProjectScanResult` as a background job."""
    with _jobs_lock:
        _jobs[job.id] = job

    def run():
        job.status, job.started = "running", time.time()
        try:
            scanner = ProjectScanner(orchestrator=_orchestrator, on_event=job.on_event)
            result  = work(scanner)
            with job.lock:
                job.stages["report"]["status"] = "done"
                job.result = result.to_dict()
            job.status = "done"
        except Exception as e:
            traceback.print_exc()
            job.error, job.status = str(e), "failed"
            with job.lock:
                for st in job.stages.values():
                    if st["status"] == "running":
                        st["status"] = "failed"
        finally:
            job.finished = time.time()
            if cleanup_dir:
                shutil.rmtree(cleanup_dir, ignore_errors=True)

    _job_pool.submit(run)
    return job.id


# ─── Request models ──────────────────────────────────────────

class RepoScanRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    max_files: Optional[int] = 100


# ─── Routes ──────────────────────────────────────────────────

@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/examples")
def get_examples():
    """Return built-in code examples for testing."""
    return JSONResponse({"examples": pipeline.BUILTIN_EXAMPLES})


@app.post("/api/scan/repo")
def scan_git_repo(req: RepoScanRequest):
    """Clone and scan a remote Git repository (background job)."""
    url = req.repo_url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Repository URL is required")
    if not (url.startswith("https://") or url.startswith("http://") or url.startswith("git@")):
        raise HTTPException(status_code=400, detail="Enter an http(s) or git@ repository URL")

    def work(scanner: ProjectScanner):
        scanner.max_files = req.max_files
        return scanner.scan_git_repo(url, branch=req.branch or None)

    return {"job_id": _start_job(Job("repo", url), work)}


def _safe_relpath(name: str) -> Optional[PurePosixPath]:
    """Uploaded file name (may carry a folder path) -> safe relative path, or None."""
    parts = [p for p in PurePosixPath(name.replace("\\", "/")).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts) or ":" in parts[0] or parts[0].startswith("/"):
        return None
    return PurePosixPath(*parts)


@app.post("/api/scan/upload")
async def scan_upload(files: list[UploadFile] = File(...)):
    """Scan uploaded files / a whole uploaded folder as one project (background job)."""
    tmp = tempfile.mkdtemp(prefix="nvd_scan_upload_")
    root = Path(tmp).resolve()
    saved = 0
    try:
        for f in files:
            rel = _safe_relpath(f.filename or "")
            if rel is None:
                continue
            raw = await f.read()
            if len(raw) > MAX_FILE_BYTES:
                continue
            dst = (root / rel).resolve()
            if root not in dst.parents:
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw)
            saved += 1
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    if not saved:
        shutil.rmtree(tmp, ignore_errors=True)
        raise HTTPException(status_code=400, detail="No usable files in the upload")

    # A folder upload arrives as "folder/..."; name the project after it.
    tops = {(_safe_relpath(f.filename or "") or PurePosixPath("x")).parts[0] for f in files}
    name = tops.pop() if len(tops) == 1 and len(files) > 1 else "Uploaded files"

    def work(scanner: ProjectScanner):
        result = scanner.scan_directory(tmp, project_name=name)
        result.source_type = "upload"
        result.source_path = f"{saved} uploaded file(s)"
        return result

    return {"job_id": _start_job(Job("upload", name), work, cleanup_dir=tmp)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job")
    return JSONResponse(job.to_dict())


@app.post("/api/analyze")
async def analyze(files: list[UploadFile] = File(...)):
    """Analyze one or multiple uploaded source code files (synchronous, per file)."""
    results = []
    for f in files:
        raw = await f.read()
        if len(raw) > MAX_FILE_BYTES:
            results.append({"filename": f.filename,
                            "error": f"File too large ({len(raw)} bytes, max {MAX_FILE_BYTES}) — skipped."})
            continue
        try:
            code = raw.decode("utf-8")
        except UnicodeDecodeError:
            code = raw.decode("latin-1", errors="ignore")
        if not code.strip():
            results.append({"filename": f.filename, "error": "File is empty — skipped."})
            continue
        try:
            state = _orchestrator.run(code)
            results.append({"filename": f.filename, "state": state.to_dict()})
        except Exception as e:
            traceback.print_exc()
            results.append({"filename": f.filename, "error": f"Analysis error: {e}"})
    return JSONResponse({"results": results})


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
