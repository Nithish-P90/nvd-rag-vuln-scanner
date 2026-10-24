# NVD RAG Vulnerability Analysis & Project Scanner

Scans source code (a file, folder, ZIP, or Git repo) for vulnerabilities. It retrieves matching CVEs from a
Qdrant vector database built from the NVD, validates findings with a fine-tuned local LLM (Ollama), and
produces JSON / Markdown / HTML audit reports.

## 0. Setup (first time)

Prerequisites: Python 3.10+, [Docker](https://www.docker.com/), [Ollama](https://ollama.com/), and a free
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key).

```bash
git clone <this-repo-url> && cd <repo-folder>
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example ingestion/.env                         # then put your NVD_API_KEY in it
```

The repo does **not** include the Qdrant database (1.3 GB) or the merged fine-tuned model (6 GB); rebuild them:

```bash
# 1. Start Qdrant, then ingest CVEs from the NVD into it (takes a while)
docker-compose up -d
python ingestion/ingest_nvd.py

# 2. Create the fine-tuned validation model for Ollama
#    The LoRA adapter is in validation_agent_lora/. Merge it into the base model (CPU is fine):
pip install torch transformers peft
python merge_lora.py
ollama create validation-agent -f Modelfile
#    (Alternatively, retrain from scratch on a GPU: python finetune.py)

# 3. Pull the other Ollama models the pipeline uses
ollama pull llama3.2
ollama pull nomic-embed-text
```

Optional: install [Joern](https://joern.io) and set `JOERN_HOME` for code-property-graph analysis; without it
the scanner falls back to Docker (`ghcr.io/joernio/joern`) and then to tree-sitter.

---

## 1. Start Vector Database (Qdrant) & Check Status
```bash
docker-compose up -d        # start Qdrant
docker-compose down         # stop it

curl http://localhost:6333/collections/nvd_threats_v2  # check stored CVE embeddings
# Qdrant local UI: http://localhost:6333/dashboard
```

---

## 2. Scanning Whole Projects, Repositories, & Files

```bash
# Scan all source files in a project folder
python orchestrator.py path/to/project_folder/

# Custom output reports (JSON, Markdown, HTML)
python orchestrator.py path/to/project/ --output-json report.json --output-html report.html --output-md report.md

# Filter by extension / limit files
python orchestrator.py path/to/project/ --ext .c,.py,.js --max-files 50

# Clone and scan a remote Git repository
python orchestrator.py --repo https://github.com/org/project-repo.git
python orchestrator.py --repo https://github.com/org/project-repo.git --branch main --output-html audit_report.html

# Scan a ZIP archive / a single file
python orchestrator.py path/to/project.zip
python orchestrator.py path/to/file.c

# Built-in examples
python orchestrator.py --builtin     # all 6 built-in test examples
python orchestrator.py               # default test (buffer overflow snippet)

# Tune retrieval parameters
python orchestrator.py path/to/file.c --top-k 10 --threshold 0.4
```

---

## 3. Interactive Web UI Dashboard
```bash
cd webui
python server.py
# (or) uvicorn server:app --host 0.0.0.0 --port 8000
```
Open **http://localhost:8000** to drag & drop folders/files, upload ZIPs, scan a local path or a Git URL,
view security scores, severity distribution, CVE matches and suggested fixes, and export JSON / Markdown reports.

---

## 4. Fine-Tuning & Evaluation Pipeline
```bash
python build_dataset.py --verify-only      # check datasets are downloaded
python build_dataset.py --no-llm           # fast first pass
python build_dataset.py                    # full build with LLM reasoning
python finetune.py                         # fine-tune (needs a GPU + unsloth)
ollama create validation-agent -f Modelfile
python evaluate.py                         # compare against baseline_results.json / finetuned_results.json
```

## 5. Tests
```bash
python -m pytest tests/
```

## Layout
| Path | Purpose |
|---|---|
| `orchestrator.py` | CLI entry point (delegates to `agents/orchestrator2.py`) |
| `agents/` | Scanner, dependency scanner, validation guardrails, risk evidence, Joern CPG integration |
| `rag/` | NVD retrieval (Qdrant + embeddings), CVSS lookup |
| `ingestion/` | NVD ingestion and Qdrant reindexing |
| `webui/` | FastAPI dashboard |
| `validation_agent_lora/` | Fine-tuned LoRA adapter (Llama-3.2-3B-Instruct base) |
| `reports/` | Example scan output |
| `tests/` | Unit tests and a seeded-vulnerability benchmark |
