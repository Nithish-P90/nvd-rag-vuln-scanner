#!/usr/bin/env python3
# orchestrator.py
"""
Root entrypoint for the NVD RAG Vulnerability Analysis Pipeline & Project Scanner.

Usage:
    # Scan a whole project directory
    python orchestrator.py path/to/project_folder/

    # Scan a remote Git repository
    python orchestrator.py --repo https://github.com/org/repo.git

    # Scan a ZIP archive
    python orchestrator.py path/to/project.zip

    # Scan a single file
    python orchestrator.py path/to/file.c

    # Run built-in vulnerability test examples
    python orchestrator.py --builtin

    # Generate JSON, Markdown, and HTML reports
    python orchestrator.py path/to/project/ --output-json report.json --output-html report.html --output-md report.md
"""

import sys
from pathlib import Path

# Add agents and rag to sys.path
_ROOT = Path(__file__).resolve().parent
_AGENTS_DIR = _ROOT / "agents"
_RAG_DIR = _ROOT / "rag"

if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))
if str(_RAG_DIR) not in sys.path:
    sys.path.insert(0, str(_RAG_DIR))

from orchestrator2 import main

if __name__ == "__main__":
    main()
