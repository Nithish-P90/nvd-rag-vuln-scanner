# rag/ollama_retry.py
"""
Retry wrapper for Ollama calls.

A dropped connection (Ollama restarted, model being swapped in, socket reset
under concurrent load: WinError 10054 / ConnectionResetError) or a 5xx from
the server is transient; retrying a few times with backoff turns it into a
short delay instead of a failed agent step.
"""

import time

import httpx
import ollama

ATTEMPTS = 4
BACKOFF  = (1, 3, 8)        # seconds before attempts 2, 3, 4


def _transient(e: Exception) -> bool:
    if isinstance(e, (ConnectionError, httpx.TransportError)):
        return True
    if isinstance(e, ollama.ResponseError):
        return getattr(e, "status_code", 0) >= 500
    return False


def with_retry(fn, *args, **kwargs):
    """fn(*args, **kwargs), retried on transient connection/server errors."""
    for attempt in range(ATTEMPTS):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if attempt == ATTEMPTS - 1 or not _transient(e):
                raise
            wait = BACKOFF[min(attempt, len(BACKOFF) - 1)]
            print(f"    [ollama] {type(e).__name__}: {str(e)[:100]} — retrying in {wait}s "
                  f"({attempt + 2}/{ATTEMPTS})")
            time.sleep(wait)
