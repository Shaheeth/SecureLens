"""
Thin wrapper around a local Ollama server. All AI explanation/fix
generation runs against a locally-hosted model (e.g. llama3.1:8b) — no
source code is sent to a third-party cloud API, which matters both for
privacy of potentially proprietary code and for cost control.
"""
from __future__ import annotations

import os
import requests

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
REQUEST_TIMEOUT = 90


class OllamaUnavailableError(Exception):
    pass


def is_ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
        return r.status_code == 200
    except requests.RequestException:
        return False


def generate(prompt: str, system: str = "", temperature: float = 0.2, max_tokens: int = 800) -> str:
    """
    Calls Ollama's /api/generate endpoint (non-streaming) and returns the
    text response. Raises OllamaUnavailableError if the server can't be
    reached, so callers can fall back to a rule-based explanation.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.RequestException as e:
        raise OllamaUnavailableError(f"Could not reach Ollama at {OLLAMA_HOST}: {e}") from e
