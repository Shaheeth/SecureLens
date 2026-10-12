"""
AI-powered secure-code fix generator.

Given a Finding, asks the local LLM (grounded with RAG context) to produce
a corrected version of the vulnerable snippet, then hands it to the
orchestrator's `rescan_single_fix` to verify — via the *same static
analyzers*, not the LLM's own opinion — that the vulnerability category no
longer triggers on the fixed code. This keeps "is it actually fixed?" an
empirical, tool-verified question rather than trusting the model's claim.
"""
from __future__ import annotations

from backend.models import Finding
from rag.retriever import retrieve_context, format_context_for_prompt
from llm.ollama_client import generate, is_ollama_available, OllamaUnavailableError

SYSTEM_PROMPT = (
    "You are a secure coding assistant. Given a vulnerable code snippet "
    "and its security finding, rewrite ONLY that snippet to fix the "
    "specific vulnerability while preserving its original functionality "
    "and style as closely as possible. Follow the trusted reference "
    "context provided. Output ONLY the corrected code in a single code "
    "block — no prose, no explanation, no markdown outside the code block."
)

# Deterministic fallback fixes for when Ollama is unavailable — covers the
# most common categories with a safe, generic pattern so the "fix" feature
# still functions offline/without a local model pulled.
_FALLBACK_TEMPLATES = {
    "SQL Injection": (
        "# SecureLens AI fallback fix: use parameterized queries.\n"
        "# Replace the string-built query below with placeholders, e.g.:\n"
        "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
    ),
    "Command Injection": (
        "# SecureLens AI fallback fix: avoid shell=True; pass args as a list.\n"
        "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, check=True)"
    ),
    "Insecure Deserialization": (
        "# SecureLens AI fallback fix: use safe deserialization.\n"
        "import json\n"
        "data = json.loads(raw_data)  # instead of pickle.loads / yaml.load"
    ),
    "Weak Cryptography": (
        "# SecureLens AI fallback fix: use a modern password hash.\n"
        "import bcrypt\n"
        "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
    ),
    "Insecure Randomness": (
        "# SecureLens AI fallback fix: use a CSPRNG.\n"
        "import secrets\n"
        "token = secrets.token_urlsafe(32)"
    ),
}


def _build_prompt(finding: Finding, context_text: str) -> str:
    category = finding.category.value if hasattr(finding.category, "value") else finding.category
    return f"""Trusted reference context:
{context_text}

---
Vulnerability: {category}
Description: {finding.description}

Vulnerable code:
```
{finding.evidence}
```

Rewrite this snippet to fix the vulnerability. Output only the corrected code block.
"""


def _extract_code_block(text: str) -> str:
    if "```" in text:
        parts = text.split("```")
        # parts[1] is typically the code (possibly with a language tag on first line)
        code = parts[1]
        lines = code.splitlines()
        if lines and lines[0].strip().isalpha():
            lines = lines[1:]
        return "\n".join(lines).strip()
    return text.strip()


def generate_fix(finding: Finding) -> Finding:
    """Mutates and returns `finding` with `ai_fix` populated."""
    category = finding.category.value if hasattr(finding.category, "value") else finding.category
    contexts = retrieve_context(finding, top_k=3)
    context_text = format_context_for_prompt(contexts)

    if not is_ollama_available():
        finding.ai_fix = _FALLBACK_TEMPLATES.get(
            category,
            "# Local LLM unavailable — start Ollama for a tailored AI fix.\n"
            f"# General guidance: {finding.remediation or 'apply OWASP/CWE remediation for this category.'}",
        )
        return finding

    try:
        prompt = _build_prompt(finding, context_text)
        raw = generate(prompt, system=SYSTEM_PROMPT, temperature=0.1, max_tokens=500)
        finding.ai_fix = _extract_code_block(raw)
    except OllamaUnavailableError:
        finding.ai_fix = _FALLBACK_TEMPLATES.get(category, "# AI fix unavailable.")
    return finding


def generate_and_verify_fix(finding: Finding) -> Finding:
    """Generates a fix and runs automatic re-scan verification against it."""
    from backend.orchestrator import rescan_single_fix  # local import avoids circular import

    generate_fix(finding)
    try:
        finding.fix_verified = rescan_single_fix(finding, finding.ai_fix or "")
    except Exception as e:
        print(f"[fix_generator] Re-scan verification failed to run: {e}")
        finding.fix_verified = None
    return finding
