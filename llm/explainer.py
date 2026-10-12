"""
Generates a grounded, plain-English explanation of a Finding using the
local LLM, conditioned on retrieved OWASP/CWE/NIST context (RAG). Falls
back to a deterministic template if Ollama is unreachable, so the app
degrades gracefully rather than breaking.
"""
from __future__ import annotations

from backend.models import Finding
from rag.retriever import retrieve_context, format_context_for_prompt
from llm.ollama_client import generate, is_ollama_available, OllamaUnavailableError

SYSTEM_PROMPT = (
    "You are a senior application security engineer reviewing static "
    "analysis findings. You explain vulnerabilities precisely and "
    "practically for a developer audience. Ground your answer in the "
    "provided trusted reference context. Be concise (150-250 words). "
    "Do not invent CWE/OWASP IDs not present in the finding or context. "
    "Only discuss the code and context given to you — never claim to have "
    "tested or executed the code."
)


def _build_prompt(finding: Finding, context_text: str) -> str:
    category = finding.category.value if hasattr(finding.category, "value") else finding.category
    severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    return f"""Trusted reference context:
{context_text}

---
Finding to explain:
- Category: {category}
- Severity: {severity}
- File: {finding.file_path}, line {finding.line_start}
- Detected by: {finding.source_tool}
- Static description: {finding.description}
- Evidence:
```
{finding.evidence}
```

Write a developer-facing explanation with three short parts:
1. **What's wrong** — plain-English root cause.
2. **Why it matters** — realistic attack scenario / potential impact.
3. **How to fix it** — concrete remediation guidance consistent with the
   reference context above.
"""


def _fallback_explanation(finding: Finding, contexts) -> str:
    category = finding.category.value if hasattr(finding.category, "value") else finding.category
    lines = [
        f"**What's wrong:** {finding.description or f'A {category} pattern was detected.'}",
        f"**Why it matters:** {finding.impact or 'This class of issue can allow an attacker to compromise confidentiality, integrity, or availability depending on how the affected code path is reached.'}",
        f"**How to fix it:** {finding.remediation or 'Follow the referenced OWASP/CWE guidance for this category.'}",
    ]
    if contexts:
        lines.append("\n_Reference:_ " + "; ".join(c.source_label for c in contexts))
    return "\n\n".join(lines)


def explain_finding(finding: Finding) -> Finding:
    """Mutates and returns `finding` with ai_explanation + rag_sources set."""
    contexts = retrieve_context(finding, top_k=3)
    finding.rag_sources = [c.source_label for c in contexts]
    context_text = format_context_for_prompt(contexts)

    if not is_ollama_available():
        finding.ai_explanation = _fallback_explanation(finding, contexts) + \
            "\n\n_(Note: local LLM unavailable — showing rule-based explanation. " \
            "Start Ollama to enable full AI explanations.)_"
        return finding

    try:
        prompt = _build_prompt(finding, context_text)
        finding.ai_explanation = generate(prompt, system=SYSTEM_PROMPT, temperature=0.2, max_tokens=600)
    except OllamaUnavailableError:
        finding.ai_explanation = _fallback_explanation(finding, contexts)
    return finding


def explain_all(findings: list[Finding]) -> list[Finding]:
    return [explain_finding(f) for f in findings]
