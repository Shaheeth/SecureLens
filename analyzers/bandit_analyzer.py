"""
Bandit wrapper (Python-specific SAST).

Like the Semgrep wrapper, this writes validated source to a temp directory
and invokes the `bandit` CLI as a subprocess — the target code is parsed by
Bandit's AST-based checks, never executed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import os
from pathlib import Path

from backend.models import Finding, Severity, VulnCategory, CWE_OWASP_MAP

ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT_SECONDS", 60))

_SEVERITY_MAP = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}

# Map Bandit test IDs to our unified categories
_TEST_ID_CATEGORY = {
    "B608": VulnCategory.SQL_INJECTION,       # hardcoded SQL string building
    "B610": VulnCategory.SQL_INJECTION,
    "B611": VulnCategory.SQL_INJECTION,
    "B602": VulnCategory.COMMAND_INJECTION,   # subprocess with shell=True
    "B603": VulnCategory.COMMAND_INJECTION,
    "B604": VulnCategory.COMMAND_INJECTION,
    "B605": VulnCategory.COMMAND_INJECTION,
    "B606": VulnCategory.COMMAND_INJECTION,
    "B607": VulnCategory.COMMAND_INJECTION,
    "B609": VulnCategory.PATH_TRAVERSAL,
    "B105": VulnCategory.HARDCODED_SECRET,    # hardcoded password string
    "B106": VulnCategory.HARDCODED_SECRET,
    "B107": VulnCategory.HARDCODED_SECRET,
    "B301": VulnCategory.INSECURE_DESERIALIZATION,  # pickle
    "B302": VulnCategory.INSECURE_DESERIALIZATION,
    "B506": VulnCategory.INSECURE_DESERIALIZATION,  # yaml.load
    "B324": VulnCategory.WEAK_CRYPTO,         # weak hash (md5/sha1)
    "B303": VulnCategory.WEAK_CRYPTO,
    "B304": VulnCategory.WEAK_CRYPTO,
    "B305": VulnCategory.WEAK_CRYPTO,
    "B311": VulnCategory.INSECURE_RANDOMNESS, # random module for security
    "B310": VulnCategory.SSRF,                # urllib with untrusted URL
    "B201": VulnCategory.AUTH_WEAKNESS,       # flask debug=True
    "B105_hc": VulnCategory.HARDCODED_SECRET,
}


def is_available() -> bool:
    return shutil.which("bandit") is not None


def run_bandit(file_map: dict[str, str]) -> list[Finding]:
    """
    file_map: {safe_filename: source_code_text}. Only .py files are
    meaningful to Bandit; non-Python files are skipped.
    """
    py_files = {n: c for n, c in file_map.items() if n.endswith(".py")}
    if not py_files:
        return []
    if not is_available():
        print("[bandit_analyzer] bandit binary not found on PATH — skipping.")
        return []

    findings: list[Finding] = []

    with tempfile.TemporaryDirectory(prefix="securelens_bandit_") as tmpdir:
        tmp_path = Path(tmpdir)
        for name, content in py_files.items():
            (tmp_path / name).write_text(content, encoding="utf-8")

        cmd = ["bandit", "-r", str(tmp_path), "-f", "json", "-q"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=ANALYSIS_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            print("[bandit_analyzer] scan timed out — partial results skipped.")
            return []

        if not proc.stdout:
            return []
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        for result in payload.get("results", []):
            test_id = result.get("test_id", "")
            category = _TEST_ID_CATEGORY.get(test_id, VulnCategory.OTHER)
            mapping = CWE_OWASP_MAP.get(category, {"cwe": [], "owasp": []})
            cwe = result.get("issue_cwe", {}).get("id")
            cwe_ids = [f"CWE-{cwe}"] if cwe else mapping["cwe"]

            findings.append(Finding(
                source_tool="bandit",
                category=category,
                severity=_SEVERITY_MAP.get(result.get("issue_severity", "MEDIUM"), Severity.MEDIUM),
                confidence={"HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.35}.get(
                    result.get("issue_confidence", "MEDIUM"), 0.5
                ),
                file_path=Path(result.get("filename", "unknown")).name,
                line_start=result.get("line_number", 0),
                line_end=result.get("line_range", [result.get("line_number", 0)])[-1],
                evidence=result.get("code", "").strip()[:400],
                description=f"[{test_id}] {result.get('issue_text', '')}".strip(),
                impact="",
                cwe_ids=cwe_ids,
                owasp_ids=mapping["owasp"],
                remediation="",
            ))

    return findings
