"""
Semgrep wrapper.

Runs Semgrep as a subprocess against a temporary, read-only copy of the
validated source files (never against arbitrary user-controlled paths, and
never via `eval`/`exec`/import of the target code). Uses Semgrep's official
`p/owasp-top-ten`, `p/security-audit`, and `p/secrets` rulesets plus our own
custom rules in analyzers/rules/custom_rules.yml.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import os
from pathlib import Path

from backend.models import Finding, Severity, VulnCategory, CWE_OWASP_MAP

SEMGREP_RULESETS = ["p/owasp-top-ten", "p/security-audit", "p/secrets"]
CUSTOM_RULES_PATH = Path(__file__).parent / "rules" / "custom_rules.yml"
ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT_SECONDS", 60))

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_CATEGORY_KEYWORDS = [
    (VulnCategory.SQL_INJECTION, ["sql-injection", "sqli", "sql_injection"]),
    (VulnCategory.XSS, ["xss", "cross-site-scripting"]),
    (VulnCategory.COMMAND_INJECTION, ["command-injection", "os-command", "shell-injection"]),
    (VulnCategory.PATH_TRAVERSAL, ["path-traversal", "directory-traversal"]),
    (VulnCategory.HARDCODED_SECRET, ["hardcoded", "secret", "credential", "api-key", "password"]),
    (VulnCategory.WEAK_CRYPTO, ["weak-crypto", "insecure-hash", "md5", "sha1", "weak-cipher"]),
    (VulnCategory.INSECURE_RANDOMNESS, ["insecure-random", "weak-random"]),
    (VulnCategory.INSECURE_DESERIALIZATION, ["deserialization", "pickle", "unsafe-load", "yaml-load"]),
    (VulnCategory.SSRF, ["ssrf", "server-side-request-forgery"]),
    (VulnCategory.AUTH_WEAKNESS, ["auth", "session", "jwt", "access-control"]),
]


def _classify_category(rule_id: str, message: str) -> VulnCategory:
    text = f"{rule_id} {message}".lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(k in text for k in keywords):
            return category
    return VulnCategory.OTHER


def is_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(file_map: dict[str, str]) -> list[Finding]:
    """
    file_map: {safe_filename: source_code_text}
    Returns a list of Finding objects. Fails soft (returns []) with a
    clear log line if semgrep isn't installed, so the rest of the
    pipeline (Bandit + AST) still works.
    """
    if not is_available():
        print("[semgrep_analyzer] semgrep binary not found on PATH — skipping.")
        return []

    findings: list[Finding] = []

    with tempfile.TemporaryDirectory(prefix="securelens_semgrep_") as tmpdir:
        tmp_path = Path(tmpdir)
        for name, content in file_map.items():
            (tmp_path / name).write_text(content, encoding="utf-8")

        config_args = []
        for ruleset in SEMGREP_RULESETS:
            config_args += ["--config", ruleset]
        if CUSTOM_RULES_PATH.exists():
            config_args += ["--config", str(CUSTOM_RULES_PATH)]

        cmd = [
            "semgrep", "scan",
            *config_args,
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--metrics=off",
            str(tmp_path),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=ANALYSIS_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired:
            print("[semgrep_analyzer] scan timed out — partial results skipped.")
            return []

        if not proc.stdout:
            return []

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        for result in payload.get("results", []):
            rule_id = result.get("check_id", "semgrep-rule")
            message = result.get("extra", {}).get("message", "")
            severity_raw = result.get("extra", {}).get("severity", "WARNING")
            category = _classify_category(rule_id, message)
            mapping = CWE_OWASP_MAP.get(category, {"cwe": [], "owasp": []})

            # semgrep may already tag CWE/OWASP metadata; prefer that when present
            meta = result.get("extra", {}).get("metadata", {})
            cwe_ids = meta.get("cwe", mapping["cwe"])
            owasp_ids = meta.get("owasp", mapping["owasp"])
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            if isinstance(owasp_ids, str):
                owasp_ids = [owasp_ids]

            lines = result.get("extra", {}).get("lines", "")
            findings.append(Finding(
                source_tool="semgrep",
                category=category,
                severity=_SEVERITY_MAP.get(severity_raw, Severity.MEDIUM),
                confidence=0.8,
                file_path=result.get("path", "unknown"),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                evidence=lines.strip()[:400],
                description=message.strip(),
                impact="",  # filled later by scoring / LLM stage
                cwe_ids=cwe_ids,
                owasp_ids=owasp_ids,
                remediation="",
            ))

    return findings
