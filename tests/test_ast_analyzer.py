"""
Unit tests for the custom AST analyzer against the intentionally
vulnerable and secure sample files.

Run: pytest tests/ -v
"""
from pathlib import Path

import pytest

from analyzers.ast_analyzer import analyze_source
from backend.models import VulnCategory

SAMPLES_DIR = Path(__file__).parent
VULN_DIR = SAMPLES_DIR / "vulnerable_samples"
SECURE_DIR = SAMPLES_DIR / "secure_samples"


def _categories_found(file_path: Path) -> set:
    source = file_path.read_text()
    findings = analyze_source(file_path.name, source)
    return {f.category for f in findings}


@pytest.mark.parametrize("filename,expected_category", [
    ("sql_injection.py", VulnCategory.SQL_INJECTION),
    ("command_injection.py", VulnCategory.COMMAND_INJECTION),
    ("hardcoded_secrets.py", VulnCategory.HARDCODED_SECRET),
    ("weak_crypto.py", VulnCategory.WEAK_CRYPTO),
    ("insecure_randomness.py", VulnCategory.INSECURE_RANDOMNESS),
    ("insecure_deserialization.py", VulnCategory.INSECURE_DESERIALIZATION),
    ("ssrf.py", VulnCategory.SSRF),
    ("auth_weakness.py", VulnCategory.AUTH_WEAKNESS),
    ("xss.py", VulnCategory.XSS),
])
def test_vulnerable_sample_detected(filename, expected_category):
    found = _categories_found(VULN_DIR / filename)
    assert expected_category in found, (
        f"Expected {expected_category} to be detected in {filename}, got {found}"
    )


@pytest.mark.parametrize("filename,forbidden_category", [
    ("sql_injection_secure.py", VulnCategory.SQL_INJECTION),
    ("command_injection_secure.py", VulnCategory.COMMAND_INJECTION),
    ("crypto_secure.py", VulnCategory.WEAK_CRYPTO),
    ("randomness_secure.py", VulnCategory.INSECURE_RANDOMNESS),
    ("deserialization_secure.py", VulnCategory.INSECURE_DESERIALIZATION),
])
def test_secure_sample_has_no_false_positive(filename, forbidden_category):
    found = _categories_found(SECURE_DIR / filename)
    assert forbidden_category not in found, (
        f"False positive: {forbidden_category} incorrectly flagged in secure sample {filename}"
    )


def test_syntax_error_handled_gracefully():
    findings = analyze_source("broken.py", "def f(:\n  pass")
    assert len(findings) == 1
    assert "could not be parsed" in findings[0].description.lower()


def test_no_code_execution_side_effect(tmp_path):
    """
    Regression guard: analyzing a snippet that would raise/exit if executed
    must NOT raise, proving analyze_source never executes the source.
    """
    dangerous_if_executed = "import sys\nsys.exit(1)\nraise RuntimeError('should never run')"
    findings = analyze_source("dangerous.py", dangerous_if_executed)
    assert isinstance(findings, list)  # completed without executing/raising
