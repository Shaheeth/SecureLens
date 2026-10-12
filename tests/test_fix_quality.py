"""
Evaluates AI-generated (and fallback) fix quality by checking whether the
fixed snippet actually clears the AST analyzer's check for the original
vulnerability category — i.e. testing the *verification* mechanism itself
using the deterministic fallback templates (works without Ollama running,
so this test suite runs in CI without a local LLM).
"""
from backend.models import Finding, VulnCategory, Severity
from llm.fix_generator import _FALLBACK_TEMPLATES
from analyzers.ast_analyzer import analyze_source


def test_fallback_sql_injection_fix_clears_ast_check():
    fixed_code = _FALLBACK_TEMPLATES["SQL Injection"]
    findings = analyze_source("fixed.py", fixed_code)
    assert not any(f.category == VulnCategory.SQL_INJECTION for f in findings)


def test_fallback_command_injection_fix_clears_ast_check():
    fixed_code = "import subprocess\n" + _FALLBACK_TEMPLATES["Command Injection"]
    findings = analyze_source("fixed.py", fixed_code)
    assert not any(f.category == VulnCategory.COMMAND_INJECTION for f in findings)


def test_fallback_deserialization_fix_clears_ast_check():
    fixed_code = _FALLBACK_TEMPLATES["Insecure Deserialization"]
    findings = analyze_source("fixed.py", fixed_code)
    assert not any(f.category == VulnCategory.INSECURE_DESERIALIZATION for f in findings)


def test_fallback_weak_crypto_fix_clears_ast_check():
    fixed_code = _FALLBACK_TEMPLATES["Weak Cryptography"]
    findings = analyze_source("fixed.py", fixed_code)
    assert not any(f.category == VulnCategory.WEAK_CRYPTO for f in findings)


def test_fallback_randomness_fix_clears_ast_check():
    fixed_code = _FALLBACK_TEMPLATES["Insecure Randomness"]
    findings = analyze_source("fixed.py", fixed_code)
    assert not any(f.category == VulnCategory.INSECURE_RANDOMNESS for f in findings)
