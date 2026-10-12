"""Unit tests for security scoring and secure file validation."""
import pytest

from backend.models import Finding, Severity, VulnCategory
from scoring.security_score import calculate_security_score, grade_for_score
from backend.file_validator import (
    validate_upload, validate_batch, sanitize_filename,
    validate_pasted_code, FileValidationError,
)


def test_score_is_100_with_no_findings():
    assert calculate_security_score([]) == 100.0


def test_score_drops_with_critical_finding():
    findings = [Finding(category=VulnCategory.SQL_INJECTION, severity=Severity.CRITICAL, confidence=1.0)]
    score = calculate_security_score(findings)
    assert score < 100.0
    assert score == 80.0  # 100 - 20 * 1.0 * (0.85**0)


def test_score_never_negative():
    findings = [Finding(severity=Severity.CRITICAL, confidence=1.0) for _ in range(50)]
    score = calculate_security_score(findings)
    assert score >= 0.0


def test_grade_boundaries():
    assert "Excellent" in grade_for_score(95)
    assert "Good" in grade_for_score(80)
    assert "Critical Risk" in grade_for_score(10)


def test_sanitize_filename_strips_path_traversal():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\config") == "config"


def test_validate_upload_rejects_bad_extension():
    with pytest.raises(FileValidationError):
        validate_upload("malware.exe", b"binary content here")


def test_validate_upload_rejects_oversized_file():
    with pytest.raises(FileValidationError):
        validate_upload("big.py", b"a" * (3 * 1024 * 1024), max_size_mb=2)


def test_validate_upload_rejects_binary_content():
    with pytest.raises(FileValidationError):
        validate_upload("file.py", b"\x00\x01\x02\xff\xfe")


def test_validate_upload_rejects_path_traversal_in_name():
    with pytest.raises(FileValidationError):
        validate_upload("../../etc/passwd.py", b"print('hi')")


def test_validate_batch_enforces_file_count_limit():
    files = [(f"f{i}.py", b"print(1)") for i in range(30)]
    with pytest.raises(FileValidationError):
        validate_batch(files, max_files=25)


def test_validate_pasted_code_rejects_empty():
    with pytest.raises(FileValidationError):
        validate_pasted_code("   ")


def test_validate_pasted_code_accepts_normal_code():
    result = validate_pasted_code("print('hello world')")
    assert "hello world" in result
