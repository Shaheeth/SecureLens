"""
Secure-by-design upload validation.

Principles enforced here:
  * Uploaded source code is NEVER executed, imported, or eval'd. It is only
    read as text and passed to static analyzers (Semgrep/Bandit) and the
    `ast` module's *parser* (ast.parse only builds a syntax tree; it does
    not execute code).
  * Strict allow-list of file extensions.
  * Hard size limits per file and per scan (defends against zip-bombs /
    resource-exhaustion via oversized pastes or uploads).
  * Filenames are sanitized before ever touching the filesystem.
  * Path traversal in archive/member names is rejected outright.
"""
from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass

DEFAULT_ALLOWED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".go"}
DEFAULT_MAX_FILE_SIZE_MB = 2
DEFAULT_MAX_FILES = 25

# Reject anything that looks like an attempt to escape the intended directory
_UNSAFE_PATH_PATTERN = re.compile(r"(\.\.[/\\])|(^[/\\])|(^[A-Za-z]:)")


class FileValidationError(Exception):
    pass


@dataclass
class ValidatedFile:
    original_name: str
    safe_name: str
    content: str
    size_bytes: int


def sanitize_filename(name: str) -> str:
    """Strip directory components and normalize to a safe basename."""
    name = unicodedata.normalize("NFKC", name)
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)
    if not name or name.startswith("."):
        name = f"file_{abs(hash(name))}.txt"
    return name


def validate_upload(
    filename: str,
    raw_bytes: bytes,
    allowed_extensions: set | None = None,
    max_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB,
) -> ValidatedFile:
    """
    Validate a single uploaded file's metadata and decode it as text.
    Raises FileValidationError on any policy violation. Never executes
    or imports the content.
    """
    allowed_extensions = allowed_extensions or DEFAULT_ALLOWED_EXTENSIONS

    if _UNSAFE_PATH_PATTERN.search(filename):
        raise FileValidationError(f"Rejected unsafe path in filename: {filename!r}")

    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed_extensions:
        raise FileValidationError(
            f"Extension '{ext}' is not permitted. Allowed: {sorted(allowed_extensions)}"
        )

    size_bytes = len(raw_bytes)
    max_bytes = max_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        raise FileValidationError(
            f"File '{filename}' is {size_bytes/1024:.1f} KB, exceeds the "
            f"{max_size_mb} MB limit."
        )
    if size_bytes == 0:
        raise FileValidationError(f"File '{filename}' is empty.")

    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise FileValidationError(
            f"File '{filename}' is not valid UTF-8 text (binary files are rejected): {e}"
        )

    # Defense-in-depth: reject NUL bytes / obvious binary payloads that
    # decoded "successfully" but aren't legitimate source text.
    if "\x00" in content:
        raise FileValidationError(f"File '{filename}' contains binary data and was rejected.")

    return ValidatedFile(
        original_name=filename,
        safe_name=sanitize_filename(filename),
        content=content,
        size_bytes=size_bytes,
    )


def validate_batch(files: list[tuple[str, bytes]], max_files: int = DEFAULT_MAX_FILES,
                    **kwargs) -> list[ValidatedFile]:
    if len(files) > max_files:
        raise FileValidationError(f"Too many files ({len(files)}); limit is {max_files}.")
    return [validate_upload(name, data, **kwargs) for name, data in files]


def validate_pasted_code(code_text: str, max_chars: int = 200_000) -> str:
    """Validate code pasted directly into the UI (no file involved)."""
    if not code_text or not code_text.strip():
        raise FileValidationError("Pasted code is empty.")
    if len(code_text) > max_chars:
        raise FileValidationError(f"Pasted code exceeds {max_chars} character limit.")
    if "\x00" in code_text:
        raise FileValidationError("Pasted content contains binary data and was rejected.")
    return code_text
