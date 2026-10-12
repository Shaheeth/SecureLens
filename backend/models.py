"""
Core data models used across SecureLens AI.

These are intentionally simple, serializable dataclasses so that the same
Finding objects can flow from analyzers -> scoring -> RAG/LLM enrichment ->
report generation (JSON/HTML/PDF) without re-shaping data at each boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class VulnCategory(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    HARDCODED_SECRET = "Hardcoded Credentials/Secrets"
    WEAK_CRYPTO = "Weak Cryptography"
    INSECURE_RANDOMNESS = "Insecure Randomness"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SSRF = "Server-Side Request Forgery (SSRF)"
    AUTH_WEAKNESS = "Authentication/Authorization Weakness"
    OTHER = "Other"


# Static mapping of internal categories to CWE / OWASP references.
# Used both for display and to build RAG retrieval queries.
CWE_OWASP_MAP = {
    VulnCategory.SQL_INJECTION: {
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021 - Injection"],
    },
    VulnCategory.XSS: {
        "cwe": ["CWE-79"],
        "owasp": ["A03:2021 - Injection"],
    },
    VulnCategory.COMMAND_INJECTION: {
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021 - Injection"],
    },
    VulnCategory.PATH_TRAVERSAL: {
        "cwe": ["CWE-22"],
        "owasp": ["A01:2021 - Broken Access Control"],
    },
    VulnCategory.HARDCODED_SECRET: {
        "cwe": ["CWE-798", "CWE-259"],
        "owasp": ["A07:2021 - Identification and Authentication Failures"],
    },
    VulnCategory.WEAK_CRYPTO: {
        "cwe": ["CWE-327", "CWE-326"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
    },
    VulnCategory.INSECURE_RANDOMNESS: {
        "cwe": ["CWE-330"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
    },
    VulnCategory.INSECURE_DESERIALIZATION: {
        "cwe": ["CWE-502"],
        "owasp": ["A08:2021 - Software and Data Integrity Failures"],
    },
    VulnCategory.SSRF: {
        "cwe": ["CWE-918"],
        "owasp": ["A10:2021 - Server-Side Request Forgery"],
    },
    VulnCategory.AUTH_WEAKNESS: {
        "cwe": ["CWE-287", "CWE-306"],
        "owasp": ["A07:2021 - Identification and Authentication Failures"],
    },
    VulnCategory.OTHER: {"cwe": [], "owasp": []},
}


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_tool: str = "unknown"          # semgrep | bandit | ast | custom-rule
    category: VulnCategory = VulnCategory.OTHER
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5               # 0.0 - 1.0
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    evidence: str = ""                    # the offending code snippet
    description: str = ""
    impact: str = ""
    cwe_ids: list = field(default_factory=list)
    owasp_ids: list = field(default_factory=list)
    remediation: str = ""                 # short static remediation text
    ai_explanation: Optional[str] = None   # LLM/RAG-generated explanation
    ai_fix: Optional[str] = None           # LLM-generated corrected code
    fix_verified: Optional[bool] = None    # result of automatic re-scan
    rag_sources: list = field(default_factory=list)  # citations used by RAG

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value if isinstance(self.category, Enum) else self.category
        d["severity"] = self.severity.value if isinstance(self.severity, Enum) else self.severity
        return d


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_name: str = ""
    files_scanned: int = 0
    lines_scanned: int = 0
    findings: list = field(default_factory=list)   # list[Finding]
    security_score: float = 100.0
    score_before_fix: Optional[float] = None
    score_after_fix: Optional[float] = None
    severity_counts: dict = field(default_factory=dict)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return d
