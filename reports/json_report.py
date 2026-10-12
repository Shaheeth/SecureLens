"""JSON security report generator."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from backend.models import ScanResult
from scoring.security_score import grade_for_score, category_breakdown


def build_json_report(scan: ScanResult) -> dict:
    findings = scan.findings
    report = {
        "report_metadata": {
            "tool": "SecureLens AI",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan.scan_id,
            "target": scan.target_name,
        },
        "executive_summary": {
            "security_score": scan.security_score,
            "grade": grade_for_score(scan.security_score),
            "total_findings": len(findings),
            "severity_distribution": scan.severity_counts,
            "category_breakdown": category_breakdown(findings),
            "files_scanned": scan.files_scanned,
            "lines_scanned": scan.lines_scanned,
            "scan_duration_seconds": scan.scan_duration_seconds,
            "score_before_fix": scan.score_before_fix,
            "score_after_fix": scan.score_after_fix,
        },
        "methodology": {
            "tools_used": ["Semgrep (OWASP Top Ten, security-audit, secrets rulesets)",
                            "Bandit (Python SAST)",
                            "Custom Python AST structural analyzer",
                            "RAG-grounded LLM explanation (OWASP/CWE/NIST corpus via ChromaDB)"],
            "note": "Static analysis only — no target code was executed at any point.",
        },
        "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
        "final_assessment": _final_assessment_text(scan),
    }
    return report


def _final_assessment_text(scan: ScanResult) -> str:
    grade = grade_for_score(scan.security_score)
    crit = scan.severity_counts.get("Critical", 0)
    high = scan.severity_counts.get("High", 0)
    if crit > 0:
        urgency = f"{crit} critical issue(s) require immediate remediation before deployment."
    elif high > 0:
        urgency = f"{high} high-severity issue(s) should be prioritized in the next release cycle."
    else:
        urgency = "No critical or high-severity issues were identified in this scan."
    return (
        f"Overall security posture: {grade} ({scan.security_score}/100). {urgency} "
        f"This assessment reflects static analysis coverage only and should be "
        f"complemented with dynamic testing (DAST), manual review, and dependency "
        f"scanning (SCA) for full coverage."
    )


def save_json_report(scan: ScanResult, output_path: str) -> str:
    report = build_json_report(scan)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return output_path
