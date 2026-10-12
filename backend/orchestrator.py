"""
Orchestrator: coordinates Semgrep, Bandit, and the AST analyzer against a
validated set of source files, deduplicates overlapping findings, scores
the result, and (optionally) triggers RAG/LLM enrichment.

No uploaded source is ever executed here — every analyzer either shells
out to a dedicated static-analysis CLI (Semgrep/Bandit) against temp files,
or uses ast.parse() for structural analysis only.
"""
from __future__ import annotations

import time
from collections import defaultdict

from backend.models import ScanResult, Finding
from backend.file_validator import ValidatedFile
from analyzers import semgrep_analyzer, bandit_analyzer, ast_analyzer
from scoring.security_score import calculate_security_score, severity_counts


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings that point at the same file/line/category from multiple
    tools into a single, higher-confidence Finding, keeping the richest
    description and the union of CWE/OWASP references.
    """
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        key = (f.file_path, f.line_start, f.category)
        buckets[key].append(f)

    merged: list[Finding] = []
    for group in buckets.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        # Prefer the finding with the longest description as the base,
        # boost confidence since multiple tools agree, union references.
        base = max(group, key=lambda f: len(f.description))
        base.confidence = min(1.0, max(f.confidence for f in group) + 0.1 * (len(group) - 1))
        base.source_tool = "+".join(sorted({f.source_tool for f in group}))
        base.cwe_ids = sorted(set(sum([f.cwe_ids for f in group], [])))
        base.owasp_ids = sorted(set(sum([f.owasp_ids for f in group], [])))
        merged.append(base)
    return merged


def run_full_scan(validated_files: list[ValidatedFile], target_name: str = "uploaded_project") -> ScanResult:
    start = time.time()
    file_map = {vf.safe_name: vf.content for vf in validated_files}

    all_findings: list[Finding] = []
    all_findings += semgrep_analyzer.run_semgrep(file_map)
    all_findings += bandit_analyzer.run_bandit(file_map)
    all_findings += ast_analyzer.analyze_files(file_map)

    findings = _dedupe(all_findings)
    # Stable ordering: most severe first, then by file/line
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: (
        severity_rank.get(f.severity.value if hasattr(f.severity, "value") else f.severity, 5),
        f.file_path, f.line_start,
    ))

    score = calculate_security_score(findings)
    lines_scanned = sum(len(c.splitlines()) for c in file_map.values())

    return ScanResult(
        target_name=target_name,
        files_scanned=len(file_map),
        lines_scanned=lines_scanned,
        findings=findings,
        security_score=score,
        score_before_fix=score,
        severity_counts=severity_counts(findings),
        scan_duration_seconds=round(time.time() - start, 2),
    )


def rescan_single_fix(original_finding: Finding, fixed_code: str) -> bool:
    """
    Re-runs all analyzers against the AI-fixed snippet to verify the
    specific vulnerability category no longer triggers. Used by the
    fix-generation workflow's automatic verification step.
    """
    file_map = {original_finding.file_path or "fixed_snippet.py": fixed_code}
    new_findings = []
    new_findings += semgrep_analyzer.run_semgrep(file_map)
    new_findings += bandit_analyzer.run_bandit(file_map)
    new_findings += ast_analyzer.analyze_files(file_map)

    still_present = any(f.category == original_finding.category for f in new_findings)
    return not still_present


if __name__ == "__main__":
    # Allows `python -m backend.orchestrator --sandbox-mode` to be used as
    # the isolated-container entrypoint (docker-compose "sandbox" profile).
    import sys
    print("SecureLens AI orchestrator sandbox entrypoint ready.", file=sys.stderr)
