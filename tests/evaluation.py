"""
Detection accuracy evaluation harness.

Computes precision, recall, F1, false-positive rate, and false-negative
rate for the detection pipeline against the labeled sample corpus in
tests/vulnerable_samples/ (expected: at least one finding of the labeled
category) and tests/secure_samples/ (expected: zero findings of the
corresponding category).

This uses the AST analyzer directly so results are reproducible without
requiring semgrep/bandit binaries to be installed (they're additive; see
README for full-pipeline evaluation instructions once installed).

Run: python -m tests.evaluation
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass

from analyzers.ast_analyzer import analyze_source
from backend.models import VulnCategory

VULN_DIR = Path(__file__).parent / "vulnerable_samples"
SECURE_DIR = Path(__file__).parent / "secure_samples"

# filename -> expected category (ground truth labels for the vulnerable corpus)
LABELS = {
    "sql_injection.py": VulnCategory.SQL_INJECTION,
    "command_injection.py": VulnCategory.COMMAND_INJECTION,
    "path_traversal.py": VulnCategory.PATH_TRAVERSAL,
    "hardcoded_secrets.py": VulnCategory.HARDCODED_SECRET,
    "weak_crypto.py": VulnCategory.WEAK_CRYPTO,
    "insecure_randomness.py": VulnCategory.INSECURE_RANDOMNESS,
    "insecure_deserialization.py": VulnCategory.INSECURE_DESERIALIZATION,
    "ssrf.py": VulnCategory.SSRF,
    "auth_weakness.py": VulnCategory.AUTH_WEAKNESS,
    "xss.py": VulnCategory.XSS,
}

# secure sample filename -> category that must NOT appear
NEGATIVE_LABELS = {
    "sql_injection_secure.py": VulnCategory.SQL_INJECTION,
    "command_injection_secure.py": VulnCategory.COMMAND_INJECTION,
    "path_traversal_secure.py": VulnCategory.PATH_TRAVERSAL,
    "crypto_secure.py": VulnCategory.WEAK_CRYPTO,
    "randomness_secure.py": VulnCategory.INSECURE_RANDOMNESS,
    "deserialization_secure.py": VulnCategory.INSECURE_DESERIALIZATION,
    "ssrf_secure.py": VulnCategory.SSRF,
    "auth_secure.py": VulnCategory.AUTH_WEAKNESS,
    "xss_secure.py": VulnCategory.XSS,
}


@dataclass
class EvalResult:
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 3) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return round(self.false_positives / denom, 3) if denom else 0.0


def run_evaluation() -> EvalResult:
    result = EvalResult()

    for filename, expected in LABELS.items():
        path = VULN_DIR / filename
        if not path.exists():
            continue
        found = {f.category for f in analyze_source(filename, path.read_text())}
        if expected in found:
            result.true_positives += 1
        else:
            result.false_negatives += 1

    for filename, forbidden in NEGATIVE_LABELS.items():
        path = SECURE_DIR / filename
        if not path.exists():
            continue
        found = {f.category for f in analyze_source(filename, path.read_text())}
        if forbidden in found:
            result.false_positives += 1
        else:
            result.true_negatives += 1

    return result


if __name__ == "__main__":
    r = run_evaluation()
    print("SecureLens AI — Detection Accuracy Evaluation (AST analyzer)")
    print("=" * 60)
    print(f"True Positives:  {r.true_positives}")
    print(f"False Negatives: {r.false_negatives}")
    print(f"True Negatives:  {r.true_negatives}")
    print(f"False Positives: {r.false_positives}")
    print("-" * 60)
    print(f"Precision:          {r.precision}")
    print(f"Recall:             {r.recall}")
    print(f"F1 Score:           {r.f1}")
    print(f"False Positive Rate:{r.false_positive_rate}")
