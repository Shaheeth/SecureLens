# Contributing to SecureLens AI

Thanks for your interest in contributing!

## Development setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

## Adding a new vulnerability category
1. Add the category to `backend/models.py` (`VulnCategory` enum + `CWE_OWASP_MAP`).
2. Add a detector to `analyzers/ast_analyzer.py` (and/or a Semgrep rule in
   `analyzers/rules/custom_rules.yml`, and/or a Bandit test-ID mapping in
   `analyzers/bandit_analyzer.py`).
3. Add a knowledge-base entry under `rag/data/` and re-run `python -m rag.ingest --force`.
4. Add one intentionally vulnerable sample (`tests/vulnerable_samples/`) and
   one secure reference sample (`tests/secure_samples/`), and register both
   in `tests/evaluation.py`'s `LABELS`/`NEGATIVE_LABELS`.
5. Add/extend tests in `tests/test_ast_analyzer.py`.

## Code style
Standard PEP 8; type hints encouraged; keep functions small and testable.

## Reporting security issues in SecureLens AI itself
Please open a private security advisory rather than a public issue.
