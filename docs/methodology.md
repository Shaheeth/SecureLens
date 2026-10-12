# Detection, RAG, and Evaluation Methodology

## 1. Vulnerability detection methodology

SecureLens AI runs three independent static analyzers per scan and merges
their output:

1. **Semgrep** — `p/owasp-top-ten`, `p/security-audit`, `p/secrets` plus a
   small custom ruleset (`analyzers/rules/custom_rules.yml`) targeting
   Flask SQL-fstring patterns, hardcoded JWT secrets, unsafe YAML loading,
   and unvalidated outbound SSRF requests.
2. **Bandit** — Python-specific SAST; its test IDs (e.g. B608, B602,
   B301/B506, B324, B311) are mapped to SecureLens's unified
   `VulnCategory` enum in `analyzers/bandit_analyzer.py`.
3. **Custom AST analyzer** (`analyzers/ast_analyzer.py`) — a single-pass
   `ast.NodeVisitor` implementing hand-written detectors for each of the
   ten supported categories: string-built/f-string SQL, shell-invoking
   subprocess calls, hardcoded-secret variable naming + literal heuristics,
   weak hash usage, `random` module usage for tokens, unsafe deserialization
   calls, dynamic-path file operations, non-constant SSRF-prone requests,
   naive credential comparison, and Flask `debug=True`.

Findings from all three are deduplicated by `(file, line, category)` in
`backend/orchestrator._dedupe`; when multiple tools agree on the same
issue, confidence is boosted and CWE/OWASP references are unioned.

### Severity and confidence
- Severity (`Critical/High/Medium/Low/Info`) is assigned per-rule at the
  analyzer level, informed by each tool's own severity/confidence output
  (Semgrep `ERROR/WARNING/INFO`, Bandit `HIGH/MEDIUM/LOW`) or, for the
  AST analyzer, a manually assigned baseline per category (e.g. SQL/command
  injection default to Critical; weak randomness defaults to Medium).
- Confidence (0.0–1.0) reflects how certain the detector is that a match is
  a true positive (e.g. a shell call with `shell=True` is higher-confidence
  than a generic dynamic file path).

### Security score (0–100)
`scoring/security_score.py` starts at 100 and subtracts
`severity_weight × confidence × diminishing_factor^n` for each finding
(weights: Critical 20, High 12, Medium 6, Low 2, Info 0.5). The
diminishing factor (0.85 per repeated same-severity finding) prevents a
large volume of low-severity findings from unrealistically zeroing the
score, while still meaningfully penalizing volume.

## 2. RAG architecture

- **Corpus**: version-controlled markdown files under `rag/data/{owasp,cwe,nist}/`,
  containing original, hand-written summaries (not scraped/copied text) of
  the relevant OWASP Top 10 2021 categories, CWE entries, and NIST SSDF/CSF
  guidance that map to the ten supported vulnerability categories.
- **Chunking**: `rag/knowledge_base.py` splits each document on `## `
  subheadings (Summary/Prevention/Related CWEs are natural retrieval
  units), with a fallback character-based splitter (900 chars, 150 overlap)
  for any oversized subsection.
- **Embedding & storage**: `sentence-transformers` (`all-MiniLM-L6-v2` by
  default) embeddings persisted in a local **ChromaDB** collection
  (`rag/ingest.py`), rebuilt via `python -m rag.ingest`.
- **Retrieval**: `rag/retriever.py` builds a query from the finding's
  category, CWE/OWASP IDs, and description, then retrieves the top-k (default
  3) most relevant chunks. This context is injected into the LLM prompt so
  explanations are grounded in the trusted corpus rather than the model's
  possibly-outdated parametric knowledge, and every explanation cites its
  source document.
- **Graceful degradation**: if ChromaDB/embeddings aren't available, the
  retriever returns an empty context list and the LLM prompt notes that no
  reference was retrieved, rather than failing the whole request.

## 3. AI fix generation and verification

`llm/fix_generator.py` prompts the local LLM (via Ollama), grounded with
the same RAG context, to rewrite only the vulnerable snippet. Critically,
**the fix is not trusted on the model's word** — `generate_and_verify_fix`
re-runs the same static analyzer pipeline against the fixed snippet
(`backend/orchestrator.rescan_single_fix`) and only marks `fix_verified = True`
if the original vulnerability category no longer triggers. This makes "is
it fixed?" an empirically testable, tool-verified claim.

Deterministic fallback templates (`_FALLBACK_TEMPLATES`) cover the most
common categories so the fix-and-verify workflow is testable and usable
even without Ollama running (see `tests/test_fix_quality.py`).

## 4. Evaluation methodology

`tests/evaluation.py` computes precision, recall, F1, and false-positive
rate against a small labeled corpus: `tests/vulnerable_samples/` (one
intentionally vulnerable file per category, expected to trigger a finding
of that category) and `tests/secure_samples/` (a corresponding fixed
version, expected to trigger zero findings of that category).

**Most recent measured results (AST analyzer only, reproducible via
`python -m tests.evaluation`):**

| Metric | Value |
|---|---|
| True Positives | 9 / 10 |
| False Negatives | 1 / 10 |
| True Negatives | 7 / 9 |
| False Positives | 2 / 9 |
| Precision | 0.818 |
| Recall | 0.9 |
| F1 | 0.857 |
| False Positive Rate | 0.222 |

These numbers are reported honestly rather than rounded up: the AST
analyzer alone (no Semgrep/Bandit) is intentionally narrow, and the
false negative/positives above are a known, documented limitation — see
`docs/limitations.md`. Running the full three-analyzer pipeline (with
Semgrep and Bandit installed) closes most of these gaps, since Bandit in
particular has mature, well-tuned checks for several of the same
categories (see `tests/test_ast_analyzer.py` for per-category unit tests).

### AI-generated fix quality
`tests/test_fix_quality.py` evaluates fix quality using the same
re-scan-verification mechanism the app uses in production: a fix "passes"
only if, after being fed back through the analyzer pipeline, it no longer
triggers the original finding's category. This is a stricter and more
meaningful signal than asking the LLM to self-report whether its fix is
correct.
