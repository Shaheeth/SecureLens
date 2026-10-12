# 🛡️ SecureLens AI — AI-Powered Secure Code Reviewer

An intelligent application-security platform that lets developers upload
or paste source code and automatically detect security vulnerabilities,
get RAG-grounded AI explanations of the risk, receive AI-generated secure
fixes that are **automatically re-scanned to verify they actually work**,
and download professional JSON/HTML/PDF security assessment reports.

> ⚠️ **Authorized use only.** This is a defensive AppSec tool for
> analyzing code you own or are authorized to test. It never executes
> uploaded code. See [`docs/ethics_and_limitations.md`](docs/ethics_and_limitations.md).

---

## Table of contents
- [Objective](#objective)
- [Features](#features)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Vulnerability detection methodology](#vulnerability-detection-methodology)
- [RAG architecture](#rag-architecture)
- [AI evaluation methodology](#ai-evaluation-methodology)
- [Project structure](#project-structure)
- [Testing](#testing)
- [Limitations](#limitations)
- [Ethical considerations](#ethical-considerations)
- [Future improvements](#future-improvements)
- [License](#license)

---

## Objective

Static Application Security Testing (SAST) tools are powerful but often
produce raw, jargon-heavy output that's hard for developers to triage and
fix quickly. SecureLens AI combines multiple SAST engines with a
**RAG-grounded local LLM** to bridge that gap: it doesn't just say *"CWE-89
detected at line 42"* — it explains *why* it matters, cites the specific
OWASP/CWE/NIST guidance behind the recommendation, generates a corrected
version of the code, and then **empirically verifies** the fix actually
resolves the issue by re-running the same analyzers against it.

Built as a portfolio-grade project demonstrating practical skills in
Application Security, Secure Coding, SAST, OWASP Top 10 / CWE, Python,
AI/LLMs, Retrieval-Augmented Generation, static analysis, vulnerability
assessment, Docker, and security automation.

## Features

- 📤 **Upload or paste code** with strict validation (extension allow-list,
  size/count limits, path-traversal-safe filenames, binary rejection).
- 🔍 **Triple-engine static analysis**: [Semgrep](https://semgrep.dev/)
  (OWASP Top Ten + security-audit + secrets rulesets + custom rules),
  [Bandit](https://bandit.readthedocs.io/) (Python SAST), and a **custom
  Python AST analyzer** with hand-written detectors for every supported
  category — so the app still works even without Semgrep/Bandit installed.
- 🗺️ **CWE / OWASP mapping** for every finding.
- 📊 **0–100 security score** with letter grade, severity distribution
  (Critical/High/Medium/Low), category breakdown, and before/after-fix
  score comparison — all rendered in an interactive Plotly dashboard.
- 🧠 **RAG-grounded AI explanations**: retrieves relevant OWASP/CWE/NIST
  reference material from a local ChromaDB vector store and feeds it to a
  local LLM (via [Ollama](https://ollama.com/)) so explanations are
  grounded in trusted sources with citations, not just model memory.
- 🔧 **AI-powered fix generator** that rewrites the vulnerable snippet —
  followed by an **automatic re-scan** that verifies, using the same
  static analyzers, that the vulnerability class is actually gone.
- 📄 **Downloadable reports** (JSON / HTML / PDF) with executive summary,
  methodology, per-finding evidence/impact/remediation, and a final
  security assessment.
- 🧪 **Test suite** with 10 intentionally vulnerable + 10 secure reference
  samples and an evaluation harness reporting precision/recall/F1/false
  positive rate.
- 🔒 **Secure-by-design**: uploaded code is never executed; strict upload
  validation; isolated, capability-dropped, read-only, network-disabled
  Docker sandbox profile for untrusted analysis; secrets never leave the
  local environment; Ollama keeps AI inference fully local.

## Architecture

```
Streamlit UI → File Validator → Orchestrator → [Semgrep | Bandit | AST]
                                                        │
                                              Dedup + Security Scoring
                                                        │
                                    RAG Retriever (ChromaDB) ← OWASP/CWE/NIST corpus
                                                        │
                                     Local LLM (Ollama) → Explanation + Fix
                                                        │
                                    Re-scan Verification (same analyzers)
                                                        │
                                        JSON / HTML / PDF Report Generator
```

Full diagram and data-flow guarantees: [`docs/architecture.md`](docs/architecture.md).

## Technology stack

| Layer | Technology |
|---|---|
| UI | Streamlit, Plotly, Pandas |
| Static analysis | Semgrep, Bandit, Python `ast` module |
| AI / LLM | Ollama (local LLM, e.g. Llama 3.1) |
| RAG / vector store | ChromaDB, sentence-transformers |
| Reporting | Jinja2 (HTML), WeasyPrint (PDF), `json` |
| Testing | pytest |
| Containerization | Docker, docker-compose (incl. sandboxed analysis profile) |

## Installation

### Option A — local (Python)

```bash
git clone https://github.com/<your-username>/securelens-ai.git
cd securelens-ai
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Pull and start a local LLM (optional but recommended for full AI features)
ollama pull llama3.1:8b
ollama serve &

# Build the RAG vector store from the OWASP/CWE/NIST corpus
python -m rag.ingest

cp .env.example .env   # adjust as needed

streamlit run app.py
```

Open http://localhost:8501.

> Semgrep and Bandit are optional at the OS level — if their binaries
> aren't found, SecureLens AI logs a notice and falls back to the custom
> AST analyzer so the app still functions. Install them for full coverage:
> `pip install semgrep bandit` (already in `requirements.txt`).

### Option B — Docker

```bash
cp .env.example .env
docker compose up --build
```

This starts the SecureLens AI app (port 8501) and an Ollama container
(port 11434). Pull a model into the Ollama container once it's up:

```bash
docker exec -it securelens-ollama ollama pull llama3.1:8b
```

For analyzing less-trusted uploads with additional containment (read-only
root filesystem, dropped Linux capabilities, no network, resource limits),
use the sandbox profile:

```bash
docker compose --profile sandbox up securelens-analyzer-sandbox
```

## Usage

1. Open the app, check **"I confirm I own this code or am authorized to
   test it"**.
2. Upload one or more source files (`.py`, `.js`, `.ts`, `.java`, `.php`,
   `.rb`, `.go` — max 2 MB/file, 25 files) or paste a snippet directly.
3. Click **Run Security Scan**. Semgrep, Bandit, and the AST analyzer run
   in sequence; results are deduplicated and scored.
4. Explore the **Dashboard** tab for the security score, severity/category
   charts, and (after fixes) a before/after comparison.
5. In **Findings & Fixes**, expand any finding to see evidence,
   CWE/OWASP references, and click **Explain with AI** for a RAG-grounded
   explanation, or **Generate & Verify Fix** for an AI-suggested fix that's
   automatically re-scanned to confirm it resolves the issue.
6. In **Reports**, download the JSON, HTML, or PDF security assessment.

### Programmatic usage

```python
from backend.file_validator import validate_batch
from backend.orchestrator import run_full_scan

files = [("app.py", open("app.py", "rb").read())]
validated = validate_batch(files)
result = run_full_scan(validated, target_name="my-project")

print(result.security_score, len(result.findings))
```

## Screenshots

> Run the app locally (`streamlit run app.py`) to see it live. Suggested
> screenshots to capture for this section once you have a running
> instance: the Scan tab, the Dashboard (score + charts), an expanded
> Finding with an AI explanation, and a rendered HTML report — add them
> under `docs/screenshots/` and reference them here, e.g.:
> `![Dashboard](docs/screenshots/dashboard.png)`

## Vulnerability detection methodology

Full write-up: [`docs/methodology.md`](docs/methodology.md). Summary:
three independent analyzers (Semgrep, Bandit, custom AST) run per scan;
findings are deduplicated by file/line/category, with confidence boosted
when multiple tools agree; severity feeds a weighted, diminishing-returns
scoring model that produces the 0–100 security score.

### Supported vulnerability categories

| Category | CWE | OWASP 2021 |
|---|---|---|
| SQL Injection | CWE-89 | A03: Injection |
| Cross-Site Scripting (XSS) | CWE-79 | A03: Injection |
| Command Injection | CWE-78 | A03: Injection |
| Path Traversal | CWE-22 | A01: Broken Access Control |
| Hardcoded Credentials/Secrets | CWE-798, CWE-259 | A07: Auth Failures |
| Weak Cryptography | CWE-327, CWE-326 | A02: Cryptographic Failures |
| Insecure Randomness | CWE-330 | A02: Cryptographic Failures |
| Insecure Deserialization | CWE-502 | A08: Software/Data Integrity Failures |
| SSRF | CWE-918 | A10: SSRF |
| Auth/Authorization Weakness | CWE-287, CWE-306 | A07: Auth Failures |

## RAG architecture

Trusted OWASP/CWE/NIST reference material lives as version-controlled
markdown under `rag/data/`, chunked and embedded (`sentence-transformers`)
into a persistent ChromaDB collection. At explanation/fix time, a query is
built from the finding's category + CWE/OWASP IDs + description, the top-k
most relevant chunks are retrieved, and that context is injected into the
LLM prompt with citations — grounding the AI's output in trusted sources
instead of relying solely on the model's training data. Full details:
[`docs/methodology.md`](docs/methodology.md#2-rag-architecture).

## AI evaluation methodology

`tests/evaluation.py` computes precision/recall/F1/false-positive rate
against a labeled corpus of 10 vulnerable + 10 secure reference samples
(`tests/vulnerable_samples/`, `tests/secure_samples/`). Fix quality is
evaluated the same way the app verifies fixes in production: re-scanning
the fixed code and checking the original issue category no longer
triggers (`tests/test_fix_quality.py`). Full methodology and current
measured results: [`docs/methodology.md`](docs/methodology.md#4-evaluation-methodology).

```bash
python -m tests.evaluation
```

## Project structure

```
securelens-ai/
├── app.py                        # Streamlit frontend
├── backend/
│   ├── models.py                 # Finding / ScanResult data models
│   ├── file_validator.py         # Secure upload validation
│   └── orchestrator.py           # Runs analyzers, dedupes, re-scan verification
├── analyzers/
│   ├── semgrep_analyzer.py
│   ├── bandit_analyzer.py
│   ├── ast_analyzer.py           # Custom Python AST detectors
│   └── rules/custom_rules.yml    # Custom Semgrep rules
├── rag/
│   ├── data/{owasp,cwe,nist}/    # Trusted knowledge base (markdown)
│   ├── knowledge_base.py         # Loading + chunking
│   ├── ingest.py                 # ChromaDB ingestion
│   └── retriever.py              # Top-k retrieval for prompts
├── llm/
│   ├── ollama_client.py          # Local LLM client
│   ├── explainer.py              # RAG-grounded explanations
│   └── fix_generator.py          # Fix generation + re-scan verification
├── scoring/
│   └── security_score.py         # 0-100 scoring model
├── reports/
│   ├── json_report.py / html_report.py / pdf_report.py
│   └── templates/report_template.html
├── tests/
│   ├── vulnerable_samples/ (10)  # Intentionally vulnerable code
│   ├── secure_samples/ (10)      # Secure reference versions
│   ├── test_ast_analyzer.py
│   ├── test_scoring_and_validation.py
│   ├── test_fix_quality.py
│   └── evaluation.py             # Precision/recall/F1 harness
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   └── ethics_and_limitations.md
├── Dockerfile / docker-compose.yml
├── requirements.txt / .env.example
└── README.md
```

## Testing

```bash
pip install -r requirements.txt
pytest tests/ -v --cov=backend --cov=analyzers --cov=scoring
python -m tests.evaluation
```

33 unit tests cover: per-category detection on the vulnerable sample
corpus, zero-false-positive checks on the secure sample corpus, secure
file-validation edge cases (path traversal, oversized files, binary
content, extension allow-listing), scoring-model boundary behavior, and
fix-verification correctness.

## Limitations

Static analysis only (not a substitute for DAST/manual pentesting);
Python-first structural analysis; non-zero false-positive/negative rates
(measured and reported, not hidden); AI explanations/fixes should be
human-reviewed before merging. Full discussion:
[`docs/ethics_and_limitations.md`](docs/ethics_and_limitations.md).

## Ethical considerations

For authorized use only — scan code you own or have explicit permission
to test. Uploaded code is never executed. By default, all analysis and AI
inference run locally (no third-party API calls). See
[`docs/ethics_and_limitations.md`](docs/ethics_and_limitations.md) for
the full policy.

## Future improvements

Multi-language AST coverage, dependency/SCA scanning integration,
multi-user scan history, expanded NIST 800-53 control mappings, side-by-side
diff view for AI fixes, and CI/CD (GitHub Action) integration. Full list:
[`docs/ethics_and_limitations.md`](docs/ethics_and_limitations.md#future-improvements).

## License

MIT — see [`LICENSE`](LICENSE). Use responsibly and only on code you're
authorized to test.
