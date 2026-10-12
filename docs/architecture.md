# SecureLens AI — Architecture

## High-level flow

```
                          ┌───────────────────────────┐
                          │   Streamlit Frontend       │
                          │   (app.py)                 │
                          │  - upload / paste code      │
                          │  - dashboard, findings, fixes│
                          │  - report downloads          │
                          └──────────────┬────────────┘
                                         │
                                         ▼
                          ┌───────────────────────────┐
                          │ backend/file_validator.py  │
                          │  - extension allow-list     │
                          │  - size/count limits         │
                          │  - path traversal defense    │
                          │  - UTF-8 / binary rejection   │
                          └──────────────┬────────────┘
                                         │ validated text (never executed)
                                         ▼
                          ┌───────────────────────────┐
                          │  backend/orchestrator.py   │
                          │  runs analyzers in parallel │
                          └───┬───────────┬───────────┬─┘
                              │           │           │
                 ┌────────────┘   ┌───────┘    ┌──────┘
                 ▼                 ▼             ▼
      analyzers/semgrep_   analyzers/bandit_  analyzers/ast_
      analyzer.py           analyzer.py        analyzer.py
      (subprocess, CLI)     (subprocess, CLI)  (ast.parse, in-process)
                 │                 │             │
                 └────────────┬────┴─────────────┘
                              ▼
                    dedupe + merge (orchestrator._dedupe)
                              │
                              ▼
                 scoring/security_score.py
                 (0-100 score, severity/category breakdown)
                              │
              ┌───────────────┴────────────────┐
              ▼                                 ▼
   rag/retriever.py  ── query ──▶  ChromaDB (rag/ingest.py)
   (top-k OWASP/CWE/NIST chunks)   persisted at CHROMA_PERSIST_DIR
              │
              ▼
   llm/explainer.py & llm/fix_generator.py
   (Ollama local LLM, grounded in retrieved context)
              │
              ▼
   backend/orchestrator.rescan_single_fix()
   (re-runs all 3 analyzers against the AI fix to VERIFY it)
              │
              ▼
   reports/{json,html,pdf}_report.py
   (executive summary, methodology, findings, final assessment)
```

## Why three analyzers instead of one

| Analyzer | Strength | Weakness |
|---|---|---|
| **Semgrep** | Broad, community-maintained rulesets (OWASP Top 10, secrets); multi-language | Requires the binary; rules can be strict/verbose |
| **Bandit** | Purpose-built for Python; mature CWE tagging; low false-positive rate on its core checks | Python-only |
| **Custom AST** | Zero external dependency; full control over confidence/CWE mapping; works even if semgrep/bandit aren't installed; catches f-string/concat patterns tuned to this project's categories | Python-only; hand-written rules, narrower coverage than Semgrep's community rulesets |

Running all three and deduplicating overlapping findings (`orchestrator._dedupe`)
gives higher-confidence results when multiple tools agree, and resilience —
the app still functions (via the AST analyzer) even in environments where
the Semgrep/Bandit CLIs aren't installed.

## Data flow guarantees (secure-by-design)

1. Uploaded/pasted code is validated (`backend/file_validator.py`) before
   anything else touches it: extension allow-list, per-file and per-batch
   size limits, UTF-8-only, path-traversal-safe filenames.
2. Code is **never executed**. Semgrep/Bandit run as separate CLI
   subprocesses against temp files; the custom analyzer only calls
   `ast.parse()`, which builds a syntax tree without evaluating anything.
3. An isolated, read-only, capability-dropped, network-disabled Docker
   profile (`securelens-analyzer-sandbox` in `docker-compose.yml`) is
   available for analyzing less-trusted uploads with extra containment.
4. Secrets found in code are only ever displayed back to the *same user*
   who uploaded them (no external transmission); the LLM calls go to a
   locally-hosted Ollama instance, not a third-party API, so source code
   never leaves the user's machine/network by default.

## RAG pipeline

See `docs/methodology.md` for the retrieval design and evaluation approach.
