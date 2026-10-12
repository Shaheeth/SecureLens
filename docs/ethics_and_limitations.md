# Ethical Considerations & Limitations

## Authorized use only
SecureLens AI is a **defensive** application-security tool. It is intended
exclusively for analyzing source code that you own or are explicitly
authorized to test (e.g. your own projects, your employer's codebase with
permission, or code in an authorized penetration-testing engagement). The
Streamlit UI requires an explicit authorization checkbox before scanning
is enabled. Do not use this tool, or any output it produces (including
AI-generated fixes or explanations), against systems or code you do not
own or have authorization to assess.

## No code execution, ever
Every analyzer in this project (Semgrep, Bandit, the custom AST module)
operates purely statically. Uploaded/pasted code is never executed,
imported, `eval`'d, or run in a subprocess as an interpreter target — it
is only parsed as text or as a syntax tree. This is a deliberate design
constraint, not an incidental property, and is enforced structurally (see
`docs/architecture.md`).

## Known limitations
- **Static analysis only.** SecureLens AI does not replace dynamic testing
  (DAST), dependency/SCA scanning, manual penetration testing, or a full
  threat model. Findings reflect code patterns, not confirmed runtime
  exploitability.
- **Language coverage.** The custom AST analyzer and Bandit are Python-only;
  Semgrep provides broader multi-language coverage but was configured here
  primarily around the ten supported categories.
- **False positives/negatives are expected.** As documented in
  `docs/methodology.md`, the evaluation harness measures real, non-zero
  false-positive and false-negative rates. Findings should be triaged by a
  human reviewer, not auto-remediated blindly.
- **LLM explanations can still be imperfect.** RAG grounding reduces (but
  does not eliminate) the risk of an inaccurate AI explanation. The
  "AI-Suggested Fix" is verified by re-scanning with the same static
  analyzers, but re-scan verification only confirms the *original* issue
  class is gone — it cannot guarantee the fix didn't introduce a *new*
  issue or break functionality. Always review AI-generated fixes before
  merging them.
- **Secrets handling.** If SecureLens AI detects what looks like a
  hardcoded secret, treat that secret as compromised and rotate it — do
  not just apply the suggested fix and consider the matter closed.
- **Local LLM quality varies by model.** Explanation/fix quality depends
  on which Ollama model is configured; smaller models may produce less
  reliable output than larger ones.

## Data handling
- By default, analysis runs entirely locally: static analyzers run as
  local subprocesses, the vector store is a local ChromaDB instance, and
  the LLM is a locally-hosted Ollama model — no source code is sent to a
  third-party cloud API in the default configuration.
- Uploaded files are validated and processed in-memory/temp directories
  and are not persisted beyond the session unless you explicitly export a
  report.

## Future improvements
- Expand multi-language structural analysis (JS/TS/Java/Go AST-equivalent
  checks) beyond the current Python-focused AST analyzer.
- Add dependency/SCA scanning (e.g. `pip-audit`, `npm audit`) to broaden
  coverage beyond first-party code.
- Add authenticated multi-user support with per-user isolated scan history.
- Expand the RAG corpus with additional NIST 800-53 control mappings and
  language-specific secure coding cheat sheets.
- Add a "diff view" comparing original vs. AI-fixed code side-by-side in
  the UI.
- CI integration (GitHub Action) to run SecureLens AI as a PR check.
