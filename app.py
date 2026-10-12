"""
SecureLens AI — Streamlit frontend.

IMPORTANT (secure-by-design): this UI never executes, imports, or evals
any uploaded/pasted code. All code is passed as text to static analyzers.

Usage: streamlit run app.py
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv

load_dotenv()

from backend.file_validator import (
    validate_batch, validate_pasted_code, sanitize_filename,
    FileValidationError, DEFAULT_ALLOWED_EXTENSIONS,
)
from backend.orchestrator import run_full_scan
from backend.models import ScanResult, Finding
from scoring.security_score import grade_for_score, category_breakdown
from llm.explainer import explain_finding
from llm.fix_generator import generate_and_verify_fix
from llm.ollama_client import is_ollama_available
from reports.json_report import build_json_report, save_json_report
from reports.html_report import save_html_report
from reports.pdf_report import save_pdf_report, PDFGenerationError

st.set_page_config(page_title="SecureLens AI", page_icon="🛡️", layout="wide")

SEVERITY_COLORS = {"Critical": "#b91c1c", "High": "#ea580c", "Medium": "#ca8a04",
                    "Low": "#2563eb", "Info": "#64748b"}

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

if "enriched" not in st.session_state:
    st.session_state.enriched = False

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ SecureLens AI")
    st.caption("AI-Powered Secure Code Reviewer")
    st.divider()

    ollama_ok = is_ollama_available()
    st.markdown(f"**Local LLM (Ollama):** {'🟢 Connected' if ollama_ok else '🔴 Not reachable'}")
    if not ollama_ok:
        st.caption("Start Ollama (`ollama serve`) and pull a model "
                    "(`ollama pull llama3.1:8b`) for full AI explanations/fixes. "
                    "The app still works with rule-based fallbacks otherwise.")

    st.divider()
    st.markdown("### ⚠️ Authorized Use Only")
    st.caption(
        "Only scan source code you own or are explicitly authorized to test. "
        "This tool performs static analysis only and never executes uploaded code."
    )

st.title("SecureLens AI — Secure Code Reviewer")
st.caption("Static analysis (Semgrep + Bandit + AST) with RAG-grounded AI explanations, "
           "fix generation, and automated re-scan verification.")

authorized = st.checkbox(
    "I confirm I own this code or am authorized to test it for security purposes.",
    value=False,
)

tab_scan, tab_dashboard, tab_findings, tab_reports = st.tabs(
    ["📤 Scan", "📊 Dashboard", "🔍 Findings & Fixes", "📄 Reports"]
)

# ---------------------------------------------------------------------------
# TAB: Scan
# ---------------------------------------------------------------------------
with tab_scan:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Upload files")
        uploaded = st.file_uploader(
            f"Allowed types: {', '.join(sorted(DEFAULT_ALLOWED_EXTENSIONS))} "
            f"(max 2 MB/file, 25 files)",
            accept_multiple_files=True,
        )

    with col2:
        st.subheader("...or paste code")
        pasted_name = st.text_input("Filename (for display)", value="pasted_snippet.py")
        pasted_code = st.text_area("Paste Python/JS/etc. source here", height=220)

    scan_clicked = st.button("🔎 Run Security Scan", type="primary", disabled=not authorized)
    if not authorized:
        st.info("Check the authorization box above to enable scanning.")

    if scan_clicked:
        files_to_validate = []
        if uploaded:
            for uf in uploaded:
                files_to_validate.append((uf.name, uf.getvalue()))
        if pasted_code.strip():
            files_to_validate.append((pasted_name or "pasted_snippet.py", pasted_code.encode("utf-8")))

        if not files_to_validate:
            st.warning("Upload at least one file or paste some code first.")
        else:
            try:
                with st.spinner("Validating input..."):
                    validated = validate_batch(files_to_validate)
                with st.spinner("Running Semgrep, Bandit, and AST analysis..."):
                    result = run_full_scan(validated, target_name="scan_" + validated[0].safe_name)
                st.session_state.scan_result = result
                st.session_state.enriched = False
                st.success(
                    f"Scan complete: {len(result.findings)} finding(s) across "
                    f"{result.files_scanned} file(s) in {result.scan_duration_seconds}s."
                )
            except FileValidationError as e:
                st.error(f"Validation failed: {e}")

# ---------------------------------------------------------------------------
# TAB: Dashboard
# ---------------------------------------------------------------------------
with tab_dashboard:
    result = st.session_state.scan_result
    if result is None:
        st.info("Run a scan first to see the dashboard.")
    else:
        score = result.score_after_fix if result.score_after_fix is not None else result.security_score
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Security Score", f"{score}/100", grade_for_score(score))
        c2.metric("Total Findings", len(result.findings))
        c3.metric("Files Scanned", result.files_scanned)
        c4.metric("Lines Scanned", result.lines_scanned)

        if result.score_before_fix is not None and result.score_after_fix is not None:
            st.markdown("#### Before / After AI Fixes")
            before_after_df = pd.DataFrame({
                "Stage": ["Before Fixes", "After Fixes"],
                "Score": [result.score_before_fix, result.score_after_fix],
            })
            fig_ba = px.bar(before_after_df, x="Stage", y="Score", range_y=[0, 100],
                             color="Stage", text="Score")
            st.plotly_chart(fig_ba, use_container_width=True)

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### Severity Distribution")
            sev_df = pd.DataFrame(
                [(k, v) for k, v in result.severity_counts.items() if v > 0],
                columns=["Severity", "Count"],
            )
            if not sev_df.empty:
                fig = px.pie(sev_df, names="Severity", values="Count",
                             color="Severity", color_discrete_map=SEVERITY_COLORS, hole=0.4)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.success("No findings — nothing to chart. 🎉")

        with col_b:
            st.markdown("#### Vulnerability Categories")
            cat = category_breakdown(result.findings)
            if cat:
                cat_df = pd.DataFrame(list(cat.items()), columns=["Category", "Count"])
                fig2 = px.bar(cat_df, x="Count", y="Category", orientation="h")
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.success("No vulnerability categories detected.")

# ---------------------------------------------------------------------------
# TAB: Findings & Fixes
# ---------------------------------------------------------------------------
with tab_findings:
    result = st.session_state.scan_result
    if result is None:
        st.info("Run a scan first.")
    elif not result.findings:
        st.success("No findings detected in this scan. 🎉")
    else:
        colx, coly = st.columns([3, 1])
        with coly:
            if st.button("✨ Generate AI explanations for all findings"):
                with st.spinner("Retrieving OWASP/CWE/NIST context and generating explanations..."):
                    for f in result.findings:
                        if not f.ai_explanation:
                            explain_finding(f)
                st.session_state.enriched = True
                st.rerun()

        for f in result.findings:
            header = f"[{f.severity.value if hasattr(f.severity,'value') else f.severity}] " \
                     f"{f.category.value if hasattr(f.category,'value') else f.category} " \
                     f"— {f.file_path}:{f.line_start} (confidence {int(f.confidence*100)}%)"
            with st.expander(header):
                sev = f.severity.value if hasattr(f.severity, "value") else f.severity
                st.markdown(
                    f"<span style='background:{SEVERITY_COLORS.get(sev,'#64748b')};"
                    f"color:white;padding:2px 10px;border-radius:12px;font-size:12px;'>{sev}</span>"
                    f"&nbsp;&nbsp;Detected by: `{f.source_tool}`&nbsp;&nbsp;"
                    f"CWE: {', '.join(f.cwe_ids) or 'N/A'}&nbsp;&nbsp;"
                    f"OWASP: {', '.join(f.owasp_ids) or 'N/A'}",
                    unsafe_allow_html=True,
                )
                st.markdown("**Description**")
                st.write(f.description)

                if f.evidence:
                    st.markdown("**Evidence**")
                    st.code(f.evidence, language="python")

                if f.ai_explanation:
                    st.markdown("**AI Explanation (RAG-grounded)**")
                    st.write(f.ai_explanation)
                    if f.rag_sources:
                        st.caption("Sources: " + ", ".join(f.rag_sources))
                else:
                    if st.button("Explain with AI", key=f"explain_{f.id}"):
                        with st.spinner("Retrieving context and generating explanation..."):
                            explain_finding(f)
                        st.rerun()

                if f.remediation:
                    st.markdown("**Static Remediation Guidance**")
                    st.write(f.remediation)

                st.markdown("**AI-Suggested Fix + Automatic Re-scan Verification**")
                if f.ai_fix:
                    st.code(f.ai_fix, language="python")
                    if f.fix_verified is True:
                        st.success("✅ Re-scan confirms this vulnerability category is no longer detected.")
                    elif f.fix_verified is False:
                        st.warning("⚠️ Re-scan still detects this vulnerability category — review the suggested fix manually.")
                else:
                    if st.button("Generate & Verify Fix", key=f"fix_{f.id}"):
                        with st.spinner("Generating fix and re-scanning to verify..."):
                            generate_and_verify_fix(f)
                        st.rerun()

# ---------------------------------------------------------------------------
# TAB: Reports
# ---------------------------------------------------------------------------
with tab_reports:
    result = st.session_state.scan_result
    if result is None:
        st.info("Run a scan first to generate reports.")
    else:
        st.write("Generate a downloadable, professional security assessment report "
                  "including an executive summary, methodology, findings, evidence, "
                  "impact, remediation, and final assessment.")

        report_dict = build_json_report(result)
        import json as _json
        st.download_button(
            "⬇️ Download JSON Report",
            data=_json.dumps(report_dict, indent=2),
            file_name=f"securelens_report_{result.scan_id[:8]}.json",
            mime="application/json",
        )

        from reports.html_report import render_html_report
        html_str = render_html_report(result)
        st.download_button(
            "⬇️ Download HTML Report",
            data=html_str,
            file_name=f"securelens_report_{result.scan_id[:8]}.html",
            mime="text/html",
        )

        if st.button("Generate PDF Report"):
            with tempfile.TemporaryDirectory() as td:
                pdf_path = str(Path(td) / "report.pdf")
                try:
                    save_pdf_report(result, pdf_path)
                    with open(pdf_path, "rb") as fh:
                        st.download_button(
                            "⬇️ Download PDF Report",
                            data=fh.read(),
                            file_name=f"securelens_report_{result.scan_id[:8]}.pdf",
                            mime="application/pdf",
                        )
                except PDFGenerationError as e:
                    st.error(str(e))

        st.markdown("---")
        st.markdown("#### Report preview")
        st.components.v1.html(html_str, height=600, scrolling=True)
