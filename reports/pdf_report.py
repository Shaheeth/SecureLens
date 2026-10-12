"""
PDF security report generator.

Reuses the HTML report template and renders it to PDF with WeasyPrint.
Kept as a separate, optional path: if WeasyPrint (and its native
dependencies like Pango/Cairo) aren't installed, the app should catch
the ImportError and simply hide the "Download PDF" option rather than
crashing the whole report flow.
"""
from __future__ import annotations

from backend.models import ScanResult
from reports.html_report import render_html_report


class PDFGenerationError(Exception):
    pass


def save_pdf_report(scan: ScanResult, output_path: str) -> str:
    try:
        from weasyprint import HTML
    except ImportError as e:
        raise PDFGenerationError(
            "WeasyPrint is not installed or its system dependencies "
            "(Pango/Cairo) are missing. Install per README, or use the "
            "HTML/JSON report formats instead."
        ) from e

    html_content = render_html_report(scan)
    HTML(string=html_content).write_pdf(output_path)
    return output_path
