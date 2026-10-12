"""HTML security report generator (renders reports/templates/report_template.html)."""
from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.models import ScanResult
from reports.json_report import build_json_report

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html_report(scan: ScanResult) -> str:
    report = build_json_report(scan)
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report_template.html")
    return template.render(report=report)


def save_html_report(scan: ScanResult, output_path: str) -> str:
    html = render_html_report(scan)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
