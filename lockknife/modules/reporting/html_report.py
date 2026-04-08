from __future__ import annotations

import pathlib
from json import dumps
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

EMBEDDED_REPORT_CSS = """
body { font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; color: #e5e7eb; background: #0f172a; }
.page { max-width: 1120px; margin: 0 auto; padding: 32px; }
.hero, .section, .panel { background: rgba(15, 23, 42, 0.78); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 18px; padding: 20px; margin-bottom: 20px; }
.grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.metric { padding: 16px; border-radius: 14px; background: rgba(30, 41, 59, 0.9); }
.badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #1d4ed8; color: #eff6ff; font-size: 12px; margin-right: 8px; }
.badge.low { background: #065f46; }.badge.medium { background: #92400e; }.badge.high, .badge.critical { background: #991b1b; }
table { width: 100%; border-collapse: collapse; } th, td { padding: 10px 12px; border-bottom: 1px solid rgba(148, 163, 184, 0.15); vertical-align: top; }
pre { white-space: pre-wrap; word-break: break-word; background: rgba(15, 23, 42, 0.95); padding: 12px; border-radius: 12px; }
ul { margin: 8px 0 0 18px; } h1, h2, h3 { margin: 0 0 12px; color: #f8fafc; } p { color: #cbd5e1; }
""".strip()


TEMPLATE_ALIASES = {
    "executive.html": "executive_report.html",
    "technical.html": "technical_report.html",
    "executive": "executive_report.html",
    "technical": "technical_report.html",
}


def render_html_report(template_path: pathlib.Path, context: dict[str, Any]) -> str:
    template_path = _resolve_template_path(template_path)
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["tojson_pretty"] = lambda value: dumps(value, indent=2, sort_keys=True)
    tmpl = env.get_template(template_path.name)
    return tmpl.render(**_prepare_context(context))


def write_html_report(
    template_path: pathlib.Path, context: dict[str, Any], output_path: pathlib.Path
) -> None:
    html = render_html_report(template_path, context)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _resolve_template_path(template_path: pathlib.Path) -> pathlib.Path:
    alias = TEMPLATE_ALIASES.get(template_path.name) or TEMPLATE_ALIASES.get(template_path.stem)
    if alias:
        candidate = template_path.with_name(alias)
        if candidate.exists():
            return candidate
    return template_path


def _prepare_context(context: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(context)
    prepared.setdefault("embedded_css", EMBEDDED_REPORT_CSS)
    prepared.setdefault("artifact_preview_rows", _artifact_preview_rows(prepared.get("artifacts")))
    prepared.setdefault("report_sections", prepared.get("report_sections") or [])
    return prepared


def _artifact_preview_rows(artifacts: Any) -> list[dict[str, Any]]:
    if isinstance(artifacts, list):
        return [row for row in artifacts[:10] if isinstance(row, dict)]
    if isinstance(artifacts, dict):
        return [artifacts]
    return [{"value": artifacts}] if artifacts is not None else []
