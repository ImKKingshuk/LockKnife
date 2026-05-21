from __future__ import annotations

import pathlib
from json import dumps
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

EMBEDDED_REPORT_CSS = """
body {
    font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    color: #e2e8f0;
    background: radial-gradient(circle at top right, #1e1b4b 0%, #0f172a 100%);
    background-attachment: fixed;
    line-height: 1.6;
}
.page {
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 24px;
}
.hero {
    background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.8) 100%);
    border: 1px solid rgba(255, 255, 255, 0.08);
    backdrop-filter: blur(12px);
    border-radius: 24px;
    padding: 40px;
    margin-bottom: 30px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
}
.hero::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle, rgba(99, 102, 241, 0.1) 0%, transparent 50%);
    pointer-events: none;
}
h1, h2, h3, h4 {
    margin: 0 0 16px;
    color: #f8fafc;
    font-weight: 700;
}
h1 {
    font-size: 2.5rem;
    letter-spacing: -0.025em;
    background: linear-gradient(to right, #ffffff, #94a3b8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.hero p {
    font-size: 1.1rem;
    color: #94a3b8;
    margin: 0 0 20px;
}

/* Tabs Navigation */
.tabs-nav {
    display: flex;
    gap: 8px;
    background: rgba(30, 41, 59, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 6px;
    border-radius: 14px;
    margin-bottom: 30px;
    overflow-x: auto;
}
.tab-btn {
    background: transparent;
    border: none;
    color: #94a3b8;
    padding: 12px 24px;
    font-size: 0.95rem;
    font-weight: 600;
    border-radius: 10px;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    white-space: nowrap;
}
.tab-btn:hover {
    color: #ffffff;
    background: rgba(255, 255, 255, 0.03);
}
.tab-btn.active {
    color: #ffffff;
    background: #6366f1;
    box-shadow: 0 4px 14px rgba(99, 102, 241, 0.4);
}
.tab-content {
    display: none;
    animation: fadeIn 0.4s ease-out;
}
.tab-content.active {
    display: block;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Grid & Metrics */
.grid {
    display: grid;
    gap: 20px;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    margin-bottom: 30px;
}
.card {
    background: rgba(30, 41, 59, 0.45);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 20px;
    padding: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}
.card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 30px rgba(0,0,0,0.25);
    border-color: rgba(99, 102, 241, 0.3);
}
.metric {
    text-align: center;
    background: linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.6) 100%);
}
.metric h3 {
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #94a3b8;
    margin-bottom: 8px;
}
.metric .val {
    font-size: 2.2rem;
    font-weight: 800;
    color: #f8fafc;
    line-height: 1;
}

/* Badges */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 6px 12px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    gap: 6px;
    border: 1px solid transparent;
}
.badge.info { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border-color: rgba(99, 102, 241, 0.3); }
.badge.low { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border-color: rgba(16, 185, 129, 0.3); }
.badge.medium { background: rgba(245, 158, 11, 0.15); color: #fde047; border-color: rgba(245, 158, 11, 0.3); }
.badge.high { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-color: rgba(239, 68, 68, 0.3); }
.badge.critical { background: rgba(220, 38, 38, 0.25); color: #fecaca; border-color: rgba(220, 38, 38, 0.5); animation: pulseRed 2s infinite; }

@keyframes pulseRed {
    0% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.4); }
    70% { box-shadow: 0 0 0 10px rgba(220, 38, 38, 0); }
    100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0); }
}

/* Forensic Integrity Seal */
.integrity-seal {
    display: flex;
    align-items: center;
    gap: 20px;
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(4, 120, 87, 0.08) 100%);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-radius: 20px;
    padding: 24px;
    margin-bottom: 30px;
}
.integrity-seal.tampered {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(185, 28, 28, 0.08) 100%);
    border-color: rgba(239, 68, 68, 0.3);
}
.seal-icon {
    font-size: 2.5rem;
    color: #10b981;
    animation: pulseGreen 2.5s infinite;
}
.integrity-seal.tampered .seal-icon {
    color: #ef4444;
    animation: shake 0.5s infinite;
}
.seal-details h3 {
    margin: 0 0 6px;
    color: #f8fafc;
}
.seal-details p {
    margin: 0;
    font-size: 0.9rem;
    color: #94a3b8;
}
.seal-details code {
    background: rgba(15, 23, 42, 0.6);
    color: #6ee7b7;
    padding: 3px 8px;
    border-radius: 6px;
    font-family: 'Fira Code', monospace;
    font-size: 0.85rem;
    word-break: break-all;
}
.integrity-seal.tampered .seal-details code {
    color: #fca5a5;
}

@keyframes pulseGreen {
    0%, 100% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.05); opacity: 0.8; }
}
@keyframes shake {
    0%, 100% { transform: rotate(0); }
    20%, 60% { transform: rotate(-5deg); }
    40%, 80% { transform: rotate(5deg); }
}

/* Tables & Lists */
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}
th {
    text-align: left;
    padding: 14px 16px;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #94a3b8;
    border-bottom: 2px solid rgba(255, 255, 255, 0.06);
}
td {
    padding: 14px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    font-size: 0.95rem;
    color: #cbd5e1;
    vertical-align: middle;
}
tr:hover td {
    background: rgba(255, 255, 255, 0.01);
}

/* Frida Live Terminal Visualizer */
.terminal-block {
    background: #090d16;
    border: 1px solid #1e293b;
    border-radius: 16px;
    padding: 24px;
    font-family: 'Fira Code', 'Courier New', Courier, monospace;
    font-size: 0.9rem;
    color: #10b981;
    box-shadow: inset 0 0 20px rgba(0,0,0,0.8);
    position: relative;
    max-height: 480px;
    overflow-y: auto;
}
.terminal-block::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
    background-size: 100% 4px, 6px 100%;
    pointer-events: none;
}
.terminal-line {
    margin-bottom: 6px;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-all;
}
.terminal-line.info { color: #38bdf8; }
.terminal-line.warn { color: #fbbf24; }
.terminal-line.error { color: #f87171; }
.terminal-line.success { color: #34d399; }

/* Collapsible Threat Intel Panels */
.threat-panel {
    background: rgba(30, 41, 59, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 16px;
    margin-bottom: 12px;
    overflow: hidden;
}
.threat-header {
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    cursor: pointer;
    background: rgba(30, 41, 59, 0.5);
    transition: background 0.2s ease;
}
.threat-header:hover {
    background: rgba(30, 41, 59, 0.8);
}
.threat-title {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 600;
    color: #f8fafc;
}
.threat-arrow {
    transition: transform 0.2s ease;
    font-size: 0.8rem;
    color: #94a3b8;
}
.threat-body {
    padding: 0;
    max-height: 0;
    overflow: hidden;
    transition: all 0.3s cubic-bezier(0, 1, 0, 1);
    background: rgba(15, 23, 42, 0.4);
}
.threat-panel.expanded .threat-body {
    padding: 20px;
    max-height: 1000px;
    transition: all 0.3s cubic-bezier(1, 0, 1, 0);
}
.threat-panel.expanded .threat-arrow {
    transform: rotate(90deg);
}

pre {
    background: rgba(15, 23, 42, 0.85);
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 16px;
    border-radius: 12px;
    font-family: 'Fira Code', monospace;
    font-size: 0.85rem;
    color: #e2e8f0;
    overflow-x: auto;
    margin: 8px 0;
}
code {
    font-family: 'Fira Code', monospace;
}
.section {
    background: rgba(30, 41, 59, 0.25);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 20px;
    padding: 30px;
    margin-bottom: 30px;
}
ul { margin: 8px 0 0 18px; } p { color: #cbd5e1; }
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
