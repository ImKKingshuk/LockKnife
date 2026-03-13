from __future__ import annotations

import io
import pathlib
from typing import Any
from typing import cast

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.logging import get_logger
from lockknife.modules.reporting.html_report import render_html_report, write_html_report

log = get_logger()

class PdfReportError(LockKnifeError):
    pass


def _load_weasyprint_html() -> Any:
    from weasyprint import HTML

    return HTML


def _load_xhtml2pdf_pisa() -> Any:
    from xhtml2pdf import pisa

    return pisa


def pdf_backend_status() -> dict[str, Any]:
    weasyprint_available = False
    xhtml2pdf_available = False
    try:
        _load_weasyprint_html()
        weasyprint_available = True
    except (ImportError, OSError):
        weasyprint_available = False
    try:
        _load_xhtml2pdf_pisa()
        xhtml2pdf_available = True
    except (ImportError, OSError):
        xhtml2pdf_available = False
    return {
        "available": weasyprint_available or xhtml2pdf_available,
        "preferred": "weasyprint" if weasyprint_available else ("xhtml2pdf" if xhtml2pdf_available else None),
        "backends": {"weasyprint": weasyprint_available, "xhtml2pdf": xhtml2pdf_available},
    }


def render_pdf_report(template_path: pathlib.Path, context: dict[str, Any]) -> bytes:
    html = render_html_report(template_path, context)
    try:
        html_cls = _load_weasyprint_html()
    except (ImportError, OSError):
        html_cls = None

    if html_cls is not None:
        try:
            return cast(bytes, html_cls(string=html, base_url=str(template_path.parent)).write_pdf())
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            log.warning("pdf_render_weasyprint_failed", exc_info=True)

    try:
        pisa = _load_xhtml2pdf_pisa()
        buf = io.BytesIO()
        status = pisa.CreatePDF(io.StringIO(html), dest=buf, link_callback=None)
        if status.err:
            raise PdfReportError("PDF rendering failed (xhtml2pdf)")
        return buf.getvalue()
    except PdfReportError:
        raise
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError) as e:
        status = pdf_backend_status()
        raise PdfReportError(
            "PDF rendering requires weasyprint or xhtml2pdf. "
            f"Backend status: {status['backends']}. Use HTML output or install a supported backend."
        ) from e


def write_pdf_report(
    template_path: pathlib.Path,
    context: dict[str, Any],
    output_path: pathlib.Path,
    *,
    fallback_html_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        pdf = render_pdf_report(template_path, context)
        output_path.write_bytes(pdf)
        return {"format": "pdf", "output": str(output_path), "degraded": False, "pdf_backend_status": pdf_backend_status()}
    except PdfReportError as exc:
        if fallback_html_path is None:
            raise
        write_html_report(template_path, context, fallback_html_path)
        return {
            "format": "html",
            "requested_format": "pdf",
            "output": str(fallback_html_path),
            "requested_output": str(output_path),
            "degraded": True,
            "reason": str(exc),
            "pdf_backend_status": pdf_backend_status(),
        }
