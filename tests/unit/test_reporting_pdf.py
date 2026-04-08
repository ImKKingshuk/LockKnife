import pathlib
import types

import pytest

from lockknife.modules.reporting.pdf_report import (
    PdfReportError,
    pdf_backend_status,
    render_pdf_report,
    write_pdf_report,
)


def test_render_pdf_report_if_backend_available(tmp_path: pathlib.Path) -> None:
    try:
        pass  # type: ignore
    except Exception:
        try:
            pass  # type: ignore
        except Exception:
            pytest.skip("No PDF backend installed")

    tpl = tmp_path / "t.html"
    tpl.write_text("<h1>{{ case_id }}</h1>", encoding="utf-8")
    pdf = render_pdf_report(tpl, {"case_id": "X"})
    assert isinstance(pdf, (bytes, bytearray))
    assert len(pdf) > 50


def test_write_pdf_report_falls_back_to_html_when_backend_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    tpl = tmp_path / "t.html"
    tpl.write_text("<h1>{{ case_id }}</h1>", encoding="utf-8")

    def _boom(_template: pathlib.Path, _context: dict[str, object]) -> bytes:
        raise PdfReportError("backend missing")

    monkeypatch.setattr("lockknife.modules.reporting.pdf_report.render_pdf_report", _boom)

    out = write_pdf_report(
        tpl,
        {"case_id": "X"},
        tmp_path / "report.pdf",
        fallback_html_path=tmp_path / "report.html",
    )

    assert out["degraded"] is True
    assert out["format"] == "html"
    assert (tmp_path / "report.html").exists()


def test_pdf_backend_status_detects_available_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    import lockknife.modules.reporting.pdf_report as pdf_mod

    monkeypatch.setattr(pdf_mod, "_load_weasyprint_html", lambda: object())
    monkeypatch.setattr(
        pdf_mod, "_load_xhtml2pdf_pisa", lambda: (_ for _ in ()).throw(ImportError("missing"))
    )

    status = pdf_backend_status()
    assert status["available"] is True
    assert status["preferred"] == "weasyprint"
    assert status["backends"]["weasyprint"] is True


def test_render_pdf_report_falls_back_to_xhtml2pdf_when_weasyprint_render_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    import lockknife.modules.reporting.pdf_report as pdf_mod

    tpl = tmp_path / "t.html"
    tpl.write_text("<h1>{{ case_id }}</h1>", encoding="utf-8")

    class _BrokenHtml:
        def __init__(self, string: str, base_url: str) -> None:
            self.string = string
            self.base_url = base_url

        def write_pdf(self) -> bytes:
            raise RuntimeError("render failed")

    monkeypatch.setattr(pdf_mod, "_load_weasyprint_html", lambda: _BrokenHtml)
    monkeypatch.setattr(
        pdf_mod,
        "_load_xhtml2pdf_pisa",
        lambda: types.SimpleNamespace(
            CreatePDF=lambda _src, dest, link_callback=None: (
                dest.write(b"pdf-bytes"),
                types.SimpleNamespace(err=False),
            )[1]
        ),
    )

    assert render_pdf_report(tpl, {"case_id": "X"}) == b"pdf-bytes"


def test_render_pdf_report_raises_when_no_pdf_backend_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    import lockknife.modules.reporting.pdf_report as pdf_mod

    tpl = tmp_path / "t.html"
    tpl.write_text("<h1>{{ case_id }}</h1>", encoding="utf-8")
    monkeypatch.setattr(
        pdf_mod, "_load_weasyprint_html", lambda: (_ for _ in ()).throw(ImportError("missing"))
    )
    monkeypatch.setattr(
        pdf_mod, "_load_xhtml2pdf_pisa", lambda: (_ for _ in ()).throw(ImportError("missing"))
    )

    with pytest.raises(PdfReportError, match="requires weasyprint or xhtml2pdf"):
        render_pdf_report(tpl, {"case_id": "X"})
