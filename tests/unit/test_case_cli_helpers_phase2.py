import pathlib

import pytest

from lockknife_headless_cli._case_cli_helpers import (
    _artifact_ref_kwargs,
    _case_filter_kwargs,
    _render_enrichment_text,
    _render_filter_summary,
    _render_graph_text,
    _render_rows,
    _render_search_summary,
)


def test_case_cli_helper_renderers_and_filters(tmp_path: pathlib.Path) -> None:
    assert _render_rows("Kinds", []) == ["Kinds:", "- none"]
    assert _render_rows("Kinds", [{"name": "apk", "count": 2}])[1] == "- apk: 2"

    filters = _case_filter_kwargs(categories=("apk",), exclude_categories=("tmp",), source_commands=("apk analyze",), device_serials=("SERIAL",))
    assert "categories=apk" in (_render_filter_summary(filters) or "")
    assert _render_filter_summary({}) is None

    search_summary = _render_search_summary({"search": {"query": "token", "path_contains": "logs", "metadata_contains": "severity", "limit": 5}})
    assert "query=token" in (search_summary or "")
    assert _render_search_summary({}) is None

    path = tmp_path / "artifact.json"
    with pytest.raises(Exception):
        _artifact_ref_kwargs(artifact_id="A1", artifact_path=path)
    assert _artifact_ref_kwargs(artifact_id="A1", artifact_path=None)["artifact_id"] == "A1"


def test_case_cli_graph_and_enrichment_rendering() -> None:
    graph = {
        "case_id": "CASE-1",
        "title": "Demo",
        "examiner": "Examiner",
        "artifact_count": 3,
        "root_artifact_ids": ["a1"],
        "edges": [["a1", "a2"], ["a2", "a1"]],
        "nodes": [
            {"artifact_id": "a1", "category": "apk", "path": "one.json", "child_artifact_ids": ["a2"]},
            {"artifact_id": "a2", "category": "intel", "path": "two.json", "child_artifact_ids": ["a1"]},
            {"artifact_id": "a3", "category": "misc", "path": "three.json", "child_artifact_ids": [], "device_serial": "SERIAL"},
        ],
    }
    text = _render_graph_text(graph)
    assert "[cycle]" in text
    assert "Remaining:" in text
    assert "device=SERIAL" in text

    enrichment = _render_enrichment_text(
        {
            "case_id": "CASE-1",
            "title": "Demo",
            "artifact_id": "a1",
            "summary": {"selected_artifact_count": 2, "workflow_run_count": 4, "skipped_artifact_count": 1},
            "provider_status": [{"provider": "otx"}, {"provider": "vt"}],
            "run_summary": {"success_count": 3, "error_count": 1, "workflow_status": [{"name": "wf", "count": 4}]},
            "output": "out.json",
        }
    )
    assert "Providers: otx, vt" in enrichment
    assert "Seed artifact: a1" in enrichment
