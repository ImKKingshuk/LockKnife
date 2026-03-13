from __future__ import annotations

import sys

import click

from lockknife.core.case import (
    case_artifact_details,
    case_artifact_lineage,
    case_lineage_graph,
    case_output_path,
    create_case_workspace,
    export_case_bundle,
    load_case_manifest,
    query_case_artifacts,
    register_case_artifact,
    register_case_artifact_with_status,
    summarize_case_manifest,
)
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.custody import list_entries
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.case_enrichment import run_case_enrichment

from lockknife_headless_cli._case_cli_helpers import (
    _artifact_ref_kwargs,
    _case_filter_kwargs,
    _render_enrichment_text,
    _render_filter_summary,
    _render_graph_node,
    _render_graph_text,
    _render_rows,
    _render_search_summary,
)
from lockknife_headless_cli._case_cli_core import register as _register_core
from lockknife_headless_cli._case_cli_enrichment import register as _register_enrichment
from lockknife_headless_cli._case_cli_queries import register as _register_queries


@click.group("case", help="Manage investigation case workspaces and manifests.", cls=LockKnifeGroup)
def case_group() -> None:
    pass


_module = sys.modules[__name__]
for _register in (_register_core, _register_queries, _register_enrichment):
    _register(case_group, _module)
del _register, _module
