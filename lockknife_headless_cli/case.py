import sys

import click

from lockknife.core.case import (
    case_artifact_details,
    case_artifact_lineage,
    case_job_details,
    case_job_rerun_context,
    case_lineage_graph,
    case_output_path,
    complete_case_job,
    create_case_workspace,
    export_case_bundle,
    fail_case_job,
    find_case_artifact,
    find_case_artifact_by_id,
    load_case_manifest,
    query_case_artifacts,
    query_case_jobs,
    register_case_artifact,
    register_case_artifact_with_status,
    save_case_manifest,
    start_case_job,
    summarize_case_manifest,
)
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.custody import list_entries
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules.case_enrichment import run_case_enrichment
from lockknife_headless_cli._case_cli_core import register as _register_core
from lockknife_headless_cli._case_cli_enrichment import register as _register_enrichment
from lockknife_headless_cli._case_cli_helpers import (
    _artifact_ref_kwargs,
    _case_filter_kwargs,
    _render_enrichment_text,
    _render_filter_summary,
    _render_graph_text,
    _render_rows,
    _render_search_summary,
)
from lockknife_headless_cli._case_cli_jobs import register as _register_jobs
from lockknife_headless_cli._case_cli_queries import register as _register_queries


@click.group("case", help="Manage investigation case workspaces and manifests.", cls=LockKnifeGroup)
def case_group() -> None:
    pass


_module = sys.modules[__name__]
for _register in (_register_core, _register_queries, _register_enrichment, _register_jobs):
    _register(case_group, _module)
del _register, _module
