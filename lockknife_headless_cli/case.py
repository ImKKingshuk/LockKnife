from __future__ import annotations

import sys

import click

from lockknife.core.cli_instrumentation import LockKnifeGroup
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
