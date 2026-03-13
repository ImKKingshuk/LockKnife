from __future__ import annotations

import json

import click
from rich.table import Table

from lockknife.core.cli_instrumentation import LockKnifeCommand
from lockknife.core.feature_matrix import FEATURE_STATUSES, filter_features, iter_features
from lockknife.core.output import console


def _rows_payload(*, status: str | None, category: str | None) -> list[dict[str, str]]:
    return [
        {
            "category": row.category,
            "capability": row.capability,
            "cli": row.cli,
            "status": row.status,
            "requirements": row.requirements,
            "notes": row.notes,
        }
        for row in filter_features(status=status, category=category)
    ]


@click.command("features", cls=LockKnifeCommand, help="Show the current LockKnife feature maturity matrix.")
@click.option("--format", "out_format", type=click.Choice(["table", "json"], case_sensitive=False), default="table")
@click.option("--status", type=click.Choice(list(FEATURE_STATUSES), case_sensitive=False))
@click.option("--category", type=click.Choice(sorted({row.category for row in iter_features()}), case_sensitive=False))
def features_cmd(out_format: str, status: str | None, category: str | None) -> None:
    rows = _rows_payload(status=status.lower() if status else None, category=category.lower() if category else None)
    if out_format.lower() == "json":
        console.print_json(json.dumps({"rows": rows, "statuses": list(FEATURE_STATUSES)}))
        return

    table = Table(title="LockKnife Feature Matrix")
    table.add_column("Category")
    table.add_column("Capability")
    table.add_column("Status")
    table.add_column("Requirements")
    table.add_column("Notes")
    for row in rows:
        table.add_row(row["category"], row["capability"], row["status"], row["requirements"], row["notes"])
    console.print(table)