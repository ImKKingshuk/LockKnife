from __future__ import annotations

import pathlib
from typing import Any

from lockknife.core.serialize import write_csv


def export_csv(rows: list[dict[str, Any]], output_path: pathlib.Path) -> None:
    write_csv(output_path, rows)

