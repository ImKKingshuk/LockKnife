from __future__ import annotations

import pathlib
from typing import Any

from lockknife.core.serialize import write_json


def export_json(data: Any, output_path: pathlib.Path) -> None:
    write_json(output_path, data)
