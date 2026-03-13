from __future__ import annotations



import pathlib

from typing import Any



from lockknife.core.case import case_output_path, register_case_artifact



def _resolve_case_output(output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="evidence", filename=filename), True



def _register_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    category: str,
    source_command: str,
    device_serial: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category=category,
        source_command=source_command,
        device_serial=device_serial,
        metadata=metadata,
    )
