from __future__ import annotations

import json
from typing import Any, cast

from lockknife.core.exceptions import LockKnifeError


class CorrelationError(LockKnifeError):
    pass


def correlate_artifacts_json_blobs(json_blobs: list[str]) -> dict[str, Any]:
    try:
        import lockknife.lockknife_core as lockknife_core
    except ImportError as e:
        raise CorrelationError("lockknife_core extension is not available") from e

    try:
        out = lockknife_core.correlate_artifacts_json(json_blobs)
    except (RuntimeError, ValueError, TypeError) as e:
        # PyO3 errors typically manifest as RuntimeError, ValueError, or TypeError
        raise CorrelationError(f"Correlation engine failed: {e}") from e
    except Exception as e:
        # Fallback for unexpected errors
        raise CorrelationError(f"Correlation engine failed: {e}") from e
    
    try:
        return cast(dict[str, Any], json.loads(out))
    except json.JSONDecodeError as e:
        raise CorrelationError("Correlation engine returned invalid JSON") from e


def correlate_artifact_objects(objs: list[Any]) -> dict[str, Any]:
    blobs = [json.dumps(o) for o in objs]
    return correlate_artifacts_json_blobs(blobs)
