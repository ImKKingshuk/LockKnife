from __future__ import annotations

import contextlib
import logging
import sys
import threading
import uuid
from typing import Any, cast

import structlog

from lockknife.core.config import LockKnifeConfig


class StderrPrintLoggerFactory:
    def __call__(self, *_args: Any) -> Any:
        return structlog.PrintLogger(file=sys.stderr)


# Thread-local storage for trace context
_trace_context = threading.local()


def get_trace_id() -> str | None:
    """Get the current trace_id from thread-local storage."""
    return getattr(_trace_context, "trace_id", None)


def set_trace_id(trace_id: str) -> None:
    """Set the trace_id in thread-local storage."""
    _trace_context.trace_id = trace_id


def clear_trace_id() -> None:
    """Clear the trace_id from thread-local storage."""
    _trace_context.trace_id = None


@contextlib.contextmanager
def trace_context(name: str | None = None) -> Any:
    """Context manager for trace context with automatic trace_id generation.

    Args:
        name: Optional name for the trace span.

    Yields:
        The trace_id for this context.
    """
    trace_id = str(uuid.uuid4())
    set_trace_id(trace_id)
    try:
        yield trace_id
    finally:
        clear_trace_id()


def add_trace_id_processor(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor to add trace_id to all log messages."""
    trace_id = get_trace_id()
    if trace_id:
        event_dict["trace_id"] = trace_id
    return event_dict


def configure_logging(cfg: LockKnifeConfig) -> None:
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)

    shared_processors: list[structlog.typing.Processor] = [
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        add_trace_id_processor,
    ]

    if cfg.log_format.lower() == "json":
        # format_exc_info serialises tracebacks to strings for JSON output;
        # ConsoleRenderer handles exception rendering natively so adding
        # format_exc_info with it causes a UserWarning.
        shared_processors.append(structlog.processors.format_exc_info)
        renderer: structlog.typing.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=StderrPrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def get_logger() -> structlog.BoundLogger:
    return cast(structlog.BoundLogger, structlog.get_logger("lockknife"))
