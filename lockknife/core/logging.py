from __future__ import annotations

import logging
import sys
from typing import Any, cast

import structlog

from lockknife.core.config import LockKnifeConfig


class StderrPrintLoggerFactory:
    def __call__(self, *_args: Any) -> Any:
        return structlog.PrintLogger(file=sys.stderr)


def configure_logging(cfg: LockKnifeConfig) -> None:
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)

    shared_processors: list[structlog.typing.Processor] = [
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
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
