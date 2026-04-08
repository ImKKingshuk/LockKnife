from __future__ import annotations

import sys

import click

from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.logging import get_logger
from lockknife_headless_cli._extract_all import register as _register_all
from lockknife_headless_cli._extract_basic import register as _register_basic
from lockknife_headless_cli._extract_browser import register as _register_browser
from lockknife_headless_cli._extract_messaging import register as _register_messaging
from lockknife_headless_cli._extract_misc import register as _register_misc


@click.group(
    help="Extract high-value artifacts from a connected Android device.", cls=LockKnifeGroup
)
def extract() -> None:
    pass


log = get_logger()


_module = sys.modules[__name__]
for _register in (
    _register_basic,
    _register_all,
    _register_browser,
    _register_messaging,
    _register_misc,
):
    _register(extract, _module)
del _register, _module
