from __future__ import annotations

import sys

import click

from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.logging import get_logger
from lockknife.core.output import console
from lockknife.modules.extraction.call_logs import extract_call_logs
from lockknife.modules.extraction.browser import (
    extract_chrome_bookmarks,
    extract_chrome_cookies,
    extract_chrome_downloads,
    extract_chrome_history,
    extract_chrome_saved_logins,
    extract_firefox_bookmarks,
    extract_firefox_history,
    extract_firefox_saved_logins,
)
from lockknife.modules.extraction.contacts import extract_contacts
from lockknife.modules.extraction.location import extract_location_artifacts, extract_location_snapshot
from lockknife.modules.extraction.media import extract_media_with_exif
from lockknife.modules.extraction.messaging import (
    extract_signal_artifacts,
    extract_signal_messages,
    extract_telegram_artifacts,
    extract_telegram_messages,
    extract_whatsapp_artifacts,
    extract_whatsapp_messages,
)
from lockknife.modules.extraction.sms import extract_sms

from lockknife_headless_cli._extract_all import register as _register_all
from lockknife_headless_cli._extract_basic import register as _register_basic
from lockknife_headless_cli._extract_browser import register as _register_browser
from lockknife_headless_cli._extract_helpers import _register_output, _resolve_case_output
from lockknife_headless_cli._extract_messaging import register as _register_messaging
from lockknife_headless_cli._extract_misc import register as _register_misc


@click.group(help="Extract high-value artifacts from a connected Android device.", cls=LockKnifeGroup)
def extract() -> None:
    pass


log = get_logger()


_module = sys.modules[__name__]
for _register in (_register_basic, _register_all, _register_browser, _register_messaging, _register_misc):
    _register(extract, _module)
del _register, _module
