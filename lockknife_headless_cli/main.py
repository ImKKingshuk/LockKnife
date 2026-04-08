from __future__ import annotations

import pathlib
import signal
from types import FrameType

import click
from rich.panel import Panel

from lockknife import __version__
from lockknife.core.adb import AdbClient
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.config import LoadedConfig, load_config
from lockknife.core.device import DeviceManager
from lockknife.core.logging import configure_logging, get_logger
from lockknife.core.output import console
from lockknife.core.plugin import import_submodules
from lockknife.modules.base import load_registered_modules
from lockknife_headless_cli.ai import ai
from lockknife_headless_cli.analyze import analyze
from lockknife_headless_cli.apk import apk
from lockknife_headless_cli.case import case_group
from lockknife_headless_cli.completion import completion
from lockknife_headless_cli.crack import crack
from lockknife_headless_cli.crypto_wallet import crypto_wallet
from lockknife_headless_cli.device import device
from lockknife_headless_cli.exploit import exploit
from lockknife_headless_cli.extract import extract
from lockknife_headless_cli.features import features_cmd
from lockknife_headless_cli.forensics import forensics
from lockknife_headless_cli.health import doctor_cmd, health_cmd
from lockknife_headless_cli.intel import intel
from lockknife_headless_cli.interactive import interactive
from lockknife_headless_cli.network import network
from lockknife_headless_cli.plugins import plugins_group
from lockknife_headless_cli.report import report
from lockknife_headless_cli.runtime import runtime
from lockknife_headless_cli.security import security


class AppContext:
    def __init__(self, loaded: LoadedConfig) -> None:
        self.loaded = loaded
        self.log = get_logger()
        self.adb = AdbClient(adb_path=loaded.config.adb_path or "adb")
        self.devices = DeviceManager(self.adb)


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
    cls=LockKnifeGroup,
)
@click.option("--config", "config_path", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option(
    "--cli", "headless", is_flag=True, default=False, help="Run the Click CLI instead of the TUI."
)
@click.option("--headless", "headless", is_flag=True, default=False, help="Alias for --cli.")
@click.version_option(__version__, "--version", "-V")
@click.pass_context
def cli(ctx: click.Context, config_path: pathlib.Path | None, headless: bool) -> None:
    if config_path:
        from lockknife.core.config import _load_from_path

        loaded = LoadedConfig(config=_load_from_path(config_path), path=config_path)
    else:
        loaded = load_config()

    configure_logging(loaded.config)
    ctx.obj = AppContext(loaded)
    import_submodules("lockknife.modules")
    load_registered_modules()

    def _handle_signal(signum: int, _frame: FrameType | None) -> None:
        ctx.obj.log.warning("signal_received", signal=signum)
        from lockknife.core.cleanup import cleanup_all

        cleanup_all()
        ctx.exit(128 + int(signum))

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if ctx.invoked_subcommand is None and not headless:
        try:
            from lockknife import lockknife_core
            from lockknife.core.cleanup import register_terminal_cleanup
            from lockknife_headless_cli.tui_callback import build_tui_callback
        except Exception as exc:
            raise click.ClickException(
                "TUI unavailable: lockknife_core extension not loaded"
            ) from exc

        # Register terminal cleanup callback for crash recovery
        def _restore_terminal() -> None:
            """Python-side terminal restoration as fallback."""
            try:
                import subprocess
                subprocess.run(["stty", "sane"], check=False, capture_output=True)
            except Exception:
                pass  # Best effort

        register_terminal_cleanup(_restore_terminal)

        callback = build_tui_callback(ctx.obj)
        try:
            lockknife_core.run_tui(callback)
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc
        return

    if ctx.invoked_subcommand is None:
        banner = "\n".join(
            [
                " _                _  __ _      _  __      _  __     ",
                "| |    ___   ___ | |/ /| |    (_)/ _| ___| |/ / ___ ",
                "| |   / _ \\ / _ \\| ' / | |    | | |_ / _ \\ ' / / _ \\",
                "| |__| (_) | (_) | . \\ | |___ | |  _|  __/ . \\|  __/",
                "|_____\\___/ \\___/|_|\\_\\|_____|/ |_|  \\___|_|\\_\\\\___|",
                "                                 |__/               ",
                f"v{__version__}",
                "",
                "Tip: run `lockknife interactive` for the classic menu UI.",
            ]
        )
        console.print(Panel.fit(banner, title="LockKnife", border_style="red"))


cli.add_command(device)
cli.add_command(case_group)
cli.add_command(crack)
cli.add_command(extract)
cli.add_command(apk)
cli.add_command(analyze)
cli.add_command(forensics)
cli.add_command(runtime)
cli.add_command(report)
cli.add_command(security)
cli.add_command(intel)
cli.add_command(ai)
cli.add_command(network)
cli.add_command(crypto_wallet)
cli.add_command(interactive)
cli.add_command(completion)
cli.add_command(health_cmd)
cli.add_command(doctor_cmd)
cli.add_command(features_cmd)
cli.add_command(plugins_group)
cli.add_command(exploit)
