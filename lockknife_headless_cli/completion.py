from __future__ import annotations

import click


@click.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"], case_sensitive=False))
def completion(shell: str) -> None:
    from click.shell_completion import get_completion_class

    ctx = click.get_current_context()
    root = ctx.find_root()
    prog = root.info_name or "lockknife"
    complete_var = f"_{prog.replace('-', '_').upper()}_COMPLETE"

    complete_cls = get_completion_class(shell.lower())
    if complete_cls is None:
        raise click.ClickException(f"Shell completion is not available for {shell}")
    completer = complete_cls(root.command, {}, prog, complete_var)
    click.echo(completer.source())
