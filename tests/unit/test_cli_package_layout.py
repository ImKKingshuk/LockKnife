def test_new_headless_cli_package_imports() -> None:
    from lockknife_headless_cli.main import cli

    assert cli.name == "cli"