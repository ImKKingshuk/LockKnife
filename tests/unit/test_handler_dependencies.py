import ast
import pathlib

import pytest


@pytest.mark.parametrize(("prefix", "namespace"), [("_extract", "cli"), ("_tui_callback", "cb")])
def test_handler_dependency_namespaces_are_complete(prefix: str, namespace: str) -> None:
    import lockknife_headless_cli.extract as extract
    import lockknife_headless_cli.tui_callback as callback
    from tests.unit.test_tui_callback import DummyApp

    callback.build_tui_callback(DummyApp())
    owner = extract if namespace == "cli" else callback
    root = pathlib.Path(owner.__file__).parent
    missing = {}
    for source in root.glob(f"{prefix}*.py"):
        attributes = {
            node.attr
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == namespace
        }
        absent = sorted(name for name in attributes if not hasattr(owner, name))
        if absent:
            missing[source.name] = absent
    assert not missing, missing
