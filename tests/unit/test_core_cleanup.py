import pathlib

from lockknife.core.cleanup import cleanup_all, register_temp_path, unregister_temp_path


def test_cleanup_all_removes_registered(tmp_path: pathlib.Path) -> None:
    d = tmp_path / "temp"
    d.mkdir()
    register_temp_path(d)
    cleanup_all()
    assert not d.exists()


def test_unregister_does_not_remove(tmp_path: pathlib.Path) -> None:
    d = tmp_path / "temp2"
    d.mkdir()
    register_temp_path(d)
    unregister_temp_path(d)
    cleanup_all()
    assert d.exists()
