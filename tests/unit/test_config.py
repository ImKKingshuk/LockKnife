import pathlib

from lockknife.core.config import LockKnifeConfig, _load_from_path


def test_load_toml_nested_lockknife(tmp_path: pathlib.Path) -> None:
    cfg_path = tmp_path / "lockknife.toml"
    cfg_path.write_text(
        """
[lockknife]
log_level = "DEBUG"
log_format = "json"
adb_path = "/usr/local/bin/adb"
""".lstrip(),
        encoding="utf-8",
    )

    cfg = _load_from_path(cfg_path)
    assert isinstance(cfg, LockKnifeConfig)
    assert cfg.log_level == "DEBUG"
    assert cfg.log_format == "json"
    assert cfg.adb_path == "/usr/local/bin/adb"


def test_load_legacy_conf(tmp_path: pathlib.Path) -> None:
    cfg_path = tmp_path / "lockknife.conf"
    cfg_path.write_text(
        """
LOG_LEVEL=WARNING
ADB_PATH=/opt/android/platform-tools/adb
""".lstrip(),
        encoding="utf-8",
    )

    cfg = _load_from_path(cfg_path)
    assert cfg.log_level == "WARNING"
    assert cfg.adb_path == "/opt/android/platform-tools/adb"
