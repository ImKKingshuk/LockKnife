import json


def test_configure_logging_json_branch() -> None:
    from lockknife.core.config import LockKnifeConfig
    from lockknife.core.logging import configure_logging, get_logger

    configure_logging(LockKnifeConfig(log_level="INFO", log_format="json"))
    log = get_logger()
    log.info("x")


def test_structlog_writes_to_stderr(capsys) -> None:
    from lockknife.core.config import LockKnifeConfig
    from lockknife.core.logging import configure_logging, get_logger

    configure_logging(LockKnifeConfig(log_level="INFO", log_format="json"))
    get_logger().info("machine_readable")
    captured = capsys.readouterr()
    assert captured.out == ""
    payload = json.loads(captured.err.strip())
    assert payload["event"] == "machine_readable"
