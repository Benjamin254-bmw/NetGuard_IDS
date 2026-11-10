import json
import logging

from netguard_common.logging_config import configure_logging


def test_json_logging_has_utc_timestamp_and_service(capsys) -> None:  # type: ignore[no-untyped-def]
    configure_logging("unit", "INFO", "json")
    logging.getLogger("t").warning("hello %s", "world")
    rec = json.loads(capsys.readouterr().err.strip())
    assert rec["service"] == "unit" and rec["level"] == "WARNING"
    assert rec["message"] == "hello world" and rec["ts"].endswith("+00:00")


def test_level_filtering(capsys) -> None:  # type: ignore[no-untyped-def]
    configure_logging("unit", "ERROR", "text")
    logging.getLogger("t").warning("hidden")
    assert capsys.readouterr().err == ""
