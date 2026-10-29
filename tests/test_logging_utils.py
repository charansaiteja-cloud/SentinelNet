from __future__ import annotations

import json
import logging

from sentinel_net.logging_utils import JsonFormatter, configure_logging


def test_json_formatter_emits_parseable_json() -> None:
    record = logging.LogRecord(
        name="sentinel_net",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="alert src=%s",
        args=("10.0.0.1",),
        exc_info=None,
    )
    record.ctx_alert = {"src": "10.0.0.1"}

    payload = json.loads(JsonFormatter().format(record))

    assert payload["level"] == "WARNING"
    assert payload["message"] == "alert src=10.0.0.1"
    assert payload["alert"] == {"src": "10.0.0.1"}
    assert payload["timestamp"]


def test_configure_logging_replaces_handlers() -> None:
    configure_logging("DEBUG", json_logs=True)
    root = logging.getLogger()

    assert root.level == logging.DEBUG
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
