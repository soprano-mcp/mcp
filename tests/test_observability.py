import json
import logging

import pytest

from mems_mcp.observability import emit_metric, observe_tool


def test_json_formatter_produces_valid_iso_timestamp(caplog):
    import mems_mcp.observability as observability

    observability._configured = False
    observability.configure_logging()
    logger = logging.getLogger("mems_mcp.test")

    import io
    import sys

    buf = io.StringIO()
    logging.getLogger().handlers[0].stream = buf
    logger.info("hello", extra={"tool": "send_message"})

    line = json.loads(buf.getvalue().strip())
    assert line["message"] == "hello"
    assert line["tool"] == "send_message"
    # Must be a real ISO-8601 timestamp with milliseconds, not a literal "f".
    assert "f" not in line["timestamp"].split(".")[-1].rstrip("Z")
    assert line["timestamp"].endswith("Z")


def test_emit_metric_writes_valid_emf_json(capsys):
    emit_metric("ToolCallDuration", 12.5, unit="Milliseconds", dimensions={"Tool": "send_message"})
    out = capsys.readouterr().out.strip()
    doc = json.loads(out)
    assert doc["ToolCallDuration"] == 12.5
    assert doc["Tool"] == "send_message"
    assert doc["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "mems-mcp"
    assert doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [["Tool"]]


async def test_observe_tool_meters_success(capsys):
    @observe_tool
    async def my_tool(x: int) -> int:
        return x + 1

    result = await my_tool(1)
    assert result == 2
    out = capsys.readouterr().out
    docs = [json.loads(line) for line in out.strip().splitlines()]
    assert any(d.get("ToolCallDuration") is not None and d.get("Tool") == "my_tool" for d in docs)


async def test_observe_tool_meters_and_reraises_error(capsys):
    @observe_tool
    async def failing_tool() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await failing_tool()

    out = capsys.readouterr().out
    docs = [json.loads(line) for line in out.strip().splitlines()]
    assert any(d.get("ToolCallError") == 1 and d.get("Tool") == "failing_tool" for d in docs)
