"""Structured logging + CloudWatch metrics for this server.

No new AWS infrastructure or IAM permissions are required for any of this:
both ECS (via the `awslogs` log driver) and Lambda automatically ship
whatever the container writes to stdout/stderr to CloudWatch Logs. This
module just makes that output useful:

- `configure_logging()` makes regular `logging.getLogger(...)` calls emit one
  JSON object per line (instead of default plain text) - trivially queryable
  via CloudWatch Logs Insights (e.g. `filter level = "ERROR"`).
- `emit_metric()` writes a CloudWatch Embedded Metric Format (EMF) JSON line
  to stdout. CloudWatch Logs recognizes the `_aws` key and automatically
  extracts real CloudWatch Metrics from it - no `cloudwatch:PutMetricData`
  IAM permission or extra AWS SDK calls needed, unlike the regular
  `boto3.client("cloudwatch").put_metric_data(...)` approach.
- `observe_tool` is a decorator for `@mcp.tool()` functions that logs+meters
  every call (duration, outcome) with zero per-tool boilerplate.
"""

from __future__ import annotations

import functools
import json
import logging
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, TypeVar

_F = TypeVar("_F", bound=Callable[..., Awaitable[Any]])

METRICS_NAMESPACE = "mems-mcp"


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # `logging.Formatter.formatTime` uses `time.strftime`, which has no
        # `%f` (microseconds) directive - that's a `datetime.strftime`-only
        # feature, so `%f` was previously passed through literally as "f".
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        doc: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Extra fields passed via `logger.info(..., extra={...})`.
        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_RECORD_FIELDS:
                doc[key] = value
        if record.exc_info:
            doc["exception"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)


_STANDARD_LOG_RECORD_FIELDS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)

_configured = False


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent - safe to call from multiple entrypoints (server.py, asgi.py)."""
    global _configured
    if _configured:
        return
    _configured = True
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


def emit_metric(
    name: str,
    value: float,
    *,
    unit: str = "None",
    dimensions: dict[str, str] | None = None,
    **properties: Any,
) -> None:
    """Writes one CloudWatch EMF log line to stdout (see module docstring).

    Printed directly (not via `logging`) so the JSON log formatter above
    doesn't wrap/mangle the `_aws` structure CloudWatch looks for.
    """
    dimensions = dimensions or {}
    doc: dict[str, Any] = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": METRICS_NAMESPACE,
                    "Dimensions": [list(dimensions.keys())] if dimensions else [[]],
                    "Metrics": [{"Name": name, "Unit": unit}],
                }
            ],
        },
        name: value,
        **dimensions,
        **properties,
    }
    print(json.dumps(doc, default=str), flush=True)


def observe_tool(func: _F) -> _F:
    """Decorator for `@mcp.tool()` functions: logs + meters every call.

    Emits `ToolCallDuration` (Milliseconds, dimensioned by Tool) on every
    call, and `ToolCallError` (Count, dimensioned by Tool) additionally when
    the call raises. Exceptions are re-raised unchanged (the mcp SDK itself
    turns them into a clean `CallToolResult(isError=True, ...)` - this
    decorator only observes, it doesn't change tool error behavior).
    """
    logger = logging.getLogger("mems_mcp.tool")
    tool_name = func.__name__

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            result = await func(*args, **kwargs)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "tool call failed",
                extra={"tool": tool_name, "duration_ms": round(duration_ms, 1), "error": str(exc)},
            )
            emit_metric("ToolCallDuration", duration_ms, unit="Milliseconds", dimensions={"Tool": tool_name})
            emit_metric("ToolCallError", 1, unit="Count", dimensions={"Tool": tool_name})
            raise
        duration_ms = (time.perf_counter() - start) * 1000
        logger.info("tool call succeeded", extra={"tool": tool_name, "duration_ms": round(duration_ms, 1)})
        emit_metric("ToolCallDuration", duration_ms, unit="Milliseconds", dimensions={"Tool": tool_name})
        return result

    return wrapper  # type: ignore[return-value]
