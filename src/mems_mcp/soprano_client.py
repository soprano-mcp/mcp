"""Thin async HTTP client for the Soprano Connect API.

Credentials and domain_url vary per MCP request (see
docs/mcp-server-implementation-plan.md), so a single shared `httpx.AsyncClient`
(created once in the server lifespan) is reused across requests, but no
Connect API state (tokens, cookies) is cached on it between calls.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from mems_mcp.connection import Connection
from mems_mcp.exceptions import SopranoAPIError
from mems_mcp.observability import emit_metric

DEFAULT_TIMEOUT = httpx.Timeout(30.0)

logger = logging.getLogger("mems_mcp.soprano_client")


class SopranoClient:
    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self._http_client = http_client

    async def send_message(self, connection: Connection, channel: str, payload: dict[str, Any]) -> dict[str, Any]:
        """`POST {domain_url}/cgpapi/messages/{channel}` - real-time mode send."""
        url = f"{connection.domain_url}/cgpapi/messages/{channel}"
        response = await self._request("POST", url, connection, operation="send_message", json=payload)
        return response.json()

    async def get_message_status(self, connection: Connection, channel: str, message_id: str) -> dict[str, Any]:
        """`GET {domain_url}/cgpapi/messages/{channel}/{id}` - query a single message's status.

        Confirmed GET per the Connect API guide's "Quering message status" section (the
        guide's own Supported Endpoints summary table lists this as POST, but that table is
        inconsistent with the detailed section - live testing confirms POST returns
        HTTP 405 Method Not Allowed, so GET is the correct verb here).
        """
        url = f"{connection.domain_url}/cgpapi/messages/{channel}/{message_id}"
        response = await self._request("GET", url, connection, operation="get_message_status")
        return response.json()

    async def send_batch(self, connection: Connection, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """`POST {domain_url}/cgpapi/batch/messages` - batch mode send."""
        url = f"{connection.domain_url}/cgpapi/batch/messages"
        response = await self._request("POST", url, connection, operation="send_batch", json=messages)
        return response.json()

    async def get_batch_status(self, connection: Connection, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """`POST {domain_url}/cgpapi/batch/messages/status` - query multiple messages' status."""
        url = f"{connection.domain_url}/cgpapi/batch/messages/status"
        response = await self._request("POST", url, connection, operation="get_batch_status", json=items)
        return response.json()

    async def send_broadcast(self, connection: Connection, payload: dict[str, Any]) -> dict[str, Any]:
        """`POST {domain_url}/cgpapi/broadcast/sms` - broadcast mode send."""
        url = f"{connection.domain_url}/cgpapi/broadcast/sms"
        response = await self._request("POST", url, connection, operation="send_broadcast", json=payload)
        return response.json()

    async def list_whatsapp_templates(self, connection: Connection) -> Any:
        """`GET {domain_url}/cgpapi/waba/templates` - list approved WABA templates.

        Requires the caller's `Connection` to use `SessionCookieAuth` (the one
        documented auth outlier for this endpoint - see connection.py).
        """
        url = f"{connection.domain_url}/cgpapi/waba/templates"
        response = await self._request("GET", url, connection, operation="list_whatsapp_templates")
        return response.json()

    async def upload_whatsapp_media(
        self, connection: Connection, source: str, file_bytes: bytes, filename: str, content_type: str
    ) -> dict[str, Any]:
        """`POST {domain_url}/cgpapi/waba/media/{source}` - upload media to Facebook for WhatsApp.

        `source` is the WhatsApp sender number the media is uploaded against.
        Uses the connection's normal auth strategy (not the session-cookie
        outlier - that's only required by `list_whatsapp_templates`).
        """
        url = f"{connection.domain_url}/cgpapi/waba/media/{source}"
        response = await self._request(
            "POST",
            url,
            connection,
            operation="upload_whatsapp_media",
            files={"file": (filename, file_bytes, content_type)},
        )
        return response.json()

    async def delete_whatsapp_media(self, connection: Connection, media_id: str) -> None:
        """`DELETE {domain_url}/cgpapi/waba/media/{id}` - delete media from Facebook."""
        url = f"{connection.domain_url}/cgpapi/waba/media/{media_id}"
        await self._request("DELETE", url, connection, operation="delete_whatsapp_media")

    async def _request(
        self, method: str, url: str, connection: Connection, *, operation: str, **kwargs: Any
    ) -> httpx.Response:
        auth_headers = await connection.auth_strategy.get_auth_headers(
            domain_url=connection.domain_url, http_client=self._http_client
        )
        headers = dict(auth_headers)
        if "json" in kwargs:
            # Only set Content-Type when there's an actual JSON body - sending it on
            # bodyless GET requests makes Soprano's server try (and fail) to parse an
            # empty body as JSON, surfacing as "Fatal problems with mapping JSON content".
            headers["Content-Type"] = "application/json;charset=UTF-8"
        start = time.perf_counter()
        try:
            response = await self._http_client.request(
                method, url, headers=headers, timeout=DEFAULT_TIMEOUT, **kwargs
            )
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "soprano call errored",
                extra={"operation": operation, "method": method, "duration_ms": round(duration_ms, 1), "error": str(exc)},
            )
            emit_metric("SopranoCallDuration", duration_ms, unit="Milliseconds", dimensions={"Operation": operation})
            emit_metric("SopranoCallError", 1, unit="Count", dimensions={"Operation": operation})
            raise
        duration_ms = (time.perf_counter() - start) * 1000
        logger.info(
            "soprano call completed",
            extra={
                "operation": operation,
                "method": method,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 1),
            },
        )
        emit_metric("SopranoCallDuration", duration_ms, unit="Milliseconds", dimensions={"Operation": operation})
        if response.status_code >= 400:
            emit_metric("SopranoCallError", 1, unit="Count", dimensions={"Operation": operation})
            _raise_for_error(response)
        return response


def _raise_for_error(response: httpx.Response) -> None:
    try:
        body = response.json()
    except ValueError:
        body = {}
    error_code = body.get("errorCode")
    error_type = body.get("errorType")
    error_description = body.get("errorDescription")
    message_parts = [f"HTTP {response.status_code}"]
    if error_type:
        message_parts.append(f"errorType={error_type}")
    if error_code is not None:
        message_parts.append(f"errorCode={error_code}")
    message_parts.append(error_description or "no errorDescription in response body")
    raise SopranoAPIError(
        " - ".join(message_parts),
        status_code=response.status_code,
        error_code=error_code,
        error_type=error_type,
        error_description=error_description,
    )
