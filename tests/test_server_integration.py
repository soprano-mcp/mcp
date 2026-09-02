from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import respx
from asgi_lifespan import LifespanManager
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.transport_security import TransportSecuritySettings

from mems_mcp.server import mcp as mcp_server

DOMAIN = "https://aus.sopranodesign.com"

CONNECTION_HEADERS = {
    "X-Soprano-Domain-Url": DOMAIN,
    "X-Soprano-Auth-Method": "api_key",
    "X-Soprano-Api-Id": "12345",
    "X-Soprano-Api-Key": "secret",
}


def _client_factory(app: Any) -> Any:
    def factory(headers: dict[str, str] | None = None, timeout: Any = None, auth: Any = None) -> httpx.AsyncClient:
        """Builds the MCP client's httpx.AsyncClient wired directly to our ASGI app in-process."""
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", headers=headers)

    return factory


async def _call_tool_end_to_end(tool_name: str, arguments: dict[str, Any], headers: dict[str, str] = CONNECTION_HEADERS) -> Any:
    """Exercises a tool call through the full Streamable HTTP + MCP protocol
    stack (not just a direct SopranoClient call), for tools whose payload
    shape/auth path doesn't need a bespoke test like `send_message`'s above.
    """
    mcp_server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    # FastMCP lazily caches its StreamableHTTPSessionManager, which can only be
    # `.run()` once per instance - reset it so each test gets a fresh one,
    # since `mcp_server` is a module-level singleton shared across tests.
    mcp_server._session_manager = None
    app = mcp_server.streamable_http_app()
    async with LifespanManager(app):
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers=headers,
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool(tool_name, arguments)


@respx.mock
async def test_send_message_end_to_end() -> None:
    """Exercises the full Streamable HTTP request path (real MCP protocol
    handshake + tool call), confirming the tool reads X-Soprano-* headers off
    the raw HTTP request (see connection.py) and calls the (respx-mocked)
    Soprano API accordingly. Also confirms missing connection headers surface
    as a clean tool error rather than a crash.
    """
    route = respx.post(f"{DOMAIN}/cgpapi/messages/sms").mock(
        return_value=httpx.Response(201, json={"id": 2150400270, "destination": "61299002200", "status": "ENROUTE"})
    )

    mcp_server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    app = mcp_server.streamable_http_app()
    async with LifespanManager(app):
        # Case 1: valid Soprano connection headers -> tool succeeds
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers=CONNECTION_HEADERS,
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "send_message",
                    {"channel": "sms", "destination": "61299002200", "text": "Hello"},
                )

        assert result.isError is False
        assert route.called
        sent_request = route.calls.last.request
        assert sent_request.headers["X-MEMS-API-ID"] == "12345"
        assert sent_request.headers["X-MEMS-API-KEY"] == "secret"

        # Case 2: missing connection headers -> clean tool error, not a crash
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers={},
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "send_message",
                    {"channel": "sms", "destination": "61299002200", "text": "Hello"},
                )

        assert result.isError is True
        assert "X-Soprano-Domain-Url" in result.content[0].text


@respx.mock
async def test_send_message_falls_back_to_soprano_env_vars_when_headers_missing(monkeypatch: Any) -> None:
    """Clients that can't send custom X-Soprano-* headers (e.g. Zendesk's MCP
    connector) still work if a default connection is configured via SOPRANO_*
    env vars - same vars the stdio transport already uses."""
    monkeypatch.setenv("SOPRANO_DOMAIN_URL", DOMAIN)
    monkeypatch.setenv("SOPRANO_AUTH_METHOD", "api_key")
    monkeypatch.setenv("SOPRANO_API_ID", "env-id")
    monkeypatch.setenv("SOPRANO_API_KEY", "env-key")

    route = respx.post(f"{DOMAIN}/cgpapi/messages/sms").mock(
        return_value=httpx.Response(201, json={"id": 2150400270, "destination": "61299002200", "status": "ENROUTE"})
    )

    mcp_server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    mcp_server._session_manager = None
    app = mcp_server.streamable_http_app()
    async with LifespanManager(app):
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers={},
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "send_message",
                    {"channel": "sms", "destination": "61299002200", "text": "Hello"},
                )

    assert result.isError is False
    assert route.called
    assert route.calls.last.request.headers["X-MEMS-API-ID"] == "env-id"


@respx.mock
async def test_send_message_forwards_extra_for_rich_channel_content() -> None:
    """Confirms the `extra` tool parameter reaches the outgoing Soprano payload
    verbatim, so rich channel-specific content (RCS cards, WhatsApp interactive
    messages, etc.) not covered by dedicated tool parameters can still be sent.
    """
    route = respx.post(f"{DOMAIN}/cgpapi/messages/rcs").mock(
        return_value=httpx.Response(201, json={"id": 2150400271, "destination": "61299002200", "status": "ENROUTE"})
    )

    mcp_server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    # FastMCP lazily caches its StreamableHTTPSessionManager, which can only be
    # `.run()` once per instance - reset it so this test gets a fresh one,
    # since `mcp_server` is a module-level singleton shared across tests.
    mcp_server._session_manager = None
    app = mcp_server.streamable_http_app()
    async with LifespanManager(app):
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers=CONNECTION_HEADERS,
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "send_message",
                    {
                        "channel": "rcs",
                        "destination": "61299002200",
                        "text": "Hello",
                        "extra": {"rcs": {"suggestions": [{"text": "Yes", "postbackData": "yes123"}]}},
                    },
                )

        assert result.isError is False
        assert route.called
        sent_body = route.calls.last.request.content
        assert json.loads(sent_body)["rcs"] == {"suggestions": [{"text": "Yes", "postbackData": "yes123"}]}


@respx.mock
async def test_send_message_with_typed_whatsapp_interactive_content() -> None:
    """Confirms the dedicated `whatsapp` tool parameter (typed rich content,
    added alongside the generic `extra` escape hatch) is validated and
    serialized to the correct camelCase Connect API payload.
    """
    route = respx.post(f"{DOMAIN}/cgpapi/messages/whatsapp").mock(
        return_value=httpx.Response(201, json={"id": 7469674, "destination": "61491089858", "status": "ENROUTE"})
    )

    mcp_server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    mcp_server._session_manager = None
    app = mcp_server.streamable_http_app()
    async with LifespanManager(app):
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers=CONNECTION_HEADERS,
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "send_message",
                    {
                        "channel": "whatsapp",
                        "destination": "61491089858",
                        "whatsapp": {
                            "type": "interactive",
                            "interactive": {
                                "type": "button",
                                "body": {"text": "how are you?"},
                                "action": {"buttons": [{"title": "Good", "postback_data": "good123"}]},
                            },
                        },
                    },
                )

        assert result.isError is False
        assert route.called
        sent_body = json.loads(route.calls.last.request.content)
        assert sent_body["whatsapp"]["interactive"]["action"]["buttons"] == [
            {"type": "reply", "title": "Good", "postbackData": "good123"}
        ]


@respx.mock
async def test_list_whatsapp_templates_uses_session_cookie_auth() -> None:
    """Confirms `list_whatsapp_templates` reads the `session_cookie` auth
    outlier (X-Soprano-Auth-Method: session_cookie + X-Soprano-Session-Cookie)
    end-to-end through the real Streamable HTTP transport.
    """
    route = respx.get(f"{DOMAIN}/cgpapi/waba/templates").mock(
        return_value=httpx.Response(200, json=[{"name": "hello_world", "language": "en", "status": "APPROVED"}])
    )

    mcp_server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    mcp_server._session_manager = None
    app = mcp_server.streamable_http_app()
    session_cookie_headers = {
        "X-Soprano-Domain-Url": DOMAIN,
        "X-Soprano-Auth-Method": "session_cookie",
        "X-Soprano-Session-Cookie": "ABC123DEF456",
    }
    async with LifespanManager(app):
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers=session_cookie_headers,
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("list_whatsapp_templates", {})

        assert result.isError is False
        assert route.called


@respx.mock
async def test_get_message_status_end_to_end() -> None:
    route = respx.get(f"{DOMAIN}/cgpapi/messages/sms/2150400270").mock(
        return_value=httpx.Response(200, json={"id": 2150400270, "status": "SENT"})
    )

    result = await _call_tool_end_to_end("get_message_status", {"channel": "sms", "message_id": "2150400270"})

    assert result.isError is False
    assert route.called


@respx.mock
async def test_send_batch_end_to_end() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/batch/messages").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "status": "ENROUTE"}, {"id": 2, "status": "ENROUTE"}])
    )

    result = await _call_tool_end_to_end(
        "send_batch",
        {
            "messages": [
                {"channel": "sms", "destination": "61299002200", "text": "msg1"},
                {"channel": "sms", "destination": "61299002200", "text": "msg2"},
            ]
        },
    )

    assert result.isError is False
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == [
        {"messageType": "sms", "destination": "61299002200", "text": "msg1"},
        {"messageType": "sms", "destination": "61299002200", "text": "msg2"},
    ]


@respx.mock
async def test_get_batch_status_end_to_end() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/batch/messages/status").mock(
        return_value=httpx.Response(200, json=[{"id": 2148226149, "status": "ACCEPTED_BY_NETWORK_ELEMENT"}])
    )

    result = await _call_tool_end_to_end("get_batch_status", {"items": [{"id": 2148226149, "message_type": "SMS"}]})

    assert result.isError is False
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == [{"id": 2148226149, "messageType": "SMS"}]


@respx.mock
async def test_send_broadcast_end_to_end() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/broadcast/sms").mock(return_value=httpx.Response(201, json={"id": 696654}))

    result = await _call_tool_end_to_end(
        "send_broadcast", {"text": "Hello Broadcast", "endpoints": [{"type": 1, "id": 211232}]}
    )

    assert result.isError is False
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == {"message": {"text": "Hello Broadcast"}, "endpoints": [{"type": 1, "id": 211232}]}


@respx.mock
async def test_upload_whatsapp_media_end_to_end() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/waba/media/61490254749").mock(
        return_value=httpx.Response(201, json={"id": "155555327322099001"})
    )

    result = await _call_tool_end_to_end(
        "upload_whatsapp_media",
        {
            "source": "61490254749",
            "filename": "image.jpg",
            "content_type": "image/jpeg",
            "file_content_base64": base64.b64encode(b"fake-image-bytes").decode(),
        },
    )

    assert result.isError is False
    assert route.called
    assert b"fake-image-bytes" in route.calls.last.request.content


@respx.mock
async def test_delete_whatsapp_media_end_to_end() -> None:
    route = respx.delete(f"{DOMAIN}/cgpapi/waba/media/155555327322099001").mock(return_value=httpx.Response(204))

    result = await _call_tool_end_to_end("delete_whatsapp_media", {"media_id": "155555327322099001"})

    assert result.isError is False
    assert route.called
