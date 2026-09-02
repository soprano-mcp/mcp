from __future__ import annotations

import httpx
import pytest
import respx

from mems_mcp.auth.api_key import ApiKeyAuth
from mems_mcp.auth.session_cookie import SessionCookieAuth
from mems_mcp.connection import Connection
from mems_mcp.exceptions import SopranoAPIError
from mems_mcp.soprano_client import SopranoClient

DOMAIN = "https://aus.sopranodesign.com"


def _connection() -> Connection:
    return Connection(domain_url=DOMAIN, auth_strategy=ApiKeyAuth(api_id="12345", api_key="secret"))


@respx.mock
async def test_send_message_posts_to_channel_endpoint() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/messages/sms").mock(
        return_value=httpx.Response(201, json={"id": 2150400270, "destination": "61299002200", "status": "ENROUTE"})
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.send_message(_connection(), "sms", {"messageType": "sms", "destination": "61299002200", "text": "Hi"})

    assert result == {"id": 2150400270, "destination": "61299002200", "status": "ENROUTE"}
    sent_request = route.calls.last.request
    assert sent_request.headers["X-MEMS-API-ID"] == "12345"
    assert sent_request.headers["X-MEMS-API-KEY"] == "secret"


@respx.mock
async def test_get_message_status_queries_channel_and_id() -> None:
    respx.get(f"{DOMAIN}/cgpapi/messages/sms/2150400270").mock(
        return_value=httpx.Response(200, json={"id": 2150400270, "status": "SENT"})
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.get_message_status(_connection(), "sms", "2150400270")

    assert result == {"id": 2150400270, "status": "SENT"}


@respx.mock
async def test_send_batch_posts_array_payload() -> None:
    respx.post(f"{DOMAIN}/cgpapi/batch/messages").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "status": "ENROUTE"},
                {"id": 2, "status": "ENROUTE"},
            ],
        )
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.send_batch(
            _connection(),
            [
                {"messageType": "sms", "destination": "61299002200", "text": "msg1"},
                {"messageType": "sms", "destination": "61299002200", "text": "msg2"},
            ],
        )

    assert result == [{"id": 1, "status": "ENROUTE"}, {"id": 2, "status": "ENROUTE"}]


@respx.mock
async def test_get_batch_status_posts_ids() -> None:
    respx.post(f"{DOMAIN}/cgpapi/batch/messages/status").mock(
        return_value=httpx.Response(200, json=[{"id": 2148226149, "status": "ACCEPTED_BY_NETWORK_ELEMENT"}])
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.get_batch_status(_connection(), [{"id": 2148226149, "messageType": "SMS"}])

    assert result == [{"id": 2148226149, "status": "ACCEPTED_BY_NETWORK_ELEMENT"}]


@respx.mock
async def test_send_broadcast_posts_to_broadcast_endpoint() -> None:
    respx.post(f"{DOMAIN}/cgpapi/broadcast/sms").mock(return_value=httpx.Response(201, json={"id": 696654}))
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.send_broadcast(
            _connection(), {"message": {"text": "Hello"}, "endpoints": [{"type": 1, "id": 211232}]}
        )

    assert result == {"id": 696654}


@respx.mock
async def test_error_response_is_mapped_to_soprano_api_error() -> None:
    respx.post(f"{DOMAIN}/cgpapi/messages/sms").mock(
        return_value=httpx.Response(
            400,
            json={
                "statusCode": 400,
                "statusText": "Bad Request",
                "errorCode": 400102,
                "errorType": "CLIENT_ERROR",
                "errorDescription": "Submit message failed due to Error Code 505:Invalid source address",
            },
        )
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        with pytest.raises(SopranoAPIError) as exc_info:
            await client.send_message(_connection(), "sms", {"messageType": "sms", "destination": "x", "text": "Hi"})

    error = exc_info.value
    assert error.status_code == 400
    assert error.error_code == 400102
    assert error.error_type == "CLIENT_ERROR"
    assert "Invalid source address" in error.error_description


def _session_cookie_connection() -> Connection:
    return Connection(domain_url=DOMAIN, auth_strategy=SessionCookieAuth(session_cookie="ABC123DEF456"))


@respx.mock
async def test_list_whatsapp_templates_uses_session_cookie() -> None:
    route = respx.get(f"{DOMAIN}/cgpapi/waba/templates").mock(
        return_value=httpx.Response(200, json=[{"name": "hello_world", "language": "en", "status": "APPROVED"}])
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.list_whatsapp_templates(_session_cookie_connection())

    assert result == [{"name": "hello_world", "language": "en", "status": "APPROVED"}]
    assert route.calls.last.request.headers["Cookie"] == "JSESSIONID=ABC123DEF456"


@respx.mock
async def test_upload_whatsapp_media_sends_multipart_file() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/waba/media/61490254749").mock(
        return_value=httpx.Response(201, json={"id": "155555327322099001"})
    )
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        result = await client.upload_whatsapp_media(
            _connection(), "61490254749", b"fake-image-bytes", "image.jpg", "image/jpeg"
        )

    assert result == {"id": "155555327322099001"}
    sent_request = route.calls.last.request
    assert sent_request.headers["X-MEMS-API-ID"] == "12345"
    assert b"fake-image-bytes" in sent_request.content
    assert "multipart/form-data" in sent_request.headers["content-type"]


@respx.mock
async def test_delete_whatsapp_media_sends_delete_request() -> None:
    route = respx.delete(f"{DOMAIN}/cgpapi/waba/media/155555327322099001").mock(return_value=httpx.Response(204))
    async with httpx.AsyncClient() as http_client:
        client = SopranoClient(http_client)
        await client.delete_whatsapp_media(_connection(), "155555327322099001")

    assert route.called
