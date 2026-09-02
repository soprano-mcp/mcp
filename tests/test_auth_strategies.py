from __future__ import annotations

import httpx
import pytest
import respx

from mems_mcp.auth.api_key import ApiKeyAuth
from mems_mcp.auth.basic import BasicAuth
from mems_mcp.auth.legacy_oauth2 import LegacyOAuth2Auth
from mems_mcp.auth.oauth2 import OAuth2Auth
from mems_mcp.auth.session_cookie import SessionCookieAuth
from mems_mcp.exceptions import SopranoAuthError

DOMAIN = "https://aus.sopranodesign.com"


async def test_api_key_auth_returns_static_headers() -> None:
    strategy = ApiKeyAuth(api_id="12345", api_key="secret-key")
    async with httpx.AsyncClient() as http_client:
        headers = await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)
    assert headers == {"X-MEMS-API-ID": "12345", "X-MEMS-API-KEY": "secret-key"}


async def test_basic_auth_base64_encodes_credentials() -> None:
    strategy = BasicAuth(username="user@url.com", password="mypwd01")
    async with httpx.AsyncClient() as http_client:
        headers = await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)
    assert headers == {"Authorization": "Basic dXNlckB1cmwuY29tOm15cHdkMDE="}


async def test_session_cookie_auth_returns_cookie_header() -> None:
    strategy = SessionCookieAuth(session_cookie="ABC123DEF456")
    async with httpx.AsyncClient() as http_client:
        headers = await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)
    assert headers == {"Cookie": "JSESSIONID=ABC123DEF456"}


@respx.mock
async def test_oauth2_auth_exchanges_client_credentials() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"accessToken": "abc123", "tokenType": "Bearer", "expiresIn": 1800})
    )
    strategy = OAuth2Auth(client_id="123456789", client_secret="abcdefgh")
    async with httpx.AsyncClient() as http_client:
        headers = await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)

    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["content-type"] == "application/x-www-form-urlencoded"
    body = sent_request.content.decode()
    assert "grant_type=client_credentials" in body
    assert "client_id=123456789" in body
    assert "client_secret=abcdefgh" in body
    assert headers == {"Authorization": "Bearer abc123"}


@respx.mock
async def test_oauth2_auth_accepts_live_snake_case_response() -> None:
    """Live-confirmed (2026-08-28): the real Connect API returns snake_case
    (access_token/token_type), not the camelCase this endpoint was originally
    assumed to use - must not regress to only accepting camelCase."""
    respx.post(f"{DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "abc123", "token_type": "Bearer", "expires_in": 1800})
    )
    strategy = OAuth2Auth(client_id="123456789", client_secret="abcdefgh")
    async with httpx.AsyncClient() as http_client:
        headers = await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)
    assert headers == {"Authorization": "Bearer abc123"}


@respx.mock
async def test_oauth2_auth_raises_on_failure() -> None:
    respx.post(f"{DOMAIN}/cgpapi/auth/token").mock(return_value=httpx.Response(401, text="invalid client"))
    strategy = OAuth2Auth(client_id="bad", client_secret="bad")
    async with httpx.AsyncClient() as http_client:
        with pytest.raises(SopranoAuthError):
            await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)


@respx.mock
async def test_legacy_oauth2_auth_logs_in() -> None:
    route = respx.post(f"{DOMAIN}/cgpapi/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={
                "accessToken": "legacy-access",
                "refreshToken": "legacy-refresh",
                "tokenType": "Bearer",
                "expiresIn": 1800,
            },
        )
    )
    strategy = LegacyOAuth2Auth(username="user@url.com", password="mypwd01")
    async with httpx.AsyncClient() as http_client:
        headers = await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)

    assert route.called
    assert route.calls.last.request.method == "POST"
    assert headers == {"Authorization": "Bearer legacy-access"}


@respx.mock
async def test_legacy_oauth2_auth_raises_on_failure() -> None:
    respx.post(f"{DOMAIN}/cgpapi/auth/login").mock(return_value=httpx.Response(401, text="invalid credentials"))
    strategy = LegacyOAuth2Auth(username="user@url.com", password="wrong")
    async with httpx.AsyncClient() as http_client:
        with pytest.raises(SopranoAuthError):
            await strategy.get_auth_headers(domain_url=DOMAIN, http_client=http_client)
