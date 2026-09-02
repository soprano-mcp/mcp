from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import parse_qs, urlparse

import boto3
import httpx
import jwt
import pytest
import respx
from moto import mock_aws
from starlette.applications import Starlette
from starlette.routing import Route

from mems_mcp.auth import oauth_server
from mems_mcp.auth.mcp_oauth import JWTBearerTokenVerifier
from mems_mcp.auth.oauth_store import OAuthStore
from mems_mcp.exceptions import SopranoAuthError

CONNECT_DOMAIN = "https://aus.sopranodesign.com"
ISSUER = "https://mcp-aus.sopranodesign.com"
REDIRECT_URI = "https://zendesk.example.com/callback"

CLIENTS_TABLE = "test-oauth-clients"
CODES_TABLE = "test-oauth-codes"
CONSENTS_TABLE = "test-oauth-consents"
AUDIT_TABLE = "test-oauth-audit"
LAYER2_CREDENTIALS_TABLE = "test-oauth-layer2-credentials"
REFRESH_TOKENS_TABLE = "test-oauth-refresh-tokens"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMS_CONNECT_API_URL", CONNECT_DOMAIN)
    monkeypatch.setenv("MCP_OAUTH_RESOURCE_SERVER_URL", ISSUER)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    monkeypatch.setenv("MCP_OAUTH_CLIENTS_TABLE", CLIENTS_TABLE)
    monkeypatch.setenv("MCP_OAUTH_CODES_TABLE", CODES_TABLE)
    monkeypatch.setenv("MCP_OAUTH_CONSENTS_TABLE", CONSENTS_TABLE)
    monkeypatch.setenv("MCP_OAUTH_AUDIT_TABLE", AUDIT_TABLE)
    monkeypatch.setenv("MCP_OAUTH_LAYER2_CREDENTIALS_TABLE", LAYER2_CREDENTIALS_TABLE)
    monkeypatch.setenv("MCP_OAUTH_REFRESH_TOKENS_TABLE", REFRESH_TOKENS_TABLE)


@pytest.fixture
def dynamo_client():
    with mock_aws():
        db = boto3.resource("dynamodb", region_name="eu-west-2")
        db.create_table(
            TableName=CLIENTS_TABLE,
            KeySchema=[{"AttributeName": "client_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "client_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=CODES_TABLE,
            KeySchema=[{"AttributeName": "code", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "code", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=CONSENTS_TABLE,
            KeySchema=[
                {"AttributeName": "api_id", "KeyType": "HASH"},
                {"AttributeName": "client_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "api_id", "AttributeType": "S"},
                {"AttributeName": "client_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=LAYER2_CREDENTIALS_TABLE,
            KeySchema=[{"AttributeName": "api_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "api_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=REFRESH_TOKENS_TABLE,
            KeySchema=[{"AttributeName": "refresh_token", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "refresh_token", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.Table(CLIENTS_TABLE).put_item(
            Item={
                "client_id": "zendesk-agent",
                "name": "Zendesk Agent",
                "require_consent": True,
                "allowed_grant_types": ["authorization_code"],
                "redirect_uris": [REDIRECT_URI],
                "allowed_scopes": ["message.send"],
            }
        )
        yield db


def _app() -> Starlette:
    return Starlette(
        routes=[
            Route("/oauth/authorize", oauth_server.handle_authorize_get, methods=["GET"]),
            Route("/oauth/authorize", oauth_server.handle_authorize_post, methods=["POST"]),
            Route("/oauth/token", oauth_server.handle_token, methods=["POST"]),
            Route("/oauth/register", oauth_server.handle_register, methods=["POST"]),
            Route("/.well-known/jwks.json", oauth_server.handle_jwks, methods=["GET"]),
            Route(
                "/.well-known/oauth-authorization-server",
                oauth_server.handle_authorization_server_metadata,
                methods=["GET"],
            ),
        ]
    )


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=_app()), base_url=ISSUER)


def _public_key_from_jwks(jwks: dict) -> jwt.PyJWK:
    return jwt.PyJWK.from_dict(jwks["keys"][0])


@respx.mock
async def test_authorize_get_renders_login_form(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "zendesk-agent",
                "redirect_uri": REDIRECT_URI,
                "state": "xyz",
                "scope": "message.send",
            },
        )
    assert response.status_code == 200
    assert "Zendesk Agent" in response.text
    assert "api_id" in response.text


@respx.mock
async def test_authorize_get_unknown_client_rejected(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.get(
            "/oauth/authorize",
            params={"response_type": "code", "client_id": "nope", "redirect_uri": REDIRECT_URI},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


@respx.mock
async def test_full_authorization_code_flow_with_pkce(dynamo_client) -> None:
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"accessToken": "real-connect-token", "tokenType": "Bearer"})
    )
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()

    async with await _client() as client:
        approve_response = await client.post(
            "/oauth/authorize",
            data={
                "client_id": "zendesk-agent",
                "redirect_uri": REDIRECT_URI,
                "state": "xyz",
                "scope": "message.send",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "api_id": "12345",
                "api_key": "secret",
                "action": "approve",
            },
        )
        assert approve_response.status_code == 302
        location = approve_response.headers["location"]
        query = parse_qs(urlparse(location).query)
        assert query["state"] == ["xyz"]
        code = query["code"][0]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": "zendesk-agent",
                "code_verifier": code_verifier,
            },
        )
        assert token_response.status_code == 200
        body = token_response.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == oauth_server.ACCESS_TOKEN_TTL_SECONDS
        assert "refresh_token" in body

        jwks_response = await client.get("/.well-known/jwks.json")
    jwk = _public_key_from_jwks(jwks_response.json())
    claims = jwt.decode(body["access_token"], jwk.key, algorithms=["RS256"], issuer=ISSUER, audience=ISSUER)
    assert claims["sub"] == "12345"
    assert claims["api_id"] == "12345"
    assert claims["client_id"] == "zendesk-agent"
    assert claims["scope"] == "message.send"

    # The auth code is redeemable more than once within its TTL (NOT strict
    # single-use) - see oauth_store.consume_auth_code's docstring: Zendesk's
    # ZIS platform fires duplicate near-simultaneous token exchange requests
    # for the same code, and both must succeed.
    async with await _client() as client:
        replay_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": "zendesk-agent",
                "code_verifier": code_verifier,
            },
        )
    assert replay_response.status_code == 200


@respx.mock
async def test_refresh_token_grant_issues_new_access_and_refresh_token(dynamo_client) -> None:
    store = OAuthStore(dynamodb_resource=dynamo_client)
    refresh_token = store.create_refresh_token(
        client_id="zendesk-agent", api_id="12345", scope="message.send", ttl_seconds=oauth_server.REFRESH_TOKEN_TTL_SECONDS
    )

    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "zendesk-agent"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "message.send"
    assert "refresh_token" in body
    assert body["refresh_token"] != refresh_token  # rotated - never the same value twice

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "12345"
    assert claims["client_id"] == "zendesk-agent"


@respx.mock
async def test_refresh_token_grant_renews_layer2_credential_ttl(dynamo_client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression test: previously a client that only ever refreshed (never
    re-logged-in) would have its Layer 2 credential cache silently expire
    after ACCESS_TOKEN_TTL_SECONDS - confirmed real-world break: Zendesk's
    list_whatsapp_templates started failing ~1hr after login with "No cached
    Layer 2 credential" despite refresh tokens still working fine.
    """
    monkeypatch.setenv("MCP_OAUTH_LAYER2_FALLBACK", "true")
    store = OAuthStore(dynamodb_resource=dynamo_client)
    store.put_layer2_credential(api_id="12345", api_key="still-the-real-secret", ttl_seconds=1)  # about to expire
    refresh_token = store.create_refresh_token(
        client_id="zendesk-agent", api_id="12345", scope="message.send", ttl_seconds=oauth_server.REFRESH_TOKEN_TTL_SECONDS
    )

    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "zendesk-agent"},
        )
    assert response.status_code == 200

    credential = store.get_layer2_credential("12345")
    assert credential is not None
    assert credential.api_key == "still-the-real-secret"


@respx.mock
async def test_refresh_token_is_single_use(dynamo_client) -> None:
    store = OAuthStore(dynamodb_resource=dynamo_client)
    refresh_token = store.create_refresh_token(
        client_id="zendesk-agent", api_id="12345", scope="", ttl_seconds=oauth_server.REFRESH_TOKEN_TTL_SECONDS
    )

    async with await _client() as client:
        first = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "zendesk-agent"},
        )
        assert first.status_code == 200

        replay = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "zendesk-agent"},
        )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


@respx.mock
async def test_refresh_token_grant_rejects_client_id_mismatch(dynamo_client) -> None:
    store = OAuthStore(dynamodb_resource=dynamo_client)
    refresh_token = store.create_refresh_token(
        client_id="zendesk-agent", api_id="12345", scope="", ttl_seconds=oauth_server.REFRESH_TOKEN_TTL_SECONDS
    )

    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": "some-other-client"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


@respx.mock
async def test_refresh_token_grant_rejects_unknown_token(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "does-not-exist", "client_id": "zendesk-agent"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


@respx.mock
async def test_refresh_token_grant_accepts_client_id_via_basic_auth(dynamo_client) -> None:
    """Regression test: a client (confirmed real-world: a Zendesk ZIS
    connection) that sends its client_id via `Authorization: Basic` instead
    of the form body must not be rejected as a client_id mismatch - that
    previously burned the caller's one-shot refresh token on every attempt
    with no way to recover short of a full re-login.
    """
    store = OAuthStore(dynamodb_resource=dynamo_client)
    refresh_token = store.create_refresh_token(
        client_id="zendesk-agent", api_id="12345", scope="message.send", ttl_seconds=oauth_server.REFRESH_TOKEN_TTL_SECONDS
    )
    basic = base64.b64encode(b"zendesk-agent:unused").decode()

    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            headers={"Authorization": f"Basic {basic}"},
        )
    assert response.status_code == 200
    assert response.json()["scope"] == "message.send"


@respx.mock
async def test_authorization_code_flow_rejects_wrong_pkce_verifier(dynamo_client) -> None:
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"accessToken": "real-connect-token"})
    )
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(b"correct-verifier").digest()).rstrip(b"=").decode()

    async with await _client() as client:
        approve_response = await client.post(
            "/oauth/authorize",
            data={
                "client_id": "zendesk-agent",
                "redirect_uri": REDIRECT_URI,
                "state": "xyz",
                "scope": "message.send",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "api_id": "12345",
                "api_key": "secret",
                "action": "approve",
            },
        )
        code = parse_qs(urlparse(approve_response.headers["location"]).query)["code"][0]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": "zendesk-agent",
                "code_verifier": "wrong-verifier",
            },
        )
    assert token_response.status_code == 400
    assert token_response.json()["error"] == "invalid_grant"


@respx.mock
async def test_authorize_post_deny_redirects_with_access_denied(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.post(
            "/oauth/authorize",
            data={"client_id": "zendesk-agent", "redirect_uri": REDIRECT_URI, "state": "xyz", "action": "deny"},
        )
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["xyz"]


@respx.mock
async def test_authorize_post_invalid_connect_credentials_rerenders_form(dynamo_client) -> None:
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(return_value=httpx.Response(401))
    async with await _client() as client:
        response = await client.post(
            "/oauth/authorize",
            data={
                "client_id": "zendesk-agent",
                "redirect_uri": REDIRECT_URI,
                "state": "xyz",
                "scope": "message.send",
                "api_id": "12345",
                "api_key": "wrong",
                "action": "approve",
            },
        )
    assert response.status_code == 401
    assert "Invalid Connect API ID or API Key" in response.text


@respx.mock
async def test_client_credentials_grant_issues_token(dynamo_client) -> None:
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"accessToken": "real-connect-token"})
    )
    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "client_id": "12345", "client_secret": "secret", "scope": "message.send"},
        )
    assert response.status_code == 200
    body = response.json()
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "12345"
    assert claims["client_id"] == "12345"


@respx.mock
async def test_client_credentials_grant_accepts_live_snake_case_connect_response(dynamo_client) -> None:
    """Live-confirmed (2026-08-28): real Connect API accounts return
    snake_case (access_token), not the camelCase this was originally
    assumed to use - must not regress to only accepting camelCase."""
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "real-connect-token", "token_type": "Bearer"})
    )
    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "client_id": "12345", "client_secret": "secret", "scope": "message.send"},
        )
    assert response.status_code == 200


@respx.mock
async def test_minted_token_verifies_via_jwt_bearer_token_verifier(dynamo_client) -> None:
    """End-to-end Layer 1 check: a token this AS mints must actually be
    accepted by the generic JWTBearerTokenVerifier used to protect the MCP
    endpoint (`_build_client_auth()` in server.py) when configured with this
    server's own issuer/audience/JWKS - regressions here would silently
    break Layer 1 auth even though the AS itself "works".
    """
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"accessToken": "real-connect-token"})
    )
    async with await _client() as client:
        response = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "client_id": "12345", "client_secret": "secret", "scope": "message.send"},
        )
        jwks_response = await client.get("/.well-known/jwks.json")

    def _fake_jwk_client():
        jwk = _public_key_from_jwks(jwks_response.json())
        return type("FakeJWKClient", (), {"get_signing_key_from_jwt": staticmethod(lambda _token: jwk)})()

    verifier = JWTBearerTokenVerifier(
        issuer=ISSUER,
        audience=ISSUER,
        jwks_uri=f"{ISSUER}/.well-known/jwks.json",
        jwk_client=_fake_jwk_client(),
    )
    access_token = await verifier.verify_token(response.json()["access_token"])
    assert access_token is not None
    assert access_token.subject == "12345"


@respx.mock
async def test_client_credentials_grant_rejects_invalid_credentials(dynamo_client) -> None:
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(return_value=httpx.Response(401))
    async with await _client() as client:
        response = await client.post(
            "/oauth/token", data={"grant_type": "client_credentials", "client_id": "12345", "client_secret": "wrong"}
        )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


@respx.mock
async def test_token_unsupported_grant_type(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.post("/oauth/token", data={"grant_type": "password"})
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


@respx.mock
async def test_authorization_server_metadata(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.get("/.well-known/oauth-authorization-server")
    body = response.json()
    assert body["issuer"] == ISSUER
    assert body["authorization_endpoint"] == f"{ISSUER}/oauth/authorize"
    assert body["token_endpoint"] == f"{ISSUER}/oauth/token"
    assert body["registration_endpoint"] == f"{ISSUER}/oauth/register"
    assert body["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert "refresh_token" in body["grant_types_supported"]


@respx.mock
async def test_register_creates_public_client(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.post(
            "/oauth/register",
            json={"client_name": "New MCP Client", "redirect_uris": ["https://client.example.com/callback"]},
        )
    assert response.status_code == 201
    body = response.json()
    assert body["client_id"].startswith("dcr-")
    assert body["token_endpoint_auth_method"] == "none"
    assert body["redirect_uris"] == ["https://client.example.com/callback"]
    assert "client_secret" not in body

    store = OAuthStore(dynamodb_resource=dynamo_client)
    client = store.get_client(body["client_id"])
    assert client is not None
    assert client.name == "New MCP Client"
    assert client.require_consent is True


@respx.mock
async def test_register_requires_redirect_uris_for_authorization_code(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.post("/oauth/register", json={"client_name": "No Redirect Client"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client_metadata"


@respx.mock
async def test_register_rejects_unsupported_grant_type(dynamo_client) -> None:
    async with await _client() as client:
        response = await client.post("/oauth/register", json={"grant_types": ["implicit"]})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client_metadata"


@respx.mock
async def test_register_then_full_authorization_code_flow(dynamo_client) -> None:
    """End-to-end: a freshly self-registered client can complete the exact
    same authorization_code + PKCE + token exchange flow as a Terraform-seeded
    one - DCR only adds a new row to the same oauth_clients table, nothing
    else about the flow changes.
    """
    redirect_uri = "https://new-client.example.com/callback"
    async with await _client() as client:
        register_response = await client.post(
            "/oauth/register", json={"client_name": "New MCP Client", "redirect_uris": [redirect_uri]}
        )
        client_id = register_response.json()["client_id"]

        code_verifier = "test-verifier"
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()

        authorize_response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        assert authorize_response.status_code == 200

        respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "real-connect-token"})
        )
        approve_response = await client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "api_id": "12345",
                "api_key": "secret",
                "action": "approve",
            },
        )
        assert approve_response.status_code == 302
        code = parse_qs(urlparse(approve_response.headers["location"]).query)["code"][0]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
            },
        )
    assert token_response.status_code == 200
    assert "refresh_token" in token_response.json()


def test_code_challenge_matches_s256() -> None:
    verifier = "test-verifier"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert oauth_server._code_challenge_matches(code_verifier=verifier, code_challenge=challenge, method="S256")
    assert not oauth_server._code_challenge_matches(code_verifier="wrong", code_challenge=challenge, method="S256")


def test_layer2_fallback_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_OAUTH_LAYER2_FALLBACK", raising=False)
    assert not oauth_server.layer2_fallback_enabled()


def test_cache_layer2_credential_noop_when_disabled(dynamo_client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_OAUTH_LAYER2_FALLBACK", raising=False)
    store = OAuthStore(dynamodb_resource=dynamo_client)
    oauth_server.cache_layer2_credential(store=store, api_id="12345", api_key="secret", token="connect-token")
    assert store.get_layer2_credential("12345") is None


def test_cache_layer2_credential_populates_store_when_enabled(dynamo_client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_OAUTH_LAYER2_FALLBACK", "true")
    store = OAuthStore(dynamodb_resource=dynamo_client)
    oauth_server.cache_layer2_credential(store=store, api_id="12345", api_key="secret", token="connect-token")
    credential = store.get_layer2_credential("12345")
    assert credential is not None
    assert credential.api_key == "secret"
    assert credential.cached_token == "connect-token"


@respx.mock
async def test_client_credentials_grant_seeds_layer2_cache_when_enabled(dynamo_client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_OAUTH_LAYER2_FALLBACK", "true")
    respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "real-connect-token"})
    )
    async with await _client() as client:
        response = await client.post(
            "/oauth/token", data={"grant_type": "client_credentials", "client_id": "12345", "client_secret": "secret"}
        )
    assert response.status_code == 200

    store = OAuthStore(dynamodb_resource=dynamo_client)
    credential = store.get_layer2_credential("12345")
    assert credential is not None
    assert credential.api_key == "secret"
    assert credential.cached_token == "real-connect-token"


class TestLayer2FallbackAuth:
    async def test_raises_when_no_cached_credential(self, dynamo_client) -> None:
        strategy = oauth_server.Layer2FallbackAuth(api_id="unknown")
        async with oauth_server._http_client() as http_client:
            with pytest.raises(SopranoAuthError, match="No cached Layer 2 credential"):
                await strategy.get_auth_headers(domain_url=CONNECT_DOMAIN, http_client=http_client)

    @respx.mock
    async def test_reuses_fresh_cached_token_without_a_new_connect_call(self, dynamo_client) -> None:
        route = respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token")
        store = OAuthStore(dynamodb_resource=dynamo_client)
        store.put_layer2_credential(api_id="12345", api_key="secret", ttl_seconds=3600)
        store.put_layer2_cached_token(api_id="12345", token="still-fresh-token", expires_at=int(time.time()) + 1800)

        strategy = oauth_server.Layer2FallbackAuth(api_id="12345")
        async with oauth_server._http_client() as http_client:
            headers = await strategy.get_auth_headers(domain_url=CONNECT_DOMAIN, http_client=http_client)

        assert headers == {"Authorization": "Bearer still-fresh-token"}
        assert not route.called

    @respx.mock
    async def test_silently_refreshes_an_expired_cached_token(self, dynamo_client) -> None:
        respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "brand-new-token"})
        )
        store = OAuthStore(dynamodb_resource=dynamo_client)
        store.put_layer2_credential(api_id="12345", api_key="secret", ttl_seconds=3600)
        store.put_layer2_cached_token(api_id="12345", token="stale-token", expires_at=int(time.time()) - 10)

        strategy = oauth_server.Layer2FallbackAuth(api_id="12345")
        async with oauth_server._http_client() as http_client:
            headers = await strategy.get_auth_headers(domain_url=CONNECT_DOMAIN, http_client=http_client)

        assert headers == {"Authorization": "Bearer brand-new-token"}
        # The refreshed token must be persisted for the next call to reuse.
        credential = store.get_layer2_credential("12345")
        assert credential is not None
        assert credential.cached_token == "brand-new-token"

    @respx.mock
    async def test_raises_clear_error_when_stored_api_key_is_rejected(self, dynamo_client) -> None:
        respx.post(f"{CONNECT_DOMAIN}/cgpapi/auth/token").mock(return_value=httpx.Response(401))
        store = OAuthStore(dynamodb_resource=dynamo_client)
        store.put_layer2_credential(api_id="12345", api_key="rotated-away", ttl_seconds=3600)

        strategy = oauth_server.Layer2FallbackAuth(api_id="12345")
        async with oauth_server._http_client() as http_client:
            with pytest.raises(SopranoAuthError, match="rejected by Soprano"):
                await strategy.get_auth_headers(domain_url=CONNECT_DOMAIN, http_client=http_client)


def test_code_challenge_matches_plain() -> None:
    assert oauth_server._code_challenge_matches(code_verifier="abc", code_challenge="abc", method="plain")
    assert not oauth_server._code_challenge_matches(code_verifier="abc", code_challenge="xyz", method="plain")
