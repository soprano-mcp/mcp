"""End-to-end verification that Layer 1 OAuth 2.1 (MCP_CLIENT_AUTH_MODE=oauth2.1)
actually enforces bearer-token auth over the real Streamable HTTP transport.

Builds a standalone `FastMCP` instance wired the same way `server.py` wires
`_build_client_auth()`'s output (rather than reusing the module-level `mcp`
singleton, which is constructed once at import time from whatever env vars
happened to be set then) - keeps this test independent of import order/env
state and mirrors exactly what a real oauth2.1-enabled deployment does.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import httpx
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import encode as jwt_encode
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from mems_mcp.auth.mcp_oauth import JWTBearerTokenVerifier

ISSUER = "https://auth.example.com"
AUDIENCE = "https://mems-mcp.example.com"


def _keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_server(public_key: rsa.RSAPublicKey) -> FastMCP:
    fake_jwk_client = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public_key))
    verifier = JWTBearerTokenVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_uri="unused", jwk_client=fake_jwk_client)
    server = FastMCP(
        "oauth-test-server",
        stateless_http=True,
        auth=AuthSettings(issuer_url=ISSUER, resource_server_url=AUDIENCE),  # type: ignore[arg-type]
        token_verifier=verifier,
    )

    @server.tool()
    def ping() -> str:
        return "pong"

    return server


def _client_factory(app: Any) -> Any:
    def factory(headers: dict[str, str] | None = None, timeout: Any = None, auth: Any = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", headers=headers)

    return factory


async def test_request_without_bearer_token_is_rejected() -> None:
    _, public_key = _keypair()
    server = _make_server(public_key)
    server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    app = server.streamable_http_app()

    async with LifespanManager(app):
        raised = False
        try:
            async with streamablehttp_client(
                "http://testserver/mcp", httpx_client_factory=_client_factory(app)
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
        except Exception:  # noqa: BLE001 - any failure here confirms auth was enforced
            raised = True

        assert raised, "expected the request without a bearer token to be rejected"


async def test_request_with_valid_bearer_token_succeeds() -> None:
    private_key, public_key = _keypair()
    server = _make_server(public_key)
    server.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=["testserver"], allowed_origins=["http://testserver"]
    )
    app = server.streamable_http_app()

    now = int(time.time())
    token = jwt_encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-123", "iat": now, "exp": now + 300, "scope": "send"},
        private_key,
        algorithm="RS256",
    )

    async with LifespanManager(app):
        async with streamablehttp_client(
            "http://testserver/mcp",
            headers={"Authorization": f"Bearer {token}"},
            httpx_client_factory=_client_factory(app),
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("ping", {})

        assert result.isError is False
        assert result.content[0].text == "pong"
