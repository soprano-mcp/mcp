"""Tests mems_mcp.asgi_utils's RFC 9728 protected-resource-metadata override.

Builds a standalone FastMCP instance (mirrors test_mcp_client_oauth_integration.py's
pattern) rather than importing mems_mcp.asgi/server, since importing
mems_mcp.asgi itself (not just this specific helper) eagerly builds the
shared `mems_mcp.server.mcp` singleton's ASGI apps - see asgi_utils.py's own
module docstring for why that's unsafe to trigger from a test.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from mems_mcp.asgi_utils import override_protected_resource_route
from mems_mcp.auth.mcp_oauth import JWTBearerTokenVerifier

ISSUER = "https://mcp-aus.example.com"
AUDIENCE = "https://mcp-aus.example.com"


def _keypair() -> rsa.RSAPublicKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()


def _server() -> FastMCP:
    fake_jwk_client = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=_keypair()))
    verifier = JWTBearerTokenVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_uri="unused", jwk_client=fake_jwk_client)
    return FastMCP(
        "protected-resource-test-server",
        stateless_http=True,
        auth=AuthSettings(issuer_url=ISSUER, resource_server_url=AUDIENCE),  # type: ignore[arg-type]
        token_verifier=verifier,
    )


async def test_override_derives_resource_and_authorization_servers_from_host() -> None:
    app = _server().streamable_http_app()
    override_protected_resource_route(app)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get(
            "/.well-known/oauth-protected-resource", headers={"Host": "mcp-br.example.com"}
        )

    assert response.status_code == 200
    body = response.json()
    assert body["resource"] == "https://mcp-br.example.com/"
    assert body["authorization_servers"] == ["https://mcp-br.example.com/"]


async def test_override_is_noop_when_route_absent() -> None:
    """No auth configured - the SDK never adds the route, so this must not raise."""
    app = FastMCP("no-auth-test-server", stateless_http=True).streamable_http_app()
    override_protected_resource_route(app)  # should not raise

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 404


@pytest.fixture(autouse=True)
def _no_required_scopes_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_OAUTH_REQUIRED_SCOPES", raising=False)
