from __future__ import annotations

import pytest

from mems_mcp.auth.mcp_oauth import JWTBearerTokenVerifier
from mems_mcp.exceptions import ServerConfigError
from mems_mcp.server import _build_client_auth

ENV_VARS = (
    "MCP_CLIENT_AUTH_MODE",
    "MCP_OAUTH_ISSUER_URL",
    "MCP_OAUTH_AUDIENCE",
    "MCP_OAUTH_RESOURCE_SERVER_URL",
    "MCP_OAUTH_JWKS_URI",
    "MCP_OAUTH_REQUIRED_SCOPES",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_default_mode_is_no_auth() -> None:
    auth_settings, verifier = _build_client_auth()
    assert auth_settings is None
    assert verifier is None


def test_explicit_none_mode_is_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "none")
    auth_settings, verifier = _build_client_auth()
    assert auth_settings is None
    assert verifier is None


def test_invalid_mode_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "not-a-mode")
    with pytest.raises(ServerConfigError, match="Invalid MCP_CLIENT_AUTH_MODE"):
        _build_client_auth()


def test_oauth_mode_missing_issuer_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "oauth2.1")
    with pytest.raises(ServerConfigError, match="MCP_OAUTH_ISSUER_URL"):
        _build_client_auth()


def test_oauth_mode_builds_verifier_and_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "oauth2.1")
    monkeypatch.setenv("MCP_OAUTH_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("MCP_OAUTH_AUDIENCE", "https://mems-mcp.example.com")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE_SERVER_URL", "https://mems-mcp.example.com")

    auth_settings, verifier = _build_client_auth()

    assert auth_settings is not None
    assert str(auth_settings.issuer_url).rstrip("/") == "https://auth.example.com"
    assert str(auth_settings.resource_server_url).rstrip("/") == "https://mems-mcp.example.com"
    assert auth_settings.required_scopes is None
    assert isinstance(verifier, JWTBearerTokenVerifier)


def test_oauth_mode_defaults_jwks_uri_from_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "oauth2.1")
    monkeypatch.setenv("MCP_OAUTH_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("MCP_OAUTH_AUDIENCE", "https://mems-mcp.example.com")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE_SERVER_URL", "https://mems-mcp.example.com")

    _, verifier = _build_client_auth()

    assert isinstance(verifier, JWTBearerTokenVerifier)
    assert verifier._jwk_client.uri == "https://auth.example.com/.well-known/jwks.json"


def test_oauth_mode_respects_explicit_jwks_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "oauth2.1")
    monkeypatch.setenv("MCP_OAUTH_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("MCP_OAUTH_AUDIENCE", "https://mems-mcp.example.com")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE_SERVER_URL", "https://mems-mcp.example.com")
    monkeypatch.setenv("MCP_OAUTH_JWKS_URI", "https://auth.example.com/custom/jwks")

    _, verifier = _build_client_auth()

    assert verifier._jwk_client.uri == "https://auth.example.com/custom/jwks"


def test_oauth_mode_parses_required_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_CLIENT_AUTH_MODE", "oauth2.1")
    monkeypatch.setenv("MCP_OAUTH_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("MCP_OAUTH_AUDIENCE", "https://mems-mcp.example.com")
    monkeypatch.setenv("MCP_OAUTH_RESOURCE_SERVER_URL", "https://mems-mcp.example.com")
    monkeypatch.setenv("MCP_OAUTH_REQUIRED_SCOPES", "send, read")

    auth_settings, verifier = _build_client_auth()

    assert auth_settings is not None
    assert auth_settings.required_scopes == ["send", "read"]
    assert isinstance(verifier, JWTBearerTokenVerifier)
    assert verifier._required_scopes == ["send", "read"]
