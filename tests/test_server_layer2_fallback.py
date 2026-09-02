from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.requests import Request

import mems_mcp.server as server_module
from mems_mcp.auth import oauth_server
from mems_mcp.exceptions import ConnectionConfigError


def _ctx_with_no_soprano_headers() -> SimpleNamespace:
    """A minimal stand-in for `Context` exposing just what `_connection()`
    reads: `.request_context.request` (a real Starlette Request with no
    X-Soprano-* headers, so `connection_from_headers` raises)."""
    request = Request(scope={"type": "http", "headers": [], "method": "POST", "path": "/mcp"})
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


@pytest.fixture(autouse=True)
def _no_default_soprano_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate from the unrelated SOPRANO_* env var fallback so these tests
    # only exercise the Layer 2 fallback branch.
    monkeypatch.delenv("SOPRANO_DOMAIN_URL", raising=False)


def test_connection_raises_when_layer2_fallback_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_OAUTH_LAYER2_FALLBACK", raising=False)
    with pytest.raises(ConnectionConfigError):
        server_module._connection(_ctx_with_no_soprano_headers())  # type: ignore[arg-type]


def test_connection_raises_when_no_layer1_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_OAUTH_LAYER2_FALLBACK", "true")
    monkeypatch.setattr(server_module, "get_access_token", lambda: None)
    with pytest.raises(ConnectionConfigError):
        server_module._connection(_ctx_with_no_soprano_headers())  # type: ignore[arg-type]


def test_connection_uses_layer2_fallback_when_enabled_with_layer1_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_OAUTH_LAYER2_FALLBACK", "true")
    monkeypatch.setenv("MEMS_CONNECT_API_URL", "https://aus.sopranodesign.com")
    fake_access_token = SimpleNamespace(claims={"api_id": "12345"})
    monkeypatch.setattr(server_module, "get_access_token", lambda: fake_access_token)

    connection = server_module._connection(_ctx_with_no_soprano_headers())  # type: ignore[arg-type]

    assert connection.domain_url == "https://aus.sopranodesign.com"
    assert isinstance(connection.auth_strategy, oauth_server.Layer2FallbackAuth)
    assert connection.auth_strategy.api_id == "12345"
