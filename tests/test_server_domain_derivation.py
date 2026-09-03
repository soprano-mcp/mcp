from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.requests import Request

import mems_mcp.server as server_module
from mems_mcp.auth.api_key import ApiKeyAuth
from mems_mcp.exceptions import ConnectionConfigError


def _ctx(headers: list[tuple[bytes, bytes]]) -> SimpleNamespace:
    request = Request(scope={"type": "http", "headers": headers, "method": "POST", "path": "/mcp"})
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


@pytest.fixture(autouse=True)
def _no_default_soprano_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate from the unrelated SOPRANO_* env var fallback so these tests
    # only exercise host-based domain derivation.
    monkeypatch.delenv("SOPRANO_DOMAIN_URL", raising=False)


def test_connection_derives_domain_from_mcp_prefixed_host() -> None:
    ctx = _ctx(
        [
            (b"host", b"mcp-aus.sopranodesign.com"),
            (b"x-soprano-auth-method", b"api_key"),
            (b"x-soprano-api-id", b"12345"),
            (b"x-soprano-api-key", b"secret"),
        ]
    )

    connection = server_module._connection(ctx)  # type: ignore[arg-type]

    assert connection.domain_url == "https://aus.sopranodesign.com"
    assert isinstance(connection.auth_strategy, ApiKeyAuth)


def test_connection_explicit_domain_header_takes_priority_over_host() -> None:
    ctx = _ctx(
        [
            (b"host", b"mcp-aus.sopranodesign.com"),
            (b"x-soprano-domain-url", b"https://other.sopranodesign.com"),
            (b"x-soprano-auth-method", b"api_key"),
            (b"x-soprano-api-id", b"12345"),
            (b"x-soprano-api-key", b"secret"),
        ]
    )

    connection = server_module._connection(ctx)  # type: ignore[arg-type]

    assert connection.domain_url == "https://other.sopranodesign.com"


def test_connection_raises_when_host_does_not_follow_mcp_convention() -> None:
    ctx = _ctx(
        [
            (b"host", b"example.com"),
            (b"x-soprano-auth-method", b"api_key"),
            (b"x-soprano-api-id", b"12345"),
            (b"x-soprano-api-key", b"secret"),
        ]
    )

    with pytest.raises(ConnectionConfigError):
        server_module._connection(ctx)  # type: ignore[arg-type]
