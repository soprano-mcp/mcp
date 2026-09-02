from __future__ import annotations

from typing import Protocol

import httpx


class AuthStrategy(Protocol):
    """Produces the HTTP headers needed to authenticate a Connect API request.

    Each call may perform its own token exchange with Soprano. No token
    caching is performed across calls: credentials are supplied per-request
    by the MCP client and the server is stateless (see
    docs/mcp-server-implementation-plan.md, "Token caching"). The one
    deliberate, opt-in exception is `oauth_server.Layer2FallbackAuth`, used
    only when `MCP_OAUTH_LAYER2_FALLBACK` is enabled.
    """

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]: ...
