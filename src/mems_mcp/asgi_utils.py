"""Reusable ASGI route helpers - factored out of asgi.py so they're
importable without triggering that module's side-effecting top-level code
(which eagerly builds the shared `mems_mcp.server.mcp` singleton's ASGI apps,
lazily caching its StreamableHTTPSessionManager in the process - importing
asgi.py from a test poisons any other test that expects to configure
`mcp.settings.transport_security` before the *first* `streamable_http_app()`
call, see test_server_integration.py's comment on this exact caching).
"""

from __future__ import annotations

import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


async def _protected_resource_metadata(request: Request) -> Response:
    """Overrides the mcp SDK's own RFC 9728 /.well-known/oauth-protected-resource
    route (see override_protected_resource_route below) with a per-request
    Host-derived version - the SDK's own route hardcodes a SINGLE
    `authorization_servers` entry from `AuthSettings.issuer_url` (confirmed
    via `mcp.server.fastmcp.server`'s `streamable_http_app()`:
    `authorization_servers=[self.settings.auth.issuer_url]`), which is wrong
    for a deployment fronting multiple mcp-<domain> aliases - each alias's
    own Host is its own valid issuer (see oauth_server.py's
    `_issuer_url_from_request`, which this mirrors).
    """
    host = request.headers.get("host", "")
    resource = f"https://{host}/" if host else ""
    required_scopes = [s.strip() for s in os.environ.get("MCP_OAUTH_REQUIRED_SCOPES", "").split(",") if s.strip()]
    return JSONResponse(
        {
            "resource": resource,
            "authorization_servers": [resource] if resource else [],
            "bearer_methods_supported": ["header"],
            "scopes_supported": required_scopes or None,
        }
    )


def override_protected_resource_route(app: Starlette) -> None:
    """Replaces `app`'s `/.well-known/oauth-protected-resource` route (if
    present - only added by the SDK when MCP_CLIENT_AUTH_MODE=oauth2.1, see
    server.py's `_build_client_auth`) in-place with `_protected_resource_metadata`
    above. No-op if the route isn't present.
    """
    for i, route in enumerate(app.routes):
        if getattr(route, "path", None) == "/.well-known/oauth-protected-resource":
            app.routes[i] = Route(
                "/.well-known/oauth-protected-resource",
                endpoint=_protected_resource_metadata,
                methods=["GET", "OPTIONS"],
            )
            return
