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
from starlette.responses import JSONResponse, PlainTextResponse, Response
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
    # No trailing slash - RFC 8414 clients treat any path component (even a
    # bare "/") as requiring "/.well-known/..." to be inserted BEFORE it,
    # which 307-redirects here (Starlette's trailing-slash redirect) to an
    # http:// URL (CloudFront->ALB is a plain HTTP hop internally) that then
    # 403s - breaking spec-compliant clients' AS metadata discovery.
    resource = f"https://{host}" if host else ""
    required_scopes = [s.strip() for s in os.environ.get("MCP_OAUTH_REQUIRED_SCOPES", "").split(",") if s.strip()]
    return JSONResponse(
        {
            "resource": resource,
            "authorization_servers": [resource] if resource else [],
            "bearer_methods_supported": ["header"],
            "scopes_supported": required_scopes or None,
        }
    )


def _openai_apps_challenge_tokens() -> dict[str, str]:
    """Parses OPENAI_APPS_CHALLENGE_TOKENS ("host=token,host2=token2") for
    deployments verifying more than one mcp-<label> alias (e.g. a
    mems_domains platform) at once. Malformed/empty entries are skipped.
    """
    raw = os.environ.get("OPENAI_APPS_CHALLENGE_TOKENS", "")
    tokens: dict[str, str] = {}
    for pair in raw.split(","):
        host, sep, token = pair.strip().partition("=")
        if sep and host and token:
            tokens[host] = token
    return tokens


async def _openai_apps_challenge(request: Request) -> Response:
    """Serves the OpenAI Apps SDK domain-verification token at the
    origin-root well-known path OpenAI polls ("Challenge Base URL" ->
    /.well-known/openai-apps-challenge, see the Apps SDK submission flow).
    Looks up OPENAI_APPS_CHALLENGE_TOKENS by request Host first (multi-domain
    deployments), falling back to the single-token OPENAI_APPS_CHALLENGE_TOKEN
    env var. 404s (like any other unmounted path) if neither is configured
    for this Host, so this is a no-op until a verification is in progress.
    """
    host = request.headers.get("host", "").split(":", 1)[0]
    token = _openai_apps_challenge_tokens().get(host) or os.environ.get("OPENAI_APPS_CHALLENGE_TOKEN", "")
    if not token:
        return Response(status_code=404)
    return PlainTextResponse(token)


def build_openai_apps_challenge_route() -> Route:
    """Route for OpenAI Apps SDK domain verification - not auth-protected
    (must be publicly fetchable pre-verification), always registered but
    404s unless OPENAI_APPS_CHALLENGE_TOKEN(S) is set (see
    _openai_apps_challenge above).
    """
    return Route("/.well-known/openai-apps-challenge", endpoint=_openai_apps_challenge, methods=["GET"])


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
