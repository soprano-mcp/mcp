"""FastMCP server exposing the Soprano Connect API as MCP tools.

Supports two transports:
- `streamable-http` (default): Soprano connection info (domain_url, auth method,
  credentials) is read from custom `X-Soprano-*` HTTP headers per-request rather
  than tool arguments, so secrets never enter the LLM's context (see
  docs/mcp-server-implementation-plan.md section 3). `stateless_http=True`
  matches a serverless deployment target with no session affinity (plan
  section 10).
- `stdio`: there is no per-request HTTP header channel, so connection info is
  instead read once from `SOPRANO_*` environment variables set by the MCP
  client when it launches the server subprocess (single-tenant for the
  lifetime of that process).

Layer 1 (MCP client -> this server) authentication is controlled by
`MCP_CLIENT_AUTH_MODE` (`none` [default] | `oauth2.1`) - see
`_build_client_auth()` and `mems_mcp.auth.mcp_oauth` for the OAuth 2.1
Resource Server implementation. This is independent of Layer 2 (this server
-> Soprano), which is always the per-request `X-Soprano-*`/`SOPRANO_*` scheme
described above.
"""

from __future__ import annotations

import argparse
import base64
import logging
import os
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import truststore
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from mems_mcp.auth import oauth_server
from mems_mcp.auth.mcp_oauth import JWTBearerTokenVerifier
from mems_mcp.connection import Connection, connection_from_env, connection_from_headers
from mems_mcp.exceptions import ConnectionConfigError, ServerConfigError
from mems_mcp.observability import configure_logging, observe_tool
from mems_mcp.models import (
    BatchStatusItem,
    BroadcastBatchOptions,
    BroadcastEndpoint,
    ChannelLiteral,
    EmailAddresses,
    PushNotificationContent,
    RcsContent,
    SendBroadcastRequest,
    SendMessageRequest,
    VoiceContent,
    WhatsAppContent,
)
from mems_mcp.soprano_client import SopranoClient

configure_logging()


@asynccontextmanager
async def _lifespan(_: FastMCP) -> AsyncIterator[dict[str, Any]]:
    # Use the OS-native certificate trust store (macOS Keychain / Windows cert
    # store / Linux system CAs) instead of the bundled `certifi` CAs, scoped to
    # only this httpx client via an explicit SSLContext (NOT the process-wide
    # `truststore.inject_into_ssl()` monkeypatch, which is invasive and can
    # conflict with other libraries' own SSL context creation).
    ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with httpx.AsyncClient(verify=ssl_context) as http_client:
        yield {"soprano_client": SopranoClient(http_client)}


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ServerConfigError(
            f"Missing required '{name}' environment variable (MCP_CLIENT_AUTH_MODE=oauth2.1 requires it)"
        )
    return value


def _build_client_auth() -> tuple[AuthSettings | None, TokenVerifier | None]:
    """Builds Layer 1 (MCP client) auth config from `MCP_CLIENT_AUTH_MODE`.

    - `none` (default): no client-facing auth - trusted network/local dev,
      matches all prior behaviour.
    - `oauth2.1`: this server acts as an OAuth 2.1 Resource Server; a bearer
      token issued by an external Authorization Server (any standards-
      compliant OIDC/OAuth2 IdP - Auth0, Cognito, Okta, Keycloak, ...) is
      required on every request. Configured entirely via env vars so no
      particular IdP is hardcoded:
        MCP_OAUTH_ISSUER_URL          (required) - the AS's issuer URL.
        MCP_OAUTH_AUDIENCE            (required) - expected token `aud` claim.
        MCP_OAUTH_RESOURCE_SERVER_URL (required) - this server's own public
                                      URL, used for RFC 9728 protected-resource
                                      metadata / discovery.
        MCP_OAUTH_JWKS_URI            (optional) - defaults to
                                      `{issuer}/.well-known/jwks.json`, the
                                      common convention (works for Auth0/
                                      Cognito/Okta); override for IdPs that
                                      publish JWKS elsewhere.
        MCP_OAUTH_REQUIRED_SCOPES     (optional) - comma-separated scopes
                                      required on every token.
        MCP_OAUTH_METADATA_ISSUER_URL (optional) - defaults to
                                      MCP_OAUTH_ISSUER_URL. Some MCP clients
                                      (confirmed: Zendesk) require RFC 8414
                                      Authorization Server Metadata at
                                      "{authorization_server}/.well-known/
                                      oauth-authorization-server", which AWS
                                      Cognito doesn't serve itself (only OIDC's
                                      "/.well-known/openid-configuration").
                                      Set this to this server's own
                                      MCP_OAUTH_RESOURCE_SERVER_URL when using
                                      Cognito - the RFC 9728 protected-resource
                                      metadata's "authorization_servers" entry
                                      then points here instead, and
                                      _oauth_authorization_server_metadata()
                                      below serves a mirrored RFC 8414 document
                                      (the real token issuer used for
                                      verification is unaffected - still
                                      MCP_OAUTH_ISSUER_URL).
    """
    mode = os.environ.get("MCP_CLIENT_AUTH_MODE", "none").strip().lower()
    if mode == "none":
        return None, None
    if mode != "oauth2.1":
        raise ServerConfigError(f"Invalid MCP_CLIENT_AUTH_MODE '{mode}'. Must be 'none' or 'oauth2.1'")

    issuer = _require_env("MCP_OAUTH_ISSUER_URL")
    # Comma-separated - supports multiple app clients (e.g. one per
    # connecting service) issuing tokens for the same resource server.
    audiences = [a.strip() for a in _require_env("MCP_OAUTH_AUDIENCE").split(",") if a.strip()]
    resource_server_url = _require_env("MCP_OAUTH_RESOURCE_SERVER_URL")
    jwks_uri = os.environ.get("MCP_OAUTH_JWKS_URI") or f"{issuer.rstrip('/')}/.well-known/jwks.json"
    required_scopes = [s.strip() for s in os.environ.get("MCP_OAUTH_REQUIRED_SCOPES", "").split(",") if s.strip()]

    verifier = JWTBearerTokenVerifier(
        issuer=issuer,
        audience=audiences,
        jwks_uri=jwks_uri,
        required_scopes=required_scopes or None,
    )
    metadata_issuer = os.environ.get("MCP_OAUTH_METADATA_ISSUER_URL") or issuer
    auth_settings = AuthSettings(
        issuer_url=metadata_issuer,  # type: ignore[arg-type]
        resource_server_url=resource_server_url,  # type: ignore[arg-type]
        required_scopes=required_scopes or None,
    )
    return auth_settings, verifier


def _build_transport_security() -> TransportSecuritySettings | None:
    """Builds DNS-rebinding-protection config for the `streamable-http` transport.

    The mcp SDK's `TransportSecuritySettings` defaults to
    `enable_dns_rebinding_protection=True` with an EMPTY `allowed_hosts`, which
    rejects every request's `Host` header (HTTP 421) unless explicitly
    configured - fine for local dev (default `127.0.0.1`/`localhost`-style
    access rarely round-trips through a hostile DNS name), but breaks any real
    deployment (e.g. a Lambda Function URL's `*.lambda-url.<region>.on.aws`
    hostname) that never opts in.

    Configured via:
      MEMS_MCP_ALLOWED_HOSTS   - comma-separated `Host` header values to allow
                                 (e.g. the Function URL's hostname, no scheme).
      MEMS_MCP_ALLOWED_ORIGINS - comma-separated `Origin` header values to
                                 allow (e.g. `https://<function-url-host>`).

    Leaving both unset preserves the SDK's default (strict, only useful for
    same-origin/local dev) rather than silently disabling protection.
    """
    allowed_hosts = [h.strip() for h in os.environ.get("MEMS_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    allowed_origins = [
        o.strip() for o in os.environ.get("MEMS_MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()
    ]
    if not allowed_hosts and not allowed_origins:
        return None
    return TransportSecuritySettings(allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)


_auth_settings, _token_verifier = _build_client_auth()
_transport_security = _build_transport_security()


mcp = FastMCP(
    "mems-mcp",
    instructions=(
        "Tools for sending and querying multi-channel messages (SMS, WhatsApp, RCS, Email, "
        "Voice, Viber, Push Notifications) via the Soprano Connect API. Over the "
        "streamable-http transport, every tool call requires Soprano connection headers on "
        "the HTTP request: X-Soprano-Domain-Url, X-Soprano-Auth-Method "
        "(api_key|oauth2|basic|legacy_oauth2|session_cookie), and the credential headers for the "
        "chosen auth method (X-Soprano-Api-Id/X-Soprano-Api-Key, X-Soprano-Client-Id/"
        "X-Soprano-Client-Secret, X-Soprano-Username/X-Soprano-Password, or "
        "X-Soprano-Session-Cookie). session_cookie is only required by list_whatsapp_templates. "
        "Over stdio, the equivalent SOPRANO_* environment variables are used instead. If this "
        "server was started with MCP_CLIENT_AUTH_MODE=oauth2.1, an OAuth 2.1 bearer token is "
        "also required on every request (Layer 1 client auth, independent of the Soprano "
        "connection headers above)."
    ),
    stateless_http=True,
    lifespan=_lifespan,
    auth=_auth_settings,
    token_verifier=_token_verifier,
)

if _transport_security is not None:
    mcp.settings.transport_security = _transport_security


@mcp.custom_route("/healthz", methods=["GET"])
async def _healthz_route(_: Request) -> Response:
    """Liveness/readiness probe - also used as the ALB/Function URL target.

    Soprano itself isn't checked here: there's no fixed per-server connection
    to test (domain_url and credentials are supplied per-request by the MCP
    client).
    """
    return JSONResponse({"status": "ok"})


# --- Self-hosted OAuth 2.0 Authorization Server (Layer 1 auth) ---------------
# Replaces the previous Cognito-proxy setup - see
# mems_mcp/auth/oauth_server.py and MCP_OAuth_Zendesk_PRD.md. Issues its own
# RS256 JWTs after validating the caller's real Connect API ID/API KEY,
# rather than delegating to an external IdP.
@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def _oauth_authorization_server_metadata(request: Request) -> Response:
    return await oauth_server.handle_authorization_server_metadata(request)


@mcp.custom_route("/.well-known/jwks.json", methods=["GET"])
async def _oauth_jwks(request: Request) -> Response:
    return await oauth_server.handle_jwks(request)


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def _oauth_authorize_get(request: Request) -> Response:
    return await oauth_server.handle_authorize_get(request)


@mcp.custom_route("/oauth/authorize", methods=["POST"])
async def _oauth_authorize_post(request: Request) -> Response:
    return await oauth_server.handle_authorize_post(request)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def _oauth_token(request: Request) -> Response:
    return await oauth_server.handle_token(request)


@mcp.custom_route("/oauth/register", methods=["POST"])
async def _oauth_register(request: Request) -> Response:
    return await oauth_server.handle_register(request)


def _connection(ctx: Context) -> Connection:
    request = ctx.request_context.request
    if request is not None:
        try:
            return connection_from_headers(request.headers)
        except ConnectionConfigError:
            # Client can't send X-Soprano-* headers (e.g. Zendesk's MCP
            # connector has no custom-header support). Prefer reusing the
            # caller's OWN Connect identity, already proved at Layer 1 login
            # (opt-in, see oauth_server.layer2_fallback_enabled) - falling
            # through to a single shared default account instead would
            # silently send messages under the WRONG account, so a Layer 1
            # identity takes priority and its own errors (e.g. no cached
            # credential yet) are allowed to propagate rather than masked.
            if oauth_server.layer2_fallback_enabled():
                api_id = _layer1_api_id()
                if api_id is not None:
                    return oauth_server.layer2_fallback_connection(api_id)
            if _has_default_soprano_env():
                return connection_from_env()
            raise
    # No HTTP request available (e.g. stdio transport) - fall back to
    # SOPRANO_* environment variables set for the server process.
    return connection_from_env()


def _layer1_api_id() -> str | None:
    """The Connect api_id this caller already authenticated with at Layer 1,
    if any - see mems_mcp.auth.oauth_server.mint_access_token's "api_id" claim.
    """
    access_token = get_access_token()
    if access_token is None or not access_token.claims:
        return None
    api_id = access_token.claims.get("api_id")
    return str(api_id) if api_id else None


def _has_default_soprano_env() -> bool:
    return bool(os.environ.get("SOPRANO_DOMAIN_URL"))


def _client(ctx: Context) -> SopranoClient:
    return ctx.request_context.lifespan_context["soprano_client"]


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
)
@observe_tool
async def send_message(
    ctx: Context,
    channel: ChannelLiteral,
    destination: str,
    text: str | None = None,
    template_name: str | None = None,
    key_values: str | None = None,
    client_message_id: str | None = None,
    source: str | None = None,
    reply_to_ton: int | None = None,
    reply_to: str | None = None,
    registered: int | None = None,
    launch_timestamp: str | None = None,
    subject: str | None = None,
    email_cc: str | None = None,
    email_bcc: str | None = None,
    rcs: dict[str, Any] | None = None,
    whatsapp: dict[str, Any] | None = None,
    voice: dict[str, Any] | None = None,
    push_notification: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send a single real-time message via the Soprano Connect API.

    Maps to `POST {domain_url}/cgpapi/messages/{channel}`. Returns the created
    message summary (id, destination, status). `destination` may be a comma
    separated list of up to 250 recipients. Either `text`, `template_name`, or
    one of the channel-specific rich content objects below must be provided.

    - `rcs`: RCS-only. Provide exactly one of `text`, `media`, `rich_card`
      (`{"rich_card": {"cards": [{"title": ..., "media": {"file_url": ...},
      "suggestions": [{"text": ..., "postback_data": ...}]}]}}`). Overrides
      `text`/`template_name` when present.
    - `whatsapp`: `{"type": "image"|"video"|"document"|"audio", "image": {"url":
      ..., "caption": ...}}` for media; `{"type": "text", "text": {"body": ...}}`;
      `{"type": "interactive", "interactive": {"type": "button"|"list", "body":
      {"text": ...}, "action": {...}}}`; `{"type": "template", "template":
      {"name": ..., "language": ...}}`; `{"type": "location"|"reaction"|"context",
      ...}`.
    - `voice`: `{"text2voice": {"password": ..., "language": "en-AU", ...}}`, or
      `{"call_control_object": {"id": ...}}`, or `{"audio": {"url": ...}}`.
    - `push_notification`: `{"notification": {"title": ..., "body": ...}}`.

    `extra` is a passthrough dict merged verbatim into the outgoing JSON payload,
    for anything not covered by the parameters above (e.g. Viber, which has no
    documented rich-content schema in the Connect API guide). See the "Payload
    Parameters" section of the Connect API guide for full field details.
    """
    email = EmailAddresses(cc=email_cc, bcc=email_bcc) if (email_cc or email_bcc) else None
    request = SendMessageRequest(
        channel=channel,
        destination=destination,
        text=text,
        template_name=template_name,
        key_values=key_values,
        client_message_id=client_message_id,
        source=source,
        reply_to_ton=reply_to_ton,
        reply_to=reply_to,
        registered=registered,
        launch_timestamp=launch_timestamp,
        subject=subject,
        email=email,
        rcs=RcsContent.model_validate(rcs) if rcs is not None else None,
        whatsapp=WhatsAppContent.model_validate(whatsapp) if whatsapp is not None else None,
        voice=VoiceContent.model_validate(voice) if voice is not None else None,
        push_notification=(
            PushNotificationContent.model_validate(push_notification) if push_notification is not None else None
        ),
        extra=extra or {},
    )
    connection = _connection(ctx)
    result = await _client(ctx).send_message(connection, channel, request.to_payload())
    return result


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
@observe_tool
async def get_message_status(ctx: Context, channel: ChannelLiteral, message_id: str) -> dict[str, Any]:
    """Query the status of a single previously-sent message.

    Maps to `GET {domain_url}/cgpapi/messages/{channel}/{message_id}`.
    """
    connection = _connection(ctx)
    return await _client(ctx).get_message_status(connection, channel, message_id)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
)
@observe_tool
async def send_batch(ctx: Context, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Send multiple messages in a single batch call.

    Maps to `POST {domain_url}/cgpapi/batch/messages`. Each item in `messages`
    follows the same shape as `send_message`'s payload fields, e.g.
    `{"channel": "sms", "destination": "...", "text": "..."}`.
    """
    payloads = [SendMessageRequest.model_validate(message).to_payload() for message in messages]
    connection = _connection(ctx)
    return await _client(ctx).send_batch(connection, payloads)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
@observe_tool
async def get_batch_status(ctx: Context, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Query the status of multiple messages at once.

    Maps to `POST {domain_url}/cgpapi/batch/messages/status`. Each item is
    `{"id": <message id>, "message_type": "SMS"}` (currently only SMS is
    supported by this Connect API endpoint).
    """
    payloads = [BatchStatusItem.model_validate(item).to_payload() for item in items]
    connection = _connection(ctx)
    return await _client(ctx).get_batch_status(connection, payloads)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
)
@observe_tool
async def send_broadcast(
    ctx: Context,
    text: str,
    endpoints: list[dict[str, int]],
    registered: bool | None = None,
    batch_size: int | None = None,
    sleep_duration: int | None = None,
    max_destinations: int | None = None,
) -> dict[str, Any]:
    """Send a broadcast SMS order to lists, contacts and/or groups.

    Maps to `POST {domain_url}/cgpapi/broadcast/sms`. `endpoints` is a list of
    `{"type": <int>, "id": <int>}` references (list/contact/group). Ad-hoc
    mobile-only destinations require at least 250 entries.
    """
    request = SendBroadcastRequest(
        text=text,
        endpoints=[BroadcastEndpoint.model_validate(endpoint) for endpoint in endpoints],
        registered=registered,
        batch_options=(
            BroadcastBatchOptions(batch_size=batch_size, sleep_duration=sleep_duration, max_destinations=max_destinations)
            if any(v is not None for v in (batch_size, sleep_duration, max_destinations))
            else None
        ),
    )
    connection = _connection(ctx)
    return await _client(ctx).send_broadcast(connection, request.to_payload())


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
@observe_tool
async def list_whatsapp_templates(ctx: Context) -> Any:
    """List approved WhatsApp Business (WABA) message templates.

    Maps to `GET {domain_url}/cgpapi/waba/templates`. Templates with the same
    name but different languages appear as separate objects (name, language,
    languageName, category, components, status).

    Auth outlier: unlike every other tool, this endpoint requires a portal
    session cookie rather than one of the 4 standard auth methods - set
    `X-Soprano-Auth-Method: session_cookie` and `X-Soprano-Session-Cookie:
    <JSESSIONID value>` (or `SOPRANO_AUTH_METHOD`/`SOPRANO_SESSION_COOKIE` over
    stdio).
    """
    connection = _connection(ctx)
    return await _client(ctx).list_whatsapp_templates(connection)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
)
@observe_tool
async def upload_whatsapp_media(
    ctx: Context, source: str, filename: str, content_type: str, file_content_base64: str
) -> dict[str, Any]:
    """Upload media to Facebook for use in WhatsApp messages.

    Maps to `POST {domain_url}/cgpapi/waba/media/{source}` (multipart upload).
    `source` is the WhatsApp sender number the media is uploaded against.
    `file_content_base64` is the file's raw bytes, base64-encoded. Uses the
    connection's normal auth method (no session cookie needed here - that's
    only required by `list_whatsapp_templates`).
    """
    connection = _connection(ctx)
    file_bytes = base64.b64decode(file_content_base64)
    return await _client(ctx).upload_whatsapp_media(connection, source, file_bytes, filename, content_type)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False))
@observe_tool
async def delete_whatsapp_media(ctx: Context, media_id: str) -> dict[str, Any]:
    """Delete previously uploaded WhatsApp media from Facebook.

    Maps to `DELETE {domain_url}/cgpapi/waba/media/{media_id}`.
    """
    connection = _connection(ctx)
    await _client(ctx).delete_whatsapp_media(connection, media_id)
    return {"deleted": True, "media_id": media_id}


def main() -> None:
    """Entrypoint for running the server directly (e.g. `uv run mems-mcp`).

    Transport is chosen via `--transport` (or $MEMS_MCP_TRANSPORT), defaulting
    to `streamable-http`. Use `stdio` to run as a local subprocess launched by
    an MCP client (e.g. Claude Desktop, VS Code) - see connection.py for the
    SOPRANO_* environment variables that must be set in that mode. Use `sse`
    only for MCP clients that don't yet support Streamable HTTP - the
    deployed container (see asgi.py) serves both HTTP-based transports
    simultaneously, but a single `mcp.run()` process only serves one at a time.
    """
    parser = argparse.ArgumentParser(prog="mems-mcp", description="Soprano Connect API MCP server")
    parser.add_argument(
        "--transport",
        choices=["streamable-http", "stdio", "sse"],
        default=os.environ.get("MEMS_MCP_TRANSPORT", "streamable-http"),
        help="MCP transport to use (default: streamable-http, or $MEMS_MCP_TRANSPORT)",
    )
    args = parser.parse_args()

    if args.transport in ("streamable-http", "sse"):
        mcp.settings.host = os.environ.get("MEMS_MCP_HOST", "127.0.0.1")
        mcp.settings.port = int(os.environ.get("MEMS_MCP_PORT", "8000"))

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()

