"""Self-hosted OAuth 2.0 Authorization Server (Layer 1 auth), replacing the
previous Cognito-proxy setup - see `MCP_OAuth_Zendesk_PRD.md`.

Issues MCP-specific RS256 JWTs after validating the caller's real Soprano
Connect API ID/API KEY against `POST {domain}/cgpapi/auth/token` (the same
client_credentials exchange `auth/oauth2.py`'s `OAuth2Auth` already performs
for Layer 2) - so clients that require a real Authorization Code + consent
flow (confirmed: Zendesk Agent) work without provisioning separate IdP user
accounts, while non-interactive agents (Claude Desktop, OpenAI, dev/m2m
scripts) keep using client_credentials directly with those same Connect
credentials.

This is deliberately NOT a general-purpose OAuth library: it implements
exactly the PRD's Phase 1 MVP surface (authorize/token/discovery/JWKS) for
one MCP server instance backed by one fixed Connect API domain per
deployment (`MEMS_CONNECT_API_URL` - each deployment targets its own Connect
domain). The real Connect access token obtained during credential validation
is discarded immediately - never returned to the OAuth caller (PRD section
9: "must not expose Connect tokens directly").
"""

from __future__ import annotations

import base64
import hashlib
import html
import importlib.resources
import logging
import os
import ssl
import time
from dataclasses import dataclass
from string import Template
from typing import Any
from urllib.parse import urlencode

import boto3
import httpx
import jwt
import truststore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mems_mcp.auth.oauth_store import OAuthStore
from mems_mcp.connection import Connection
from mems_mcp.exceptions import SopranoAuthError

logger = logging.getLogger(__name__)

ACCESS_TOKEN_TTL_SECONDS = 3600  # PRD section 15
AUTH_CODE_TTL_SECONDS = 300  # PRD section 15
# Refresh tokens - authorization_code grant only (client_credentials callers
# already hold their own api_id/api_key and can just re-authenticate
# directly, no refresh needed). Rotated on every use, sliding expiry: a
# client that refreshes at least this often stays authenticated indefinitely
# without ever repeating the interactive consent flow.
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600
# Soprano's own client_credentials token lifetime (see auth/oauth2.py) - used
# to bound how long a cached Layer 2 token is reused before silently
# refreshing it (see Layer2FallbackAuth).
CONNECT_TOKEN_TTL_SECONDS = 1800
CONSENT_VERSION = "1"
KEY_ID = "mems-mcp-oauth-1"

# Loaded once at import time - static asset, never changes per-request. Kept as
# a separate .html file (rather than an inline f-string) so the markup/CSS can
# be edited/previewed without the Python-brace-escaping noise an f-string with
# embedded CSS would need; string.Template's `$name` substitution needs no
# escaping of the CSS's own literal `{`/`}`.
_CONSENT_FORM_TEMPLATE = Template(
    importlib.resources.files(__package__).joinpath("consent_form.html").read_text(encoding="utf-8")
)


def _load_signing_key() -> rsa.RSAPrivateKey:
    """Loads the RS256 private key, preferring (in order):

    1. `MCP_OAUTH_SIGNING_KEY_SECRET_ARN` - fetched from AWS Secrets Manager
       at process start (populated by your own deployment tooling, e.g. an
       RSA key generated once and stored there) - the secure, production
       path.
    2. `MCP_OAUTH_SIGNING_KEY` - the raw PEM directly via env var, for local
       dev/testing without AWS access.
    3. An ephemeral generated key, with a loud warning - only safe for a
       single local process: a restart (or a second ECS/Lambda instance with
       its own ephemeral key) would then reject tokens signed by the other
       instance's key.
    """
    pem = os.environ.get("MCP_OAUTH_SIGNING_KEY")
    if not pem:
        secret_arn = os.environ.get("MCP_OAUTH_SIGNING_KEY_SECRET_ARN")
        if secret_arn:
            pem = boto3.client("secretsmanager").get_secret_value(SecretId=secret_arn)["SecretString"]
    if pem:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("MCP_OAUTH_SIGNING_KEY(_SECRET_ARN) must be an RSA private key")
        return key
    logger.warning(
        "No MCP_OAUTH_SIGNING_KEY(_SECRET_ARN) set - generating an EPHEMERAL RS256 key for "
        "this process only. Fine for local dev; real/multi-instance deployments must set one."
    )
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_SIGNING_KEY = _load_signing_key()


def jwks_document() -> dict[str, Any]:
    """RFC 7517 JWK Set containing just this server's own RS256 public key."""
    public_numbers = _SIGNING_KEY.public_key().public_numbers()

    def _b64url_uint(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": _b64url_uint(public_numbers.n),
                "e": _b64url_uint(public_numbers.e),
            }
        ]
    }


def mint_access_token(*, issuer: str, api_id: str, client_id: str, scope: str) -> str:
    """`aud` is the resource server itself (a fixed, well-known value), NOT
    `client_id` - for `client_credentials` grants, `client_id` is the
    caller's own arbitrary Connect API ID (dynamic/unbounded), so it can't
    be used as a statically-configurable audience allowlist value the way
    JWTBearerTokenVerifier expects (see mcp_oauth.py's `aud`-absent
    fallback, which only makes sense for IdPs like Cognito that never issue
    an `aud` claim at all - our own tokens always have one).
    """
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": issuer,
        "sub": api_id,
        "api_id": api_id,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(claims, _SIGNING_KEY, algorithm="RS256", headers={"kid": KEY_ID})


def _code_challenge_matches(*, code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "plain":
        return code_verifier == code_challenge
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return computed == code_challenge
    return False


async def validate_connect_credentials(
    *, domain_url: str, api_id: str, api_key: str, http_client: httpx.AsyncClient
) -> str | None:
    """Confirms api_id/api_key are real, valid Connect credentials by
    performing the same client_credentials exchange `auth/oauth2.py`'s
    `OAuth2Auth` uses for Layer 2. Returns the real Connect access token if
    valid (callers that don't need it - i.e. don't have
    `MCP_OAUTH_LAYER2_FALLBACK` enabled - just discard it), else `None`.
    """
    try:
        response = await http_client.post(
            f"{domain_url}/cgpapi/auth/token",
            data={"grant_type": "client_credentials", "client_id": api_id, "client_secret": api_key},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as e:
        logger.warning("oauth_server: Connect credential validation request failed: %s", e)
        return None
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    # Live-confirmed (2026-08-28): real responses use snake_case access_token,
    # not the previously-assumed camelCase - accept both, see auth/oauth2.py.
    return body.get("accessToken") or body.get("access_token")


def _http_client() -> httpx.AsyncClient:
    ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    return httpx.AsyncClient(verify=ssl_context)


def _audit(store: OAuthStore, **kwargs: Any) -> None:
    """Audit logging must never break the actual auth flow - log and move on."""
    try:
        store.record_audit_event(**kwargs)
    except Exception:
        logger.exception("oauth_server: failed to write audit event %s", kwargs.get("event_type"))


def _connect_domain_url() -> str:
    return os.environ.get("MEMS_CONNECT_API_URL", "").rstrip("/")


def _issuer_url() -> str:
    return os.environ.get("MCP_OAUTH_RESOURCE_SERVER_URL", "").rstrip("/")


def _oauth_store() -> OAuthStore:
    return OAuthStore()


def layer2_fallback_enabled() -> bool:
    """Opt-in (default off): whether Layer 2 (Soprano) calls may reuse a
    Layer-1-authenticated caller's own Connect credentials instead of
    requiring per-request X-Soprano-* headers - for MCP clients that can't
    send custom headers. Off by default since it means this server persists
    a real Connect API key server-side (bounded by TTL) rather than staying
    fully stateless - see Layer2FallbackAuth's docstring.
    """
    return os.environ.get("MCP_OAUTH_LAYER2_FALLBACK", "").strip().lower() == "true"


def cache_layer2_credential(*, store: OAuthStore, api_id: str, api_key: str, token: str | None) -> None:
    """Called from both grant paths right after a successful Connect
    credential validation - stores api_key (so Layer 2 can silently
    re-authenticate once the cached token expires) and seeds the hot-path
    token cache from the token we just obtained anyway, avoiding a redundant
    extra Connect call on the very first Layer 2 request.
    """
    if not layer2_fallback_enabled():
        return
    store.put_layer2_credential(api_id=api_id, api_key=api_key, ttl_seconds=ACCESS_TOKEN_TTL_SECONDS)
    if token:
        store.put_layer2_cached_token(api_id=api_id, token=token, expires_at=int(time.time()) + CONNECT_TOKEN_TTL_SECONDS)


def layer2_fallback_connection(api_id: str) -> Connection:
    """Builds a Layer 2 `Connection` for a caller with no X-Soprano-* headers,
    reusing the real Connect identity it already proved at Layer 1 login -
    see server.py's `_connection()`.
    """
    return Connection(domain_url=_connect_domain_url(), auth_strategy=Layer2FallbackAuth(api_id=api_id))


@dataclass(frozen=True, slots=True)
class Layer2FallbackAuth:
    """Layer 2 AuthStrategy that reuses the Connect credentials a caller
    already proved ownership of at Layer 1 login, cached server-side (see
    `cache_layer2_credential`) - for MCP clients that can't send per-request
    X-Soprano-* headers. Unlike every other AuthStrategy in this package,
    this one DOES cache across calls (a hot-path Soprano token, refreshed
    transparently on expiry using the stored api_key) - a deliberate,
    opt-in exception to the "no caching" rule in auth/base.py, gated by
    `MCP_OAUTH_LAYER2_FALLBACK`.
    """

    api_id: str

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]:
        store = _oauth_store()
        credential = store.get_layer2_credential(self.api_id)
        if credential is None:
            raise SopranoAuthError(
                f"No cached Layer 2 credential for api_id {self.api_id!r} - re-authenticate via "
                "Layer 1 (/oauth/token or /oauth/authorize) first"
            )
        now = int(time.time())
        # 30s safety margin so a token doesn't expire mid-flight.
        if credential.cached_token and credential.cached_token_expires_at and credential.cached_token_expires_at > now + 30:
            return {"Authorization": f"Bearer {credential.cached_token}"}

        # Cached token missing/stale - silently refresh using the stored api_key.
        token = await validate_connect_credentials(
            domain_url=domain_url, api_id=self.api_id, api_key=credential.api_key, http_client=http_client
        )
        if token is None:
            raise SopranoAuthError(
                f"Cached Layer 2 credential for api_id {self.api_id!r} was rejected by Soprano - it may "
                "have been rotated/revoked. Re-authenticate Layer 1 with current credentials."
            )
        store.put_layer2_cached_token(api_id=self.api_id, token=token, expires_at=now + CONNECT_TOKEN_TTL_SECONDS)
        return {"Authorization": f"Bearer {token}"}


def _login_consent_form(
    *,
    client_name: str,
    scope: str,
    hidden_fields: dict[str, str],
    error: str | None = None,
) -> str:
    hidden_html = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in hidden_fields.items()
    )
    error_html = f'<div class="alert" role="alert">{html.escape(error)}</div>' if error else ""
    scope_html = "".join(f"<li>{html.escape(s)}</li>" for s in scope.split()) or "<li>Basic account access</li>"
    return _CONSENT_FORM_TEMPLATE.substitute(
        client_name=html.escape(client_name),
        scope_html=scope_html,
        error_html=error_html,
        hidden_html=hidden_html,
    )


async def handle_authorize_get(request: Request) -> Response:
    params = request.query_params
    if params.get("response_type") != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    store = _oauth_store()
    client = store.get_client(client_id)
    if client is None:
        return JSONResponse({"error": "invalid_client", "error_description": "unknown client_id"}, status_code=400)
    if client.redirect_uris and redirect_uri not in client.redirect_uris:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri not registered"}, status_code=400)

    hidden_fields = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": params.get("state", ""),
        "scope": params.get("scope", ""),
        "code_challenge": params.get("code_challenge", ""),
        "code_challenge_method": params.get("code_challenge_method", ""),
    }
    return HTMLResponse(_login_consent_form(client_name=client.name, scope=hidden_fields["scope"], hidden_fields=hidden_fields))


async def handle_authorize_post(request: Request) -> Response:
    form = await request.form()
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    state = str(form.get("state", ""))
    scope = str(form.get("scope", ""))
    code_challenge = str(form.get("code_challenge", "")) or None
    code_challenge_method = str(form.get("code_challenge_method", "")) or None
    action = str(form.get("action", ""))

    store = _oauth_store()
    client = store.get_client(client_id)
    if client is None:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    if action != "approve":
        _audit(store, event_type="consent_denied", client_id=client_id)
        query = urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)

    api_id = str(form.get("api_id", ""))
    api_key = str(form.get("api_key", ""))
    async with _http_client() as http_client:
        connect_token = await validate_connect_credentials(
            domain_url=_connect_domain_url(), api_id=api_id, api_key=api_key, http_client=http_client
        )
    if connect_token is None:
        _audit(store, event_type="login_failed", api_id=api_id, client_id=client_id)
        hidden_fields = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": scope,
            "code_challenge": code_challenge or "",
            "code_challenge_method": code_challenge_method or "",
        }
        return HTMLResponse(
            _login_consent_form(
                client_name=client.name,
                scope=scope,
                hidden_fields=hidden_fields,
                error="Invalid Connect API ID or API Key. Please try again.",
            ),
            status_code=401,
        )

    _audit(store, event_type="login_succeeded", api_id=api_id, client_id=client_id)
    cache_layer2_credential(store=store, api_id=api_id, api_key=api_key, token=connect_token)
    store.put_consent(api_id=api_id, client_id=client_id, scope=scope, consent_version=CONSENT_VERSION)
    _audit(store, event_type="consent_approved", api_id=api_id, client_id=client_id)

    code = store.create_auth_code(
        client_id=client_id,
        api_id=api_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        ttl_seconds=AUTH_CODE_TTL_SECONDS,
    )
    query = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)


def _token_response(*, api_id: str, client_id: str, scope: str, refresh_token: str | None = None) -> JSONResponse:
    token = mint_access_token(issuer=_issuer_url(), api_id=api_id, client_id=client_id, scope=scope)
    body: dict[str, Any] = {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "scope": scope,
    }
    if refresh_token:
        body["refresh_token"] = refresh_token
    return JSONResponse(body)


def _parse_basic_auth(request: Request) -> tuple[str, str] | None:
    """Parses an RFC 6749 `client_secret_basic` Authorization header, if
    present - some clients (confirmed real-world behaviour: at least one
    Zendesk ZIS connection) send client credentials this way rather than as
    `client_id`/`client_secret` form fields, even though our discovery
    metadata only advertises `client_secret_post`. Returns `None` if absent
    or malformed so callers can fall back to the form body.
    """
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[len("basic ") :].strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    client_id, sep, client_secret = decoded.partition(":")
    if not sep:
        return None
    return client_id, client_secret


def _reject(*, grant_type: str, error: str, description: str) -> JSONResponse:
    """Every /oauth/token 400 goes through here so the reason is always in
    CloudWatch - previously these were silent, requiring DynamoDB archaeology
    to diagnose a stuck client (see e.g. the Zendesk refresh-token incident).
    """
    logger.warning("oauth token endpoint rejected %s grant: %s", grant_type, description)
    return JSONResponse({"error": error, "error_description": description}, status_code=400)


async def _handle_authorization_code_grant(form: Any, store: OAuthStore, basic_auth: tuple[str, str] | None) -> Response:
    code = str(form.get("code", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    client_id = str(form.get("client_id", "")) or (basic_auth[0] if basic_auth else "")
    code_verifier = form.get("code_verifier")

    auth_code = store.consume_auth_code(code)
    if auth_code is None:
        return _reject(grant_type="authorization_code", error="invalid_grant", description="unknown or expired code")
    if auth_code.client_id != client_id or auth_code.redirect_uri != redirect_uri:
        return _reject(
            grant_type="authorization_code", error="invalid_grant", description="client_id/redirect_uri mismatch"
        )
    if auth_code.code_challenge:
        if not code_verifier or not _code_challenge_matches(
            code_verifier=str(code_verifier),
            code_challenge=auth_code.code_challenge,
            method=auth_code.code_challenge_method or "S256",
        ):
            return _reject(grant_type="authorization_code", error="invalid_grant", description="PKCE verification failed")

    _audit(store, event_type="token_issued", api_id=auth_code.api_id, client_id=client_id, detail="authorization_code")
    refresh_token = store.create_refresh_token(
        client_id=client_id, api_id=auth_code.api_id, scope=auth_code.scope, ttl_seconds=REFRESH_TOKEN_TTL_SECONDS
    )
    return _token_response(api_id=auth_code.api_id, client_id=client_id, scope=auth_code.scope, refresh_token=refresh_token)


async def _handle_client_credentials_grant(form: Any, store: OAuthStore, basic_auth: tuple[str, str] | None) -> Response:
    api_id = str(form.get("client_id", "")) or (basic_auth[0] if basic_auth else "")
    api_key = str(form.get("client_secret", "")) or (basic_auth[1] if basic_auth else "")
    scope = str(form.get("scope", ""))
    async with _http_client() as http_client:
        connect_token = await validate_connect_credentials(
            domain_url=_connect_domain_url(), api_id=api_id, api_key=api_key, http_client=http_client
        )
    if connect_token is None:
        _audit(store, event_type="login_failed", api_id=api_id, detail="client_credentials")
        logger.warning("oauth token endpoint rejected client_credentials grant: invalid Connect credentials")
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    _audit(store, event_type="token_issued", api_id=api_id, client_id=api_id, detail="client_credentials")
    cache_layer2_credential(store=store, api_id=api_id, api_key=api_key, token=connect_token)
    return _token_response(api_id=api_id, client_id=api_id, scope=scope)


async def handle_token(request: Request) -> Response:
    form = await request.form()
    grant_type = str(form.get("grant_type", ""))
    store = _oauth_store()
    basic_auth = _parse_basic_auth(request)

    if grant_type == "authorization_code":
        return await _handle_authorization_code_grant(form, store, basic_auth)
    if grant_type == "client_credentials":
        return await _handle_client_credentials_grant(form, store, basic_auth)
    if grant_type == "refresh_token":
        return await _handle_refresh_token_grant(form, store, basic_auth)
    logger.warning("oauth token endpoint rejected unsupported grant_type: %r", grant_type)
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def _handle_refresh_token_grant(form: Any, store: OAuthStore, basic_auth: tuple[str, str] | None) -> Response:
    """Lets authorization_code clients (Zendesk, VS Code) silently renew
    without repeating the interactive consent flow every
    ACCESS_TOKEN_TTL_SECONDS - see RefreshToken's docstring for why
    client_credentials callers don't need this at all.
    """
    refresh_token = str(form.get("refresh_token", ""))
    client_id = str(form.get("client_id", "")) or (basic_auth[0] if basic_auth else "")

    record = store.consume_refresh_token(refresh_token)
    if record is None:
        return _reject(grant_type="refresh_token", error="invalid_grant", description="unknown or expired refresh_token")
    if record.client_id != client_id:
        return _reject(
            grant_type="refresh_token",
            error="invalid_grant",
            description=f"client_id mismatch (expected {record.client_id!r}, got {client_id!r})",
        )

    _audit(store, event_type="token_refreshed", api_id=record.api_id, client_id=client_id)
    if layer2_fallback_enabled():
        # Otherwise the Layer 2 credential cache (see cache_layer2_credential)
        # silently expires ACCESS_TOKEN_TTL_SECONDS after the last full
        # login/client_credentials call, even though this refresh just proved
        # the Layer 1 session is still very much alive - confirmed real-world
        # break: Zendesk's list_whatsapp_templates started failing ~1hr after
        # login with "No cached Layer 2 credential" despite token refresh
        # working fine. Re-touching it here keeps it alive for as long as the
        # client keeps refreshing, mirroring the refresh token's own sliding
        # expiry - no re-validation against Soprano needed, just extend the TTL.
        existing_credential = store.get_layer2_credential(record.api_id)
        if existing_credential is not None:
            store.put_layer2_credential(
                api_id=record.api_id, api_key=existing_credential.api_key, ttl_seconds=ACCESS_TOKEN_TTL_SECONDS
            )
    new_refresh_token = store.create_refresh_token(
        client_id=client_id, api_id=record.api_id, scope=record.scope, ttl_seconds=REFRESH_TOKEN_TTL_SECONDS
    )
    return _token_response(api_id=record.api_id, client_id=client_id, scope=record.scope, refresh_token=new_refresh_token)


# RFC 7591 grant types this server can actually satisfy for a dynamically
# registered client - "implicit"/others are never supported.
_DCR_SUPPORTED_GRANT_TYPES = ("authorization_code", "client_credentials")


async def handle_register(request: Request) -> Response:
    """RFC 7591 Dynamic Client Registration - lets an MCP client with no
    pre-seeded client_id (unlike zendesk-agent/claude-desktop/etc., added via
    Terraform) register itself at runtime instead of failing outright or
    needing a human to add a DynamoDB row first.

    Always registers a **public client** (`token_endpoint_auth_method:
    "none"`), regardless of what's requested: `_handle_authorization_code_grant`
    already relies on PKCE, not a client_secret, for security, so there's no
    confidential-client story to build here. `client_credentials` callers
    don't need registration at all (see oauth_server.py's module docstring) -
    they authenticate directly with their own Connect API ID/API KEY.
    """
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "malformed JSON body"}, status_code=400
        )
    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "body must be a JSON object"}, status_code=400
        )

    requested_grant_types = body.get("grant_types") or ["authorization_code"]
    if not isinstance(requested_grant_types, list) or not requested_grant_types:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "grant_types must be a non-empty array"},
            status_code=400,
        )
    grant_types = [g for g in requested_grant_types if g in _DCR_SUPPORTED_GRANT_TYPES]
    if not grant_types:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "no supported grant type requested"},
            status_code=400,
        )

    redirect_uris = body.get("redirect_uris") or []
    if "authorization_code" in grant_types and (not isinstance(redirect_uris, list) or not redirect_uris):
        return JSONResponse(
            {
                "error": "invalid_client_metadata",
                "error_description": "redirect_uris is required for the authorization_code grant",
            },
            status_code=400,
        )

    client_name = str(body.get("client_name") or "Dynamically registered client")
    scope = str(body.get("scope") or "")

    store = _oauth_store()
    client_id = store.create_client(
        name=client_name,
        require_consent=True,  # safer default than the manually-vetted seeded clients
        allowed_grant_types=grant_types,
        redirect_uris=redirect_uris,
        allowed_scopes=scope.split() if scope else [],
    )
    _audit(store, event_type="client_registered", client_id=client_id, detail=client_name)

    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": ["code"] if "authorization_code" in grant_types else [],
            "token_endpoint_auth_method": "none",
            "scope": scope,
        },
        status_code=201,
    )


async def handle_authorization_server_metadata(_: Request) -> Response:
    issuer = _issuer_url()
    if not issuer:
        return JSONResponse({"error": "oauth2.1 not configured"}, status_code=404)
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register",
            "jwks_uri": f"{issuer}/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": ["message.send", "message.status.read"],
        }
    )


async def handle_jwks(_: Request) -> Response:
    return JSONResponse(jwks_document())
