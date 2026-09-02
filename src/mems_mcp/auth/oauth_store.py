"""DynamoDB-backed storage for the self-hosted OAuth Authorization Server
(Layer 1 auth) - see `oauth_server.py` and `MCP_OAuth_Zendesk_PRD.md`.

Tables (names configurable via env vars - provision matching tables via your
own deployment tooling): registered OAuth clients, short-lived authorization
codes
(redeemable multiple times within their own short TTL - see
`consume_auth_code`), per-(api_id, client) consent records, an audit log,
a Layer 2 credential cache (opt-in), and long-lived refresh tokens (for the
authorization_code grant only). Needed because ECS/Lambda instances are
stateless across restarts/instances - in-memory storage would break as soon
as there's more than one running task.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import boto3

# 90-day retention for audit records, enforced via the table's TTL attribute.
_AUDIT_RETENTION_SECONDS = 90 * 24 * 3600


@dataclass(frozen=True, slots=True)
class OAuthClient:
    """A registered OAuth client application (e.g. "zendesk-agent",
    "claude-desktop") - distinct from the Connect API ID/KEY, which
    represents the end-user identity entered at login time.
    """

    client_id: str
    name: str
    require_consent: bool
    allowed_grant_types: list[str]
    redirect_uris: list[str] = field(default_factory=list)
    allowed_scopes: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AuthCode:
    code: str
    client_id: str
    api_id: str
    redirect_uri: str
    scope: str
    code_challenge: str | None
    code_challenge_method: str | None


@dataclass(frozen=True, slots=True)
class Layer2Credential:
    """Cached Layer 2 (Soprano) identity for a Layer-1-authenticated caller
    that can't send per-request X-Soprano-* headers (see oauth_server.py's
    `PrecomputedTokenAuth` fallback). `api_key` is the real Connect secret -
    holding it is a deliberate, opt-in security tradeoff (see
    `MCP_OAUTH_LAYER2_FALLBACK` in server.py), bounded by this record's own
    DynamoDB TTL rather than kept indefinitely.
    """

    api_id: str
    api_key: str
    cached_token: str | None
    cached_token_expires_at: int | None


@dataclass(frozen=True, slots=True)
class RefreshToken:
    """A long-lived refresh token for the authorization_code grant only -
    client_credentials callers already hold their own api_id/api_key and can
    just re-authenticate directly any time, so they have no need for this.
    Rotated on every use (RFC 6749 section 10.4 best practice, and the shape
    Pulse's own generic OAuth2 client already expects - see
    Ubisend\\Pulse\\Plugins\\Integrations\\AuthorizationTypes\\OAuth2::requestToken()).
    """

    token: str
    client_id: str
    api_id: str
    scope: str


class OAuthStore:
    """Thin wrapper around the 6 DynamoDB tables (4 core + 2 opt-in: Layer 2
    credential cache, refresh tokens). Table names default to
    `mems-mcp-oauth-{clients,codes,consents,audit,layer2-credentials,refresh-tokens}`,
    overridable per-deployment via env vars so each MEMS instance can point
    at its own tables.
    """

    def __init__(self, *, dynamodb_resource: Any | None = None) -> None:
        self._db = dynamodb_resource if dynamodb_resource is not None else boto3.resource("dynamodb")
        self._clients_table = self._db.Table(os.environ.get("MCP_OAUTH_CLIENTS_TABLE", "mems-mcp-oauth-clients"))
        self._codes_table = self._db.Table(os.environ.get("MCP_OAUTH_CODES_TABLE", "mems-mcp-oauth-codes"))
        self._consents_table = self._db.Table(os.environ.get("MCP_OAUTH_CONSENTS_TABLE", "mems-mcp-oauth-consents"))
        self._audit_table = self._db.Table(os.environ.get("MCP_OAUTH_AUDIT_TABLE", "mems-mcp-oauth-audit"))
        self._layer2_credentials_table = self._db.Table(
            os.environ.get("MCP_OAUTH_LAYER2_CREDENTIALS_TABLE", "mems-mcp-oauth-layer2-credentials")
        )
        self._refresh_tokens_table = self._db.Table(
            os.environ.get("MCP_OAUTH_REFRESH_TOKENS_TABLE", "mems-mcp-oauth-refresh-tokens")
        )

    def get_client(self, client_id: str) -> OAuthClient | None:
        item = self._clients_table.get_item(Key={"client_id": client_id}).get("Item")
        if not item:
            return None
        return OAuthClient(
            client_id=item["client_id"],
            name=item.get("name", item["client_id"]),
            require_consent=bool(item.get("require_consent", True)),
            allowed_grant_types=list(item.get("allowed_grant_types", ["authorization_code"])),
            redirect_uris=list(item.get("redirect_uris", [])),
            allowed_scopes=list(item.get("allowed_scopes", [])),
        )

    def create_client(
        self,
        *,
        name: str,
        require_consent: bool,
        allowed_grant_types: list[str],
        redirect_uris: list[str],
        allowed_scopes: list[str],
    ) -> str:
        """Registers a new OAuth client at runtime (RFC 7591 Dynamic Client
        Registration) - unlike the Terraform-seeded clients (zendesk-agent,
        claude-desktop, etc.), this lets a brand new MCP client self-register
        without an admin manually adding a DynamoDB row first. The `dcr-`
        prefix makes self-registered clients easy to spot against the seeded
        ones in logs/DynamoDB.
        """
        client_id = f"dcr-{secrets.token_urlsafe(16)}"
        self._clients_table.put_item(
            Item={
                "client_id": client_id,
                "name": name,
                "require_consent": require_consent,
                "allowed_grant_types": allowed_grant_types,
                "redirect_uris": redirect_uris,
                "allowed_scopes": allowed_scopes,
            }
        )
        return client_id

    def create_auth_code(
        self,
        *,
        client_id: str,
        api_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
        ttl_seconds: int,
    ) -> str:
        code = secrets.token_urlsafe(32)
        self._codes_table.put_item(
            Item={
                "code": code,
                "client_id": client_id,
                "api_id": api_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "code_challenge": code_challenge or "",
                "code_challenge_method": code_challenge_method or "",
                "expires_at": int(time.time()) + ttl_seconds,
            }
        )
        return code

    def consume_auth_code(self, code: str) -> AuthCode | None:
        """Redeemable any number of times within its own short TTL window
        (NOT deleted on first use) - real-world clients (confirmed: Zendesk's
        ZIS integration platform) fire near-simultaneous duplicate token
        exchange requests for the same code, and strict single-use semantics
        make the losing request fail with a confusing "unknown or expired
        code" error even though nothing is actually wrong. Security instead
        relies on the short (5 min) TTL plus mandatory PKCE `code_verifier` -
        an attacker who only sees the leaked code (e.g. via a referrer
        header) still can't redeem it without the verifier, which is never
        transmitted alongside the code. Returns `None` if the code is
        missing or expired (still deleted then, so it doesn't linger past
        its own TTL waiting for DynamoDB's own sweep).
        """
        item = self._codes_table.get_item(Key={"code": code}).get("Item")
        if not item:
            return None
        if int(item["expires_at"]) < int(time.time()):
            self._codes_table.delete_item(Key={"code": code})
            return None
        return AuthCode(
            code=code,
            client_id=item["client_id"],
            api_id=item["api_id"],
            redirect_uri=item["redirect_uri"],
            scope=item.get("scope", ""),
            code_challenge=item.get("code_challenge") or None,
            code_challenge_method=item.get("code_challenge_method") or None,
        )

    def has_consent(self, *, api_id: str, client_id: str, scope: str, consent_version: str) -> bool:
        item = self._consents_table.get_item(Key={"api_id": api_id, "client_id": client_id}).get("Item")
        if not item:
            return False
        return item.get("scope") == scope and item.get("consent_version") == consent_version

    def put_consent(self, *, api_id: str, client_id: str, scope: str, consent_version: str) -> None:
        self._consents_table.put_item(
            Item={
                "api_id": api_id,
                "client_id": client_id,
                "scope": scope,
                "consent_version": consent_version,
                "consented_at": int(time.time()),
            }
        )

    def record_audit_event(
        self,
        *,
        event_type: str,
        api_id: str | None = None,
        client_id: str | None = None,
        detail: str = "",
    ) -> None:
        """Best-effort: a DynamoDB failure here must never block the actual
        auth flow, so callers should wrap this in a try/except (see
        oauth_server.py's `_audit` helper) rather than let it propagate.
        """
        self._audit_table.put_item(
            Item={
                "event_id": secrets.token_hex(16),
                "timestamp": int(time.time() * 1000),
                "event_type": event_type,
                "api_id": api_id or "",
                "client_id": client_id or "",
                "detail": detail,
                "expires_at": int(time.time()) + _AUDIT_RETENTION_SECONDS,
            }
        )

    def put_layer2_credential(self, *, api_id: str, api_key: str, ttl_seconds: int) -> None:
        """Upserts the cached Layer 2 identity for `api_id`, called every time
        Layer 1 validates it (client_credentials or authorize-consent) - this
        refreshes the record's own TTL too, so an abandoned session's cached
        credential is auto-purged rather than kept indefinitely. Does NOT
        touch any previously cached Soprano token for this api_id (still
        valid until its own expiry, reused as-is by the next lookup).
        """
        self._layer2_credentials_table.update_item(
            Key={"api_id": api_id},
            UpdateExpression="SET api_key = :api_key, expires_at = :expires_at",
            ExpressionAttributeValues={":api_key": api_key, ":expires_at": int(time.time()) + ttl_seconds},
        )

    def get_layer2_credential(self, api_id: str) -> Layer2Credential | None:
        item = self._layer2_credentials_table.get_item(Key={"api_id": api_id}).get("Item")
        if not item:
            return None
        return Layer2Credential(
            api_id=api_id,
            api_key=item["api_key"],
            cached_token=item.get("cached_token"),
            cached_token_expires_at=int(item["cached_token_expires_at"]) if "cached_token_expires_at" in item else None,
        )

    def put_layer2_cached_token(self, *, api_id: str, token: str, expires_at: int) -> None:
        """Updates just the hot-path cached Soprano token, leaving the
        record's own `api_key`/`expires_at` (session TTL) untouched.
        """
        self._layer2_credentials_table.update_item(
            Key={"api_id": api_id},
            UpdateExpression="SET cached_token = :token, cached_token_expires_at = :expires_at",
            ExpressionAttributeValues={":token": token, ":expires_at": expires_at},
        )

    def create_refresh_token(self, *, client_id: str, api_id: str, scope: str, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        self._refresh_tokens_table.put_item(
            Item={
                "refresh_token": token,
                "client_id": client_id,
                "api_id": api_id,
                "scope": scope,
                "expires_at": int(time.time()) + ttl_seconds,
            }
        )
        return token

    def consume_refresh_token(self, token: str) -> RefreshToken | None:
        """Rotated on every use: always deletes the token (even if expired),
        so a stolen/replayed refresh token can never be exchanged twice - see
        RefreshToken's docstring. Returns `None` if unknown or expired.
        """
        item = self._refresh_tokens_table.get_item(Key={"refresh_token": token}).get("Item")
        if not item:
            return None
        self._refresh_tokens_table.delete_item(Key={"refresh_token": token})
        if int(item["expires_at"]) < int(time.time()):
            return None
        return RefreshToken(token=token, client_id=item["client_id"], api_id=item["api_id"], scope=item.get("scope", ""))

