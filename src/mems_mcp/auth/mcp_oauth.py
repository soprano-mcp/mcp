"""Layer 1 (MCP client -> our server) authentication: OAuth 2.1 bearer token
verification, per the MCP Authorization spec.

This server acts purely as an OAuth 2.1 **Resource Server** - token *issuance*
is delegated entirely to an external Authorization Server (Auth0, Cognito,
Okta, Keycloak, or any standards-compliant OIDC/OAuth2 provider that publishes
a JWKS endpoint). `JWTBearerTokenVerifier` only *verifies* bearer tokens
presented by MCP clients; it has no vendor-specific code, so it works with any
compliant IdP without needing to pick one (see
docs/mcp-server-implementation-plan.md section 13, open question 1).

This is orthogonal to the Layer 2 (server -> Soprano) `AuthStrategy`
implementations in this package - Layer 1 governs who may call this MCP
server at all; Layer 2 governs how this server authenticates to Soprano on
the caller's behalf.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


class JWTBearerTokenVerifier:
    """Verifies JWT bearer tokens against a JWKS endpoint (RFC 7517).

    Implements the `mcp.server.auth.provider.TokenVerifier` protocol
    structurally (matches this codebase's convention for `AuthStrategy`
    implementations in api_key.py/basic.py/etc. - no explicit inheritance).
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str | list[str],
        jwks_uri: str,
        required_scopes: list[str] | None = None,
        algorithms: list[str] | None = None,
        jwk_client: PyJWKClient | None = None,
    ) -> None:
        self._issuer = issuer
        # Multiple accepted audiences - e.g. several Cognito app clients (one
        # per connecting service) all calling this same resource server.
        self._audiences = [audience] if isinstance(audience, str) else list(audience)
        self._required_scopes = required_scopes or []
        self._algorithms = algorithms or ["RS256"]
        # PyJWKClient caches the fetched keyset internally, only refetching on
        # a cache miss (unknown `kid`) - injectable for tests.
        self._jwk_client = jwk_client if jwk_client is not None else PyJWKClient(jwks_uri)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token and return access info if valid, else `None`.

        JWKS lookup + signature verification are synchronous (PyJWT/urllib) -
        run in a thread so a slow/cold JWKS fetch never blocks the event loop.
        """
        try:
            claims = await asyncio.to_thread(self._decode, token)
        except jwt.PyJWTError as e:
            logger.warning("mcp_oauth token rejected: %s: %s", type(e).__name__, e)
            return None

        scopes = _parse_scopes(claims)
        if self._required_scopes and not set(self._required_scopes).issubset(scopes):
            logger.warning("mcp_oauth token rejected: missing required scope(s), has=%s", scopes)
            return None

        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or claims.get("sub") or "unknown"),
            scopes=scopes,
            expires_at=int(claims["exp"]) if "exp" in claims else None,
            subject=claims.get("sub"),
            claims=claims,
        )

    def _decode(self, token: str) -> dict[str, Any]:
        signing_key = self._jwk_client.get_signing_key_from_jwt(token)
        # Some IdPs (e.g. AWS Cognito) omit the standard "aud" claim from
        # access tokens entirely - only ID tokens get "aud" there, and
        # client_credentials grants never issue an ID token. Detect this via
        # the unverified claims first, and if "aud" is absent, skip PyJWT's
        # own audience check and instead compare the configured audience(s)
        # against "client_id" (Cognito's equivalent of "azp"/client_id).
        unverified = jwt.decode(token, options={"verify_signature": False})
        has_aud = "aud" in unverified
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=self._algorithms,
            audience=self._audiences if has_aud else None,
            issuer=self._issuer,
            options={"require": ["exp", "iat"], "verify_aud": has_aud},
        )
        if not has_aud and claims.get("client_id") not in self._audiences:
            raise jwt.InvalidAudienceError("token client_id does not match any expected audience")
        return claims


def _parse_scopes(claims: dict[str, Any]) -> list[str]:
    """Extracts scopes from either the standard `scope` (space-delimited
    string, RFC 8693/OAuth2) or the `scp` (array, used by e.g. Azure AD/Okta)
    claim.
    """
    scope = claims.get("scope")
    if isinstance(scope, str):
        return scope.split()
    scp = claims.get("scp")
    if isinstance(scp, list):
        return [str(s) for s in scp]
    return []
