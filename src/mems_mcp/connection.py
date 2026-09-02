"""Parses per-request Soprano connection info from custom HTTP headers.

Soprano credentials are supplied by the MCP client per-request as custom HTTP
headers (never as MCP tool arguments, to avoid leaking secrets into the LLM's
context) - see docs/mcp-server-implementation-plan.md section 3.

Over stdio there is no per-request HTTP header channel, so `connection_from_env`
reads the equivalent SOPRANO_* environment variables instead (single-tenant,
set when the MCP client launches the server subprocess).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from mems_mcp.auth.api_key import ApiKeyAuth
from mems_mcp.auth.base import AuthStrategy
from mems_mcp.auth.basic import BasicAuth
from mems_mcp.auth.legacy_oauth2 import LegacyOAuth2Auth
from mems_mcp.auth.oauth2 import OAuth2Auth
from mems_mcp.auth.session_cookie import SessionCookieAuth
from mems_mcp.exceptions import ConnectionConfigError

HEADER_DOMAIN_URL = "X-Soprano-Domain-Url"
HEADER_AUTH_METHOD = "X-Soprano-Auth-Method"
HEADER_API_ID = "X-Soprano-Api-Id"
HEADER_API_KEY = "X-Soprano-Api-Key"
HEADER_CLIENT_ID = "X-Soprano-Client-Id"
HEADER_CLIENT_SECRET = "X-Soprano-Client-Secret"
HEADER_USERNAME = "X-Soprano-Username"
HEADER_PASSWORD = "X-Soprano-Password"
HEADER_SESSION_COOKIE = "X-Soprano-Session-Cookie"

# Environment variable equivalents of the headers above, used for the stdio
# transport where there is no HTTP request to read headers from.
ENV_VAR_NAMES: dict[str, str] = {
    HEADER_DOMAIN_URL: "SOPRANO_DOMAIN_URL",
    HEADER_AUTH_METHOD: "SOPRANO_AUTH_METHOD",
    HEADER_API_ID: "SOPRANO_API_ID",
    HEADER_API_KEY: "SOPRANO_API_KEY",
    HEADER_CLIENT_ID: "SOPRANO_CLIENT_ID",
    HEADER_CLIENT_SECRET: "SOPRANO_CLIENT_SECRET",
    HEADER_USERNAME: "SOPRANO_USERNAME",
    HEADER_PASSWORD: "SOPRANO_PASSWORD",
    HEADER_SESSION_COOKIE: "SOPRANO_SESSION_COOKIE",
}


class AuthMethod(str, Enum):
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    LEGACY_OAUTH2 = "legacy_oauth2"
    SESSION_COOKIE = "session_cookie"


@dataclass(frozen=True, slots=True)
class Connection:
    """Per-request target: which Soprano account/domain and how to auth to it."""

    domain_url: str
    auth_strategy: AuthStrategy


def connection_from_headers(headers: Mapping[str, str]) -> Connection:
    """Build a `Connection` from the X-Soprano-* headers of an incoming request.

    Raises `ConnectionConfigError` if required headers are missing or invalid.
    """
    domain_url = headers.get(HEADER_DOMAIN_URL)
    if not domain_url:
        raise ConnectionConfigError(_missing_setting_message(HEADER_DOMAIN_URL))
    domain_url = domain_url.rstrip("/")

    raw_method = headers.get(HEADER_AUTH_METHOD)
    if not raw_method:
        raise ConnectionConfigError(_missing_setting_message(HEADER_AUTH_METHOD))
    try:
        method = AuthMethod(raw_method.strip().lower())
    except ValueError as exc:
        valid = ", ".join(m.value for m in AuthMethod)
        raise ConnectionConfigError(f"Invalid '{HEADER_AUTH_METHOD}' value '{raw_method}'. Must be one of: {valid}") from exc

    return Connection(domain_url=domain_url, auth_strategy=_build_auth_strategy(method, headers))


def connection_from_env(env: Mapping[str, str] | None = None) -> Connection:
    """Build a `Connection` from SOPRANO_* environment variables.

    Used for the stdio transport (and any other transport with no per-request
    HTTP headers available): the MCP client launches the server subprocess
    with these variables set, so the connection is fixed for the lifetime of
    that process (single-tenant), unlike the per-request header-based flow.
    """
    source = env if env is not None else os.environ
    headers = {
        header_name: source[env_var_name] for header_name, env_var_name in ENV_VAR_NAMES.items() if env_var_name in source
    }
    return connection_from_headers(headers)


def _missing_setting_message(header_name: str) -> str:
    env_var_name = ENV_VAR_NAMES[header_name]
    return f"Missing required '{header_name}' header (or '{env_var_name}' environment variable when running over stdio)"


def _require(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    if not value:
        raise ConnectionConfigError(f"{_missing_setting_message(name)} for the selected auth method")
    return value


def _build_auth_strategy(method: AuthMethod, headers: Mapping[str, str]) -> AuthStrategy:
    if method is AuthMethod.API_KEY:
        return ApiKeyAuth(
            api_id=_require(headers, HEADER_API_ID),
            api_key=_require(headers, HEADER_API_KEY),
        )
    if method is AuthMethod.OAUTH2:
        return OAuth2Auth(
            client_id=_require(headers, HEADER_CLIENT_ID),
            client_secret=_require(headers, HEADER_CLIENT_SECRET),
        )
    if method is AuthMethod.BASIC:
        return BasicAuth(
            username=_require(headers, HEADER_USERNAME),
            password=_require(headers, HEADER_PASSWORD),
        )
    if method is AuthMethod.LEGACY_OAUTH2:
        return LegacyOAuth2Auth(
            username=_require(headers, HEADER_USERNAME),
            password=_require(headers, HEADER_PASSWORD),
        )
    if method is AuthMethod.SESSION_COOKIE:
        return SessionCookieAuth(session_cookie=_require(headers, HEADER_SESSION_COOKIE))
    raise ConnectionConfigError(f"Unsupported auth method: {method}")  # pragma: no cover - exhaustive enum

