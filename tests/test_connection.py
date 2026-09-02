from __future__ import annotations

import pytest

from mems_mcp.connection import (
    HEADER_API_ID,
    HEADER_API_KEY,
    HEADER_AUTH_METHOD,
    HEADER_CLIENT_ID,
    HEADER_CLIENT_SECRET,
    HEADER_DOMAIN_URL,
    HEADER_PASSWORD,
    HEADER_SESSION_COOKIE,
    HEADER_USERNAME,
    connection_from_env,
    connection_from_headers,
)
from mems_mcp.auth.api_key import ApiKeyAuth
from mems_mcp.auth.basic import BasicAuth
from mems_mcp.auth.legacy_oauth2 import LegacyOAuth2Auth
from mems_mcp.auth.oauth2 import OAuth2Auth
from mems_mcp.auth.session_cookie import SessionCookieAuth
from mems_mcp.exceptions import ConnectionConfigError

DOMAIN = "https://aus.sopranodesign.com"


def test_missing_domain_url_raises() -> None:
    with pytest.raises(ConnectionConfigError, match=HEADER_DOMAIN_URL):
        connection_from_headers({HEADER_AUTH_METHOD: "api_key"})


def test_missing_auth_method_raises() -> None:
    with pytest.raises(ConnectionConfigError, match=HEADER_AUTH_METHOD):
        connection_from_headers({HEADER_DOMAIN_URL: DOMAIN})


def test_invalid_auth_method_raises() -> None:
    with pytest.raises(ConnectionConfigError, match="Invalid"):
        connection_from_headers({HEADER_DOMAIN_URL: DOMAIN, HEADER_AUTH_METHOD: "not-a-method"})


def test_domain_url_trailing_slash_is_stripped() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: f"{DOMAIN}/",
            HEADER_AUTH_METHOD: "api_key",
            HEADER_API_ID: "12345",
            HEADER_API_KEY: "secret",
        }
    )
    assert connection.domain_url == DOMAIN


def test_api_key_method_builds_api_key_auth() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: DOMAIN,
            HEADER_AUTH_METHOD: "api_key",
            HEADER_API_ID: "12345",
            HEADER_API_KEY: "secret",
        }
    )
    assert isinstance(connection.auth_strategy, ApiKeyAuth)
    assert connection.auth_strategy.api_id == "12345"
    assert connection.auth_strategy.api_key == "secret"


def test_api_key_method_missing_credentials_raises() -> None:
    with pytest.raises(ConnectionConfigError, match=HEADER_API_KEY):
        connection_from_headers(
            {HEADER_DOMAIN_URL: DOMAIN, HEADER_AUTH_METHOD: "api_key", HEADER_API_ID: "12345"}
        )


def test_oauth2_method_builds_oauth2_auth() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: DOMAIN,
            HEADER_AUTH_METHOD: "oauth2",
            HEADER_CLIENT_ID: "cid",
            HEADER_CLIENT_SECRET: "csecret",
        }
    )
    assert isinstance(connection.auth_strategy, OAuth2Auth)
    assert connection.auth_strategy.client_id == "cid"


def test_basic_method_builds_basic_auth() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: DOMAIN,
            HEADER_AUTH_METHOD: "basic",
            HEADER_USERNAME: "user@url.com",
            HEADER_PASSWORD: "pwd",
        }
    )
    assert isinstance(connection.auth_strategy, BasicAuth)


def test_legacy_oauth2_method_builds_legacy_auth() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: DOMAIN,
            HEADER_AUTH_METHOD: "legacy_oauth2",
            HEADER_USERNAME: "user@url.com",
            HEADER_PASSWORD: "pwd",
        }
    )
    assert isinstance(connection.auth_strategy, LegacyOAuth2Auth)


def test_auth_method_is_case_insensitive() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: DOMAIN,
            HEADER_AUTH_METHOD: "API_KEY",
            HEADER_API_ID: "12345",
            HEADER_API_KEY: "secret",
        }
    )
    assert isinstance(connection.auth_strategy, ApiKeyAuth)


def test_connection_from_env_builds_connection() -> None:
    env = {
        "SOPRANO_DOMAIN_URL": DOMAIN,
        "SOPRANO_AUTH_METHOD": "api_key",
        "SOPRANO_API_ID": "12345",
        "SOPRANO_API_KEY": "secret",
    }
    connection = connection_from_env(env)
    assert connection.domain_url == DOMAIN
    assert isinstance(connection.auth_strategy, ApiKeyAuth)


def test_connection_from_env_missing_domain_url_raises() -> None:
    with pytest.raises(ConnectionConfigError, match=HEADER_DOMAIN_URL):
        connection_from_env({"SOPRANO_AUTH_METHOD": "api_key"})


def test_connection_from_env_mentions_env_var_in_error() -> None:
    with pytest.raises(ConnectionConfigError, match="SOPRANO_DOMAIN_URL"):
        connection_from_env({"SOPRANO_AUTH_METHOD": "api_key"})


def test_session_cookie_method_builds_session_cookie_auth() -> None:
    connection = connection_from_headers(
        {
            HEADER_DOMAIN_URL: DOMAIN,
            HEADER_AUTH_METHOD: "session_cookie",
            HEADER_SESSION_COOKIE: "ABC123DEF456",
        }
    )
    assert isinstance(connection.auth_strategy, SessionCookieAuth)
    assert connection.auth_strategy.session_cookie == "ABC123DEF456"


def test_session_cookie_method_missing_cookie_raises() -> None:
    with pytest.raises(ConnectionConfigError, match=HEADER_SESSION_COOKIE):
        connection_from_headers({HEADER_DOMAIN_URL: DOMAIN, HEADER_AUTH_METHOD: "session_cookie"})


def test_connection_from_env_builds_session_cookie_auth() -> None:
    env = {
        "SOPRANO_DOMAIN_URL": DOMAIN,
        "SOPRANO_AUTH_METHOD": "session_cookie",
        "SOPRANO_SESSION_COOKIE": "ABC123DEF456",
    }
    connection = connection_from_env(env)
    assert isinstance(connection.auth_strategy, SessionCookieAuth)
