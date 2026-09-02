from __future__ import annotations

import time

import boto3
import pytest
from moto import mock_aws

from mems_mcp.auth.oauth_store import OAuthClient, OAuthStore

CLIENTS_TABLE = "test-oauth-clients"
CODES_TABLE = "test-oauth-codes"
CONSENTS_TABLE = "test-oauth-consents"
AUDIT_TABLE = "test-oauth-audit"
LAYER2_CREDENTIALS_TABLE = "test-oauth-layer2-credentials"
REFRESH_TOKENS_TABLE = "test-oauth-refresh-tokens"


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MCP_OAUTH_CLIENTS_TABLE", CLIENTS_TABLE)
    monkeypatch.setenv("MCP_OAUTH_CODES_TABLE", CODES_TABLE)
    monkeypatch.setenv("MCP_OAUTH_CONSENTS_TABLE", CONSENTS_TABLE)
    monkeypatch.setenv("MCP_OAUTH_AUDIT_TABLE", AUDIT_TABLE)
    monkeypatch.setenv("MCP_OAUTH_LAYER2_CREDENTIALS_TABLE", LAYER2_CREDENTIALS_TABLE)
    monkeypatch.setenv("MCP_OAUTH_REFRESH_TOKENS_TABLE", REFRESH_TOKENS_TABLE)
    with mock_aws():
        db = boto3.resource("dynamodb", region_name="eu-west-2")
        db.create_table(
            TableName=CLIENTS_TABLE,
            KeySchema=[{"AttributeName": "client_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "client_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=CODES_TABLE,
            KeySchema=[{"AttributeName": "code", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "code", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=CONSENTS_TABLE,
            KeySchema=[
                {"AttributeName": "api_id", "KeyType": "HASH"},
                {"AttributeName": "client_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "api_id", "AttributeType": "S"},
                {"AttributeName": "client_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=AUDIT_TABLE,
            KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=LAYER2_CREDENTIALS_TABLE,
            KeySchema=[{"AttributeName": "api_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "api_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        db.create_table(
            TableName=REFRESH_TOKENS_TABLE,
            KeySchema=[{"AttributeName": "refresh_token", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "refresh_token", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield OAuthStore(dynamodb_resource=db)


def test_get_client_missing_returns_none(store: OAuthStore) -> None:
    assert store.get_client("unknown") is None


def test_get_client_returns_registered_client(store: OAuthStore) -> None:
    store._clients_table.put_item(  # type: ignore[attr-defined]
        Item={
            "client_id": "zendesk-agent",
            "name": "Zendesk Agent",
            "require_consent": True,
            "allowed_grant_types": ["authorization_code"],
            "redirect_uris": ["https://zendesk.example.com/callback"],
            "allowed_scopes": ["message.send"],
        }
    )
    client = store.get_client("zendesk-agent")
    assert client == OAuthClient(
        client_id="zendesk-agent",
        name="Zendesk Agent",
        require_consent=True,
        allowed_grant_types=["authorization_code"],
        redirect_uris=["https://zendesk.example.com/callback"],
        allowed_scopes=["message.send"],
    )


def test_auth_code_round_trip(store: OAuthStore) -> None:
    code = store.create_auth_code(
        client_id="zendesk-agent",
        api_id="12345",
        redirect_uri="https://zendesk.example.com/callback",
        scope="message.send",
        code_challenge="challenge",
        code_challenge_method="S256",
        ttl_seconds=300,
    )
    result = store.consume_auth_code(code)
    assert result is not None
    assert result.client_id == "zendesk-agent"
    assert result.api_id == "12345"
    assert result.code_challenge == "challenge"
    assert result.code_challenge_method == "S256"


def test_auth_code_is_redeemable_more_than_once_within_ttl(store: OAuthStore) -> None:
    """Deliberately NOT single-use - see consume_auth_code's docstring
    (Zendesk's ZIS platform fires duplicate near-simultaneous token exchange
    requests for the same code; both must succeed, not just the first)."""
    code = store.create_auth_code(
        client_id="zendesk-agent",
        api_id="12345",
        redirect_uri="https://zendesk.example.com/callback",
        scope="",
        code_challenge=None,
        code_challenge_method=None,
        ttl_seconds=300,
    )
    assert store.consume_auth_code(code) is not None
    assert store.consume_auth_code(code) is not None


def test_expired_auth_code_returns_none(store: OAuthStore) -> None:
    code = store.create_auth_code(
        client_id="zendesk-agent",
        api_id="12345",
        redirect_uri="https://zendesk.example.com/callback",
        scope="",
        code_challenge=None,
        code_challenge_method=None,
        ttl_seconds=-1,
    )
    assert store.consume_auth_code(code) is None


def test_consent_round_trip(store: OAuthStore) -> None:
    assert not store.has_consent(api_id="12345", client_id="zendesk-agent", scope="message.send", consent_version="1")
    store.put_consent(api_id="12345", client_id="zendesk-agent", scope="message.send", consent_version="1")
    assert store.has_consent(api_id="12345", client_id="zendesk-agent", scope="message.send", consent_version="1")
    # Different scope/version should not match the stored consent.
    assert not store.has_consent(api_id="12345", client_id="zendesk-agent", scope="message.send", consent_version="2")


def test_record_audit_event_does_not_raise(store: OAuthStore) -> None:
    store.record_audit_event(event_type="login_succeeded", api_id="12345", client_id="zendesk-agent", detail="ok")
    item = store._audit_table.scan()["Items"][0]  # type: ignore[attr-defined]
    assert item["event_type"] == "login_succeeded"


def test_get_layer2_credential_missing_returns_none(store: OAuthStore) -> None:
    assert store.get_layer2_credential("12345") is None


def test_layer2_credential_round_trip(store: OAuthStore) -> None:
    store.put_layer2_credential(api_id="12345", api_key="secret-key", ttl_seconds=3600)
    credential = store.get_layer2_credential("12345")
    assert credential is not None
    assert credential.api_id == "12345"
    assert credential.api_key == "secret-key"
    assert credential.cached_token is None
    assert credential.cached_token_expires_at is None


def test_put_layer2_cached_token_preserves_api_key(store: OAuthStore) -> None:
    store.put_layer2_credential(api_id="12345", api_key="secret-key", ttl_seconds=3600)
    store.put_layer2_cached_token(api_id="12345", token="connect-token", expires_at=int(time.time()) + 1800)
    credential = store.get_layer2_credential("12345")
    assert credential is not None
    assert credential.api_key == "secret-key"
    assert credential.cached_token == "connect-token"


def test_put_layer2_credential_refreshes_ttl_without_clearing_cached_token(store: OAuthStore) -> None:
    store.put_layer2_credential(api_id="12345", api_key="secret-key", ttl_seconds=3600)
    store.put_layer2_cached_token(api_id="12345", token="connect-token", expires_at=int(time.time()) + 1800)
    # A later Layer 1 re-login (refreshing the credential's own TTL) must not
    # wipe out a still-valid cached Soprano token.
    store.put_layer2_credential(api_id="12345", api_key="secret-key", ttl_seconds=3600)
    credential = store.get_layer2_credential("12345")
    assert credential is not None
    assert credential.cached_token == "connect-token"


def test_refresh_token_round_trip(store: OAuthStore) -> None:
    token = store.create_refresh_token(client_id="zendesk-agent", api_id="12345", scope="message.send", ttl_seconds=3600)
    record = store.consume_refresh_token(token)
    assert record is not None
    assert record.client_id == "zendesk-agent"
    assert record.api_id == "12345"
    assert record.scope == "message.send"


def test_refresh_token_is_rotated_single_use(store: OAuthStore) -> None:
    token = store.create_refresh_token(client_id="zendesk-agent", api_id="12345", scope="", ttl_seconds=3600)
    assert store.consume_refresh_token(token) is not None
    # Unlike auth codes, refresh tokens ARE strictly single-use (rotation) -
    # a stolen/replayed one must never work twice.
    assert store.consume_refresh_token(token) is None


def test_expired_refresh_token_returns_none(store: OAuthStore) -> None:
    token = store.create_refresh_token(client_id="zendesk-agent", api_id="12345", scope="", ttl_seconds=-1)
    assert store.consume_refresh_token(token) is None


def test_unknown_refresh_token_returns_none(store: OAuthStore) -> None:
    assert store.consume_refresh_token("does-not-exist") is None

