from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from mems_mcp.auth.mcp_oauth import JWTBearerTokenVerifier

ISSUER = "https://auth.example.com/"
AUDIENCE = "https://mems-mcp.example.com"


def _keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_token(private_key: rsa.RSAPrivateKey, /, **extra_claims: object) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "iat": now,
        "exp": now + 300,
        **extra_claims,
    }
    return jwt.encode(claims, private_key, algorithm="RS256")


def _verifier_with_key(public_key: rsa.RSAPublicKey, **kwargs: object) -> JWTBearerTokenVerifier:
    fake_jwk_client = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public_key))
    return JWTBearerTokenVerifier(
        issuer=ISSUER, audience=AUDIENCE, jwks_uri="unused", jwk_client=fake_jwk_client, **kwargs
    )


async def test_valid_token_is_verified() -> None:
    private_key, public_key = _keypair()
    token = _make_token(private_key, scope="send read")
    verifier = _verifier_with_key(public_key)

    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert access_token.subject == "user-123"
    assert access_token.scopes == ["send", "read"]


async def test_token_with_scp_array_claim_is_verified() -> None:
    private_key, public_key = _keypair()
    token = _make_token(private_key, scp=["send", "read"])
    verifier = _verifier_with_key(public_key)

    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert access_token.scopes == ["send", "read"]


async def test_expired_token_is_rejected() -> None:
    private_key, public_key = _keypair()
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-123", "iat": now - 600, "exp": now - 300},
        private_key,
        algorithm="RS256",
    )
    verifier = _verifier_with_key(public_key)

    assert await verifier.verify_token(token) is None


async def test_wrong_audience_is_rejected() -> None:
    private_key, public_key = _keypair()
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "aud": "https://someone-else.example.com", "sub": "user-123", "iat": now, "exp": now + 300},
        private_key,
        algorithm="RS256",
    )
    verifier = _verifier_with_key(public_key)

    assert await verifier.verify_token(token) is None


async def test_wrong_issuer_is_rejected() -> None:
    private_key, public_key = _keypair()
    now = int(time.time())
    token = jwt.encode(
        {"iss": "https://not-the-issuer.example.com", "aud": AUDIENCE, "sub": "user-123", "iat": now, "exp": now + 300},
        private_key,
        algorithm="RS256",
    )
    verifier = _verifier_with_key(public_key)

    assert await verifier.verify_token(token) is None


async def test_signature_from_wrong_key_is_rejected() -> None:
    private_key, _ = _keypair()
    _, other_public_key = _keypair()
    token = _make_token(private_key)
    verifier = _verifier_with_key(other_public_key)

    assert await verifier.verify_token(token) is None


async def test_missing_required_scope_is_rejected() -> None:
    private_key, public_key = _keypair()
    token = _make_token(private_key, scope="read")
    verifier = _verifier_with_key(public_key, required_scopes=["send"])

    assert await verifier.verify_token(token) is None


async def test_required_scopes_satisfied_is_accepted() -> None:
    private_key, public_key = _keypair()
    token = _make_token(private_key, scope="send read")
    verifier = _verifier_with_key(public_key, required_scopes=["send"])

    assert await verifier.verify_token(token) is not None


async def test_malformed_token_is_rejected() -> None:
    _, public_key = _keypair()
    verifier = _verifier_with_key(public_key)

    assert await verifier.verify_token("not-a-jwt") is None


async def test_cognito_style_token_without_aud_claim_matches_client_id() -> None:
    """AWS Cognito access tokens omit the standard "aud" claim entirely -
    verification must fall back to checking "client_id" against the
    configured audience instead."""
    private_key, public_key = _keypair()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": AUDIENCE,  # Cognito client_credentials tokens have no distinct "sub"
            "client_id": AUDIENCE,
            "token_use": "access",
            "scope": "send",
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
    )
    verifier = _verifier_with_key(public_key)

    access_token = await verifier.verify_token(token)

    assert access_token is not None
    assert access_token.client_id == AUDIENCE


async def test_cognito_style_token_with_wrong_client_id_is_rejected() -> None:
    private_key, public_key = _keypair()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "client_id": "some-other-client",
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
    )
    verifier = _verifier_with_key(public_key)

    assert await verifier.verify_token(token) is None


async def test_multiple_audiences_accepts_any_matching_client_id() -> None:
    """Several app clients (e.g. one per connecting service) can all issue
    tokens accepted by the same resource server."""
    private_key, public_key = _keypair()
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "client_id": "other-client-id", "iat": now, "exp": now + 300},
        private_key,
        algorithm="RS256",
    )
    fake_jwk_client = SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public_key))
    verifier = JWTBearerTokenVerifier(
        issuer=ISSUER,
        audience=[AUDIENCE, "other-client-id"],
        jwks_uri="unused",
        jwk_client=fake_jwk_client,
    )

    assert await verifier.verify_token(token) is not None
