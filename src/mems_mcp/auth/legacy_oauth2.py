from __future__ import annotations

from dataclasses import dataclass

import httpx

from mems_mcp.exceptions import SopranoAuthError


@dataclass(frozen=True, slots=True)
class LegacyOAuth2Auth:
    """Soprano OAuth2 (Legacy) authentication.

    POST {domain_url}/cgpapi/auth/login with a JSON {username, password} body,
    returning a Bearer accessToken (30 min expiry) and a refreshToken (8 hr
    expiry). Since the server does not cache tokens across calls, we always
    log in fresh rather than using the PUT /cgpapi/auth/refresh endpoint.
    """

    username: str
    password: str

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]:
        response = await http_client.post(
            f"{domain_url}/cgpapi/auth/login",
            json={"username": self.username, "password": self.password},
        )
        if response.status_code != 200:
            raise SopranoAuthError(f"Legacy login request failed with status {response.status_code}: {response.text}")

        body = response.json()
        # Accept both casings - see auth/oauth2.py, live-confirmed to actually
        # return snake_case on this same API family.
        access_token = body.get("accessToken") or body.get("access_token")
        if not access_token:
            raise SopranoAuthError("Legacy login response did not contain an accessToken")

        token_type = body.get("tokenType") or body.get("token_type") or "Bearer"
        return {"Authorization": f"{token_type} {access_token}"}
