from __future__ import annotations

from dataclasses import dataclass

import httpx

from mems_mcp.exceptions import SopranoAuthError


@dataclass(frozen=True, slots=True)
class OAuth2Auth:
    """OAuth2 (client_credentials) authentication.

    POST {domain_url}/cgpapi/auth/token, form-urlencoded, grant_type=client_credentials.
    Returns a Bearer accessToken that expires after 30 minutes with no refresh
    token. Since the server does not cache tokens across calls, a fresh token
    is requested on every call.
    """

    client_id: str
    client_secret: str

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]:
        response = await http_client.post(
            f"{domain_url}/cgpapi/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response.status_code != 200:
            raise SopranoAuthError(f"OAuth2 token request failed with status {response.status_code}: {response.text}")

        body = response.json()
        # Live-confirmed (2026-08-28): this endpoint actually returns snake_case
        # (access_token/token_type), despite camelCase being assumed previously -
        # accept both since casing may vary by account/API version.
        access_token = body.get("accessToken") or body.get("access_token")
        if not access_token:
            raise SopranoAuthError("OAuth2 token response did not contain an accessToken")

        token_type = body.get("tokenType") or body.get("token_type") or "Bearer"
        return {"Authorization": f"{token_type} {access_token}"}
