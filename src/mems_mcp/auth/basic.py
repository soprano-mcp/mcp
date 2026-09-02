from __future__ import annotations

import base64
from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class BasicAuth:
    """Basic authentication: base64(username:password) in the Authorization header."""

    username: str
    password: str

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]:
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}
