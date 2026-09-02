from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class ApiKeyAuth:
    """API Key authentication: static X-MEMS-API-ID / X-MEMS-API-KEY headers.

    No token exchange or expiry - the key pair is sent as-is on every request.
    """

    api_id: str
    api_key: str

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]:
        return {
            "X-MEMS-API-ID": self.api_id,
            "X-MEMS-API-KEY": self.api_key,
        }
