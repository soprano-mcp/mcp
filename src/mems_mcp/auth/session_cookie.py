from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class SessionCookieAuth:
    """Portal session-cookie (JSESSIONID) authentication.

    This is the one documented outlier in the Connect API guide: `GET
    /cgpapi/waba/templates` requires a portal session cookie instead of one
    of the 4 standard auth methods. The cookie value itself is supplied
    per-request by the MCP client (same "raw credentials, no server-side
    storage" model as the other strategies) - the server does not perform any
    login/session-establishment call itself.
    """

    session_cookie: str

    async def get_auth_headers(self, *, domain_url: str, http_client: httpx.AsyncClient) -> dict[str, str]:
        return {"Cookie": f"JSESSIONID={self.session_cookie}"}
