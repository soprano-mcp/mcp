from __future__ import annotations

import httpx
import pytest
import respx

from mems_mcp import recipients
from mems_mcp.auth.api_key import ApiKeyAuth
from mems_mcp.connection import Connection
from mems_mcp.exceptions import SopranoAPIError
from mems_mcp.soprano_client import SopranoClient

DOMAIN = "https://aus.sopranodesign.com"


def test_shape_contact_returns_id_name_and_present_contact_details_only() -> None:
    shaped = recipients.shape_contact(
        {"id": 7, "firstName": "Jo", "lastName": "Smith", "mobile": "61491089858", "email": "", "timeZone": "x"}
    )
    assert shaped == {"id": 7, "name": "Jo Smith", "mobile": "61491089858"}


def test_build_page_uses_total_on_page_one_and_heuristic_after() -> None:
    assert recipients.build_page([{}] * 2, page=1, limit=2, total=5)["has_more"] is True
    assert recipients.build_page([{}] * 1, page=3, limit=2, total=5)["has_more"] is False
    assert recipients.build_page([{}] * 2, page=2, limit=2, total=None)["has_more"] is True


@pytest.mark.parametrize(("page", "limit"), [(0, 10), (1, 0), (1, recipients.MAX_LIMIT + 1)])
def test_validate_paging_rejects_out_of_range(page: int, limit: int) -> None:
    with pytest.raises(ValueError):
        recipients.validate_paging(page, limit)


@respx.mock
async def test_search_rest_sends_paging_filters_and_reads_total() -> None:
    route = respx.get(f"{DOMAIN}/rest/groups").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "name": "A"}], headers={"X-MEMS-Records-Total": "31"})
    )
    connection = Connection(domain_url=DOMAIN, auth_strategy=ApiKeyAuth(api_id="12345", api_key="secret"))
    async with httpx.AsyncClient() as http_client:
        items, total = await SopranoClient(http_client).search_rest(
            connection, "groups", {"name": "QA", "other": None}, page=1, limit=5
        )

    assert items == [{"id": 1, "name": "A"}]
    assert total == 31
    request = route.calls.last.request
    assert dict(request.url.params) == {"name": "QA", "index": "1", "limit": "5", "count": "true"}
    assert request.headers["X-MEMS-API-ID"] == "12345"


@respx.mock
async def test_search_rest_omits_count_after_page_one_and_total_is_none() -> None:
    route = respx.get(f"{DOMAIN}/rest/lists").mock(return_value=httpx.Response(200, json=[]))
    connection = Connection(domain_url=DOMAIN, auth_strategy=ApiKeyAuth(api_id="12345", api_key="secret"))
    async with httpx.AsyncClient() as http_client:
        _, total = await SopranoClient(http_client).search_rest(connection, "lists", {}, page=2, limit=5)

    assert total is None
    assert "count" not in route.calls.last.request.url.params


@respx.mock
async def test_search_rest_adds_permission_hint_on_403() -> None:
    respx.get(f"{DOMAIN}/rest/contacts").mock(return_value=httpx.Response(403, json={}))
    connection = Connection(domain_url=DOMAIN, auth_strategy=ApiKeyAuth(api_id="12345", api_key="secret"))
    async with httpx.AsyncClient() as http_client:
        with pytest.raises(SopranoAPIError, match="lack read permission for contacts"):
            await SopranoClient(http_client).search_rest(connection, "contacts", {}, page=1, limit=5)
