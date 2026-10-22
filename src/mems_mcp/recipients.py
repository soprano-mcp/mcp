"""Shaping of MEMS `/rest/contacts|groups|lists` search results for the recipient-lookup tools.

Only the fields needed to pick a `send_broadcast` endpoint id are returned.
"""

from __future__ import annotations

from typing import Any

DEFAULT_LIMIT = 25
MAX_LIMIT = 100


def shape_contact(raw: dict[str, Any]) -> dict[str, Any]:
    name = " ".join(part for part in (raw.get("firstName"), raw.get("lastName")) if part)
    shaped: dict[str, Any] = {"id": raw.get("id"), "name": name}
    if raw.get("mobile"):
        shaped["mobile"] = raw["mobile"]
    if raw.get("email"):
        shaped["email"] = raw["email"]
    return shaped


def shape_named(raw: dict[str, Any]) -> dict[str, Any]:
    return {"id": raw.get("id"), "name": raw.get("name")}


def validate_paging(page: int, limit: int) -> None:
    if page < 1:
        raise ValueError("'page' must be >= 1")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"'limit' must be between 1 and {MAX_LIMIT}")


def build_page(
    items: list[dict[str, Any]], *, page: int, limit: int, total: int | None
) -> dict[str, Any]:
    """`total` is only known for page 1 (the backend counts on page 1 only) - later pages fall back to a full-page heuristic."""
    has_more = page * limit < total if total is not None else len(items) == limit
    return {"items": items, "page": page, "limit": limit, "total": total, "has_more": has_more}
