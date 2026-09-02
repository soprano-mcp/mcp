"""Standalone ASGI entrypoint for deployment (Docker/ECS Fargate + uvicorn).

The `mems-mcp` CLI (`server.py:main()`) builds/runs its own app internally via
`mcp.run(transport=...)`, which is the right entrypoint for local `stdio`,
`streamable-http`, or `sse` usage (one at a time). Container deployments
instead need a plain ASGI callable that `uvicorn` can import by reference
(e.g. `uvicorn mems_mcp.asgi:app`), and expose BOTH HTTP-based transports
simultaneously on the same host/port, since some MCP clients still require
the legacy SSE transport instead of Streamable HTTP.

Only relevant for the streamable-http/sse transports - `stdio` has no meaning
in a container (there's no local subprocess launcher), so this module is not
used by that path at all.
"""

from __future__ import annotations

from starlette.applications import Starlette

from mems_mcp.server import mcp

# streamable_http_app() must be called first - it lazily creates
# mcp.session_manager, which the combined app's lifespan below depends on.
_streamable_http_app = mcp.streamable_http_app()
_sse_app = mcp.sse_app()

# Combines routes from both transports into one app: `/mcp` (Streamable HTTP,
# the default/recommended transport) and `/sse` + `/messages` (legacy SSE,
# for clients that don't support Streamable HTTP yet) - plus our own
# `/healthz` custom route, present in both apps' route lists already
# (harmless duplication, Starlette matches the first).
# Only the Streamable HTTP session manager needs an explicit lifespan - SSE
# connections run per-request via `sse.connect_sse()`, no background task.
app = Starlette(
    debug=_streamable_http_app.debug,
    routes=_streamable_http_app.routes + _sse_app.routes,
    middleware=_streamable_http_app.user_middleware,
    lifespan=lambda _: mcp.session_manager.run(),
)

