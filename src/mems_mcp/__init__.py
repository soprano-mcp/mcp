"""mems-mcp - Soprano Connect API MCP server.

Deliberately does NOT eagerly import `mems_mcp.server` here: that module has
process-wide import-time side effects (`truststore.inject_into_ssl()`,
building the `FastMCP` app, parsing `MCP_CLIENT_AUTH_MODE` env vars), which
should only happen when the server is actually being run/imported directly -
not merely because some other submodule was imported. The `mems-mcp` console
script points directly at `mems_mcp.server:main` (see pyproject.toml
`[project.scripts]`), so no re-export is needed here.
"""

