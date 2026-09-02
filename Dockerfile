# syntax=docker/dockerfile:1
#
# Container image for deploying mems-mcp on ECS Fargate (behind an ALB) using
# the `streamable-http` transport - see infra/ecs.tf. Also runs unmodified on
# plain EC2/local Docker.
#
# Build:
#   docker build -t mems-mcp .
# Run locally:
#   docker run -p 8080:8080 mems-mcp

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Install dependencies first (cached layer, unaffected by source code changes).
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

# Now install the project itself.
COPY src/ src/
COPY README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

FROM python:3.12-slim-bookworm AS runtime

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY src/ src/

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    MEMS_MCP_HOST=0.0.0.0 \
    MEMS_MCP_PORT=8080

EXPOSE 8080

# NOTE: this runs the ASGI app directly via uvicorn (src/mems_mcp/asgi.py),
# NOT the `mems-mcp` CLI - the CLI's own host/port handling is for the
# `stdio`/local-http dev workflow, not container deployment.
CMD ["uvicorn", "mems_mcp.asgi:app", "--host", "0.0.0.0", "--port", "8080"]
