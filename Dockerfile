# syntax=docker/dockerfile:1
# DPanel MCP Server image.
# Build context is this mcp/ directory:
#   docker build -t dpanel-mcp:latest mcp/
#
# The server talks to DPanel over HTTP only (no docker.sock needed).

FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Dependencies first so this layer is cached independently of source changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Then the project itself.
COPY README.md ./README.md
COPY dpanel_mcp/ ./dpanel_mcp/
RUN uv sync --frozen --no-dev


FROM python:3.12-slim

# Container-friendly defaults; override any of these with -e / compose.
# DPANEL_HOST / DPANEL_USERNAME / DPANEL_PASSWORD are intentionally NOT
# defaulted here — they must point at the DPanel container and its account.
ENV DPANEL_MCP_TRANSPORT=streamable-http \
    DPANEL_MCP_HTTP_HOST=0.0.0.0 \
    DPANEL_MCP_HTTP_PORT=8090 \
    DPANEL_MCP_HTTP_PATH=/mcp \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=builder /app /app

RUN useradd --system --uid 10001 --create-home mcp \
    && chown -R mcp:mcp /app
USER mcp

EXPOSE 8090

# Liveness only: TCP connect when serving HTTP; stdio mode passes trivially.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,socket; exit(0) if os.environ.get('DPANEL_MCP_TRANSPORT') != 'streamable-http' else socket.create_connection(('127.0.0.1', int(os.environ.get('DPANEL_MCP_HTTP_PORT', '8090'))), timeout=3).close()"

ENTRYPOINT ["/app/.venv/bin/dpanel-mcp"]
