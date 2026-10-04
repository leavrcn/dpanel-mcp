# syntax=docker/dockerfile:1
# dpanel-mcp 服务镜像
# 在仓库根目录构建：
#   docker build -t dpanel-mcp:latest .
#
# 服务仅通过 HTTP 与 DPanel 通信（无需挂载 docker.sock）。

FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app
# 先拷贝依赖清单，让这一层在源码变更时仍能被缓存
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# 再拷贝项目本体
COPY README.md ./README.md
COPY dpanel_mcp/ ./dpanel_mcp/
RUN uv sync --frozen --no-dev


FROM python:3.12-slim

# 容器友好默认值，可用 -e 或 compose 覆盖。
# DPANEL_HOST / DPANEL_USERNAME / DPANEL_PASSWORD 故意不设默认值——
# 必须由使用者指向自己的 DPanel 容器与账号。
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

# 存活探针：HTTP 模式下做 TCP 连接检查；stdio 模式直接通过
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,socket; exit(0) if os.environ.get('DPANEL_MCP_TRANSPORT') != 'streamable-http' else socket.create_connection(('127.0.0.1', int(os.environ.get('DPANEL_MCP_HTTP_PORT', '8090'))), timeout=3).close()"

ENTRYPOINT ["/app/.venv/bin/dpanel-mcp"]
