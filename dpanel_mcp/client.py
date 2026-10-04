"""异步 DPanel HTTP 客户端，支持 JWT 登录与透明 token 续期"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .config import Config


class DPanelApiError(Exception):
    """DPanel 返回错误信封或非 2xx 状态时抛出"""

    def __init__(self, message: str, status_code: int | None = None, payload: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class DPanelClient:
    """DPanel 面板 API（/dpanel/api）的轻量异步客户端。

    鉴权模型（对照 Go 源码验证）：
      - POST /dpanel/api/common/user/login  {username, password, autoLogin}
        -> {code: 0, data: {token: <JWT>}}（HS256；24 小时，autoLogin 时 30 天）
      - 其余端点均要求请求头 Authorization: Bearer <token>
      - 所有业务端点均为 POST + JSON body（包括查询类）。
    """

    def __init__(self, config: Config):
        self.config = config
        self._http = httpx.AsyncClient(
            base_url=config.api_base,
            timeout=config.request_timeout,
            verify=config.dpanel_tls_verify,
            headers={"Content-Type": "application/json"},
        )
        self._token: str | None = None
        self._token_exp: float = 0.0
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ auth

    async def login(self) -> str:
        """登录并缓存 JWT，并发安全"""
        async with self._lock:
            resp = await self._http.post(
                "/common/user/login",
                json={
                    "username": self.config.dpanel_username,
                    "password": self.config.dpanel_password,
                    "autoLogin": self.config.dpanel_auto_login,
                },
            )
            data = self._unwrap(resp, expect_auth=False)
            token = (data or {}).get("token") or (data or {}).get("accessToken")
            if not token:
                raise DPanelApiError(f"login succeeded but no token in response: {data!r}")
            self._token = token
            # JWT 有效期：24 小时，autoLogin 时 30 天。优先解析 exp 字段，
            # 解析失败时按文档有效期减去刷新偏移量估算。
            self._token_exp = self._decode_jwt_exp(token) or (
                time.time()
                + (86400 * 30 if self.config.dpanel_auto_login else 86400)
                - self.config.token_refresh_skew
            )
            return token

    @staticmethod
    def _decode_jwt_exp(token: str) -> float | None:
        import base64
        import json

        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = payload.get("exp")
            return float(exp) if exp else None
        except Exception:
            return None

    async def _ensure_token(self) -> str:
        if self._token is None or time.time() >= self._token_exp:
            return await self.login()
        return self._token

    # -------------------------------------------------------------- requests

    @staticmethod
    def _unwrap(resp: httpx.Response, expect_auth: bool = True) -> Any:
        if resp.status_code == 401 and expect_auth:
            raise DPanelApiError("unauthorized (token expired or invalid)", 401)
        # DPanel 对未知的 /dpanel/api 路由返回 SPA 页面（HTML，HTTP 200）。
        # 识别这种情况并给出可操作的错误信息，而不是透传原始 HTML。
        content_type = resp.headers.get("content-type", "")
        if "text/html" in content_type or resp.text.lstrip().startswith("<!DOCTYPE"):
            req_path = ""
            try:
                req_path = str(resp.request.url.path)
            except Exception:
                pass
            raise DPanelApiError(
                f"endpoint not found on DPanel: {req_path or '(unknown path)'} "
                f"(got SPA HTML). The DPanel version may not match this MCP server "
                f"(built for DPanel 1.11.x). Check DPANEL_HOST and the DPanel version.",
                resp.status_code,
            )
        try:
            body = resp.json()
        except Exception:
            raise DPanelApiError(
                f"non-JSON response (HTTP {resp.status_code}): {resp.text[:200]}",
                resp.status_code,
            )
        # DPanel 信封格式：成功 {code: 200, data: ...}；失败 {code: N, error: ...}。
        code = body.get("code", 0)
        if code not in (0, 200):
            raise DPanelApiError(
                body.get("error") or body.get("message") or f"dpanel error code={code}",
                resp.status_code,
                body,
            )
        return body.get("data")

    async def post(self, path: str, payload: dict | None = None, _retry: bool = True) -> Any:
        """POST 请求面板 API 端点（路径相对于 /dpanel/api）"""
        token = await self._ensure_token()
        resp = await self._http.post(
            path,
            json=payload or {},
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 401 and _retry:
            # token 提前失效（如服务端重启、secret 轮换）-> 透明重登一次
            self._token = None
            token = await self.login()
            resp = await self._http.post(
                path,
                json=payload or {},
                headers={"Authorization": f"Bearer {token}"},
            )
        return self._unwrap(resp)

    async def close(self) -> None:
        await self._http.aclose()
