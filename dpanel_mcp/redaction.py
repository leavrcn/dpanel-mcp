"""工具返回值中敏感值（密码、token、secret）的脱敏。

对工具返回的任意 dict/list 在序列化给 MCP 客户端前递归执行。
脱敏始终开启（冻结决策 9B）。
"""

from __future__ import annotations

import re
from typing import Any

MASK = "******"

# 始终脱敏的键名（小写、分隔符归一化后匹配）
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "accesstoken", "refreshtoken",
    "apikey", "api_key", "accesskey", "secretkey", "privatekey", "private_key",
    "jwt", "authorization", "cookie", "session", "credential", "credentials",
    "webhooksecret", "clientsecret", "client_secret", "sshkey", "ssh_key",
    "tlskey", "tls_key", "certkey", "passphrase",
}

# 环境变量风格：NAME=VALUE 且 NAME 含敏感特征
_ENV_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIAL|JWT)[A-Z0-9_]*)\s*=\s*([^\s\"']+)"
)

# 自由文本中的长 Bearer 风格字符串（JWT 为 xxx.yyy.zzz 格式）
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")


def _normalize_key(key: str) -> str:
    return re.sub(r"[\s_\-.\[\]]+", "", key.lower())


def _is_sensitive_key(key: str) -> bool:
    norm = _normalize_key(key)
    return any(norm == k or norm.endswith(k) for k in (_normalize_key(s) for s in SENSITIVE_KEYS))


def redact_text(text: str) -> str:
    """对自由文本（如日志）中的 KEY=VALUE 形式赋值与 JWT 做脱敏"""
    text = _ENV_RE.sub(lambda m: f"{m.group(1)}={MASK}", text)
    text = _JWT_RE.sub(MASK, text)
    return text


def redact(obj: Any) -> Any:
    """递归脱敏 JSON 结构"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _is_sensitive_key(k):
                out[k] = MASK
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        # only touch strings that actually look like they contain secrets,
        # to avoid mangling ordinary prose
        if _JWT_RE.search(obj) or _ENV_RE.search(obj):
            return redact_text(obj)
        return obj
    return obj
