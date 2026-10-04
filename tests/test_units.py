"""Unit tests for redaction, profiles, and client logic."""

import base64
import json
import time

import pytest

from dpanel_mcp.config import Config
from dpanel_mcp.profiles import ProfileGate, TOOLS
from dpanel_mcp.redaction import redact, redact_text


# ------------------------------------------------------------------ redaction

def test_redact_dict_keys():
    obj = {"username": "admin", "password": "hunter2", "token": "abc", "nested": {"apiKey": "k"}}
    out = redact(obj)
    assert out["username"] == "admin"
    assert out["password"] == "******"
    assert out["token"] == "******"
    assert out["nested"]["apiKey"] == "******"


def test_redact_env_style():
    text = "MYSQL_PASSWORD=secret123 and MYSQL_USER=root"
    out = redact_text(text)
    assert "secret123" not in out
    assert "MYSQL_USER=root" in out
    assert "MYSQL_PASSWORD=******" in out


def test_redact_jwt_in_text():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    out = redact_text(f"token is {jwt}")
    assert jwt not in out
    assert "******" in out


def test_redact_plain_text_untouched():
    assert redact_text("hello world, nothing secret here") == "hello world, nothing secret here"


def test_redact_list():
    out = redact([{"password": "x"}, {"ok": 1}])
    assert out[0]["password"] == "******"
    assert out[1]["ok"] == 1


# ------------------------------------------------------------------- profiles

def test_profile_ranking():
    ro = ProfileGate(Config(profile="read-only"))
    rw = ProfileGate(Config(profile="read-write"))
    adm = ProfileGate(Config(profile="admin"))

    assert ro.allowed("dpanel_container_list")
    assert not ro.allowed("dpanel_container_status")
    assert not ro.allowed("dpanel_container_delete")

    assert rw.allowed("dpanel_container_status")
    assert not rw.allowed("dpanel_container_delete")

    assert adm.allowed("dpanel_container_delete")
    assert adm.is_destructive("dpanel_container_delete")
    assert not adm.is_destructive("dpanel_container_list")


def test_destructive_needs_confirm():
    adm = ProfileGate(Config(profile="admin"))
    assert adm.is_destructive("dpanel_container_delete")
    assert adm.is_destructive("dpanel_image_prune")
    assert adm.is_destructive("dpanel_compose_destroy")
    assert not adm.is_destructive("dpanel_compose_deploy")


def test_every_tool_has_entry():
    # every tool in TOOLS has a valid (profile, destructive) tuple
    for name, (minimum, destructive) in TOOLS.items():
        assert minimum in ("read-only", "read-write", "admin"), name
        assert isinstance(destructive, bool), name


# --------------------------------------------------------------------- client

def _make_jwt(exp: float) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps({"exp": int(exp)}).encode()).rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.signature"


class TestJwtExp:
    def test_decodes_exp(self):
        token = _make_jwt(time.time() + 3600)
        exp = DPanelJwtExp(token)
        assert abs(exp - (time.time() + 3600)) < 5

    def test_returns_none_on_garbage(self):
        assert DPanelJwtExp("not.a.jwt") is None
        assert DPanelJwtExp("") is None


from dpanel_mcp.client import DPanelClient  # noqa: E402

DPanelJwtExp = DPanelClient._decode_jwt_exp  # noqa: E402


def test_config_defaults_and_validation():
    c = Config()
    assert c.profile == "read-write"
    assert c.transport == "stdio"
    problems = c.validate()
    assert any("DPANEL_USERNAME" in p for p in problems)
    assert any("DPANEL_PASSWORD" in p for p in problems)


def test_api_base():
    c = Config(dpanel_host="http://127.0.0.1:8807/")
    assert c.api_base == "http://127.0.0.1:8807/dpanel/api"


# ------------------------------------------------------- 1.11.0 route contract

# Routes verified against a live DPanel 1.11.0 container (probe evidence in
# /tmp/route_probe.json during development). Every path used by tools.py must
# be in the verified-exists set.
VERIFIED_ROUTES = {
    "/common/home/info", "/common/panel/usage", "/common/home/get-stat-list",
    "/common/setting/get-setting", "/common/log/get-list",
    "/common/env/get-list", "/common/env/get-detail", "/common/env/switch",
    "/common/env/create", "/common/env/delete",
    "/app/container/get-list", "/app/container/get-detail", "/app/container/delete",
    "/app/container/status", "/app/container/update", "/app/container/prune",
    "/app/container/export", "/app/container/commit", "/app/container/copy",
    "/app/container/check-port", "/app/container/get-stat-info", "/app/container/get-process-info",
    "/app/container-upgrade/upgrade", "/app/container-upgrade/check",
    "/app/container-upgrade/get-list", "/app/container-upgrade/ignore",
    "/app/container-backup/create", "/app/container-backup/delete",
    "/app/container-backup/get-detail", "/app/container-backup/get-list",
    "/app/container-backup/restore",
    "/app/compose/create", "/app/compose/get-list", "/app/compose/get-task",
    "/app/compose/get-from-uri", "/app/compose/get-from-git", "/app/compose/download",
    "/app/compose/container-deploy", "/app/compose/container-destroy",
    "/app/compose/container-ctrl", "/app/compose/container-log",
    "/app/image/get-list", "/app/image/get-detail", "/app/image/delete",
    "/app/image/prune", "/app/image/export", "/app/image/tag-add",
    "/app/image/tag-delete", "/app/image/tag-sync", "/app/image/tag-push-batch",
    "/app/image/tag-search", "/app/image/import-by-image-tar",
    "/app/image-build/create", "/app/image-build/build", "/app/image-build/delete",
    "/app/image-build/get-list", "/app/image-build/get-detail", "/app/image-build/prune",
    "/app/network/get-list", "/app/network/get-detail", "/app/network/create",
    "/app/network/delete", "/app/network/prune", "/app/network/connect",
    "/app/network/disconnect", "/app/network/get-container-list",
    "/app/volume/get-list", "/app/volume/get-detail", "/app/volume/create",
    "/app/volume/delete", "/app/volume/prune",
    "/common/explorer/get-path-list", "/common/explorer/get-content",
    "/common/explorer/get-file-stat", "/common/explorer/get-path-size",
    "/common/explorer/delete", "/common/explorer/export", "/common/explorer/import",
    "/common/explorer/unzip", "/common/explorer/mkdir", "/common/explorer/permission",
    "/common/cron/get-list", "/common/cron/get-detail", "/common/cron/create",
    "/common/cron/delete", "/common/cron/run-once", "/common/cron/get-log-list",
    "/common/cron/prune-log", "/common/cron/template",
    "/common/store/get-list", "/common/store/create", "/common/store/delete",
    "/common/store/deploy", "/common/store/sync",
    "/common/registry/get-list", "/common/registry/create", "/common/registry/delete",
    "/common/registry/get-detail",
    "/common/notice/get-list", "/common/notice/unread", "/common/notice/delete",
}


def test_tools_use_only_verified_routes():
    """Extract every _call("path") in tools.py and assert it exists on 1.11.0."""
    import os
    import re

    tools_path = os.path.join(os.path.dirname(__file__), "..", "dpanel_mcp", "tools.py")
    src = open(tools_path).read()
    used = set(re.findall(r'_call\(\s*"([^"]+)"', src))
    assert used, "no routes extracted; regex broken?"
    unknown = used - VERIFIED_ROUTES
    assert not unknown, f"tools.py calls unverified routes: {unknown}"


def test_explorer_mountpoint_validation():
    """_mp() must reject invalid mountPoint formats with a helpful error."""
    from dpanel_mcp.client import DPanelApiError
    from dpanel_mcp.tools import _mp

    for bad in ("local", "/dpanel", "dpanel://x", "volume", "container"):
        with pytest.raises(DPanelApiError):
            _mp(bad)
    assert _mp("volume:mydata") == "volume:mydata"
    assert _mp("container:abc123") == "container:abc123"
    assert _mp("docker:local") == "docker:local"
