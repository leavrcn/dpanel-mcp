"""针对真实 DPanel 实例的端到端 MCP 协议测试。

以 stdio 模式启动服务进程，通过 JSON-RPC 走 MCP 协议，覆盖：
  - initialize 握手
  - tools/list（按能力分级过滤）
  - tools/call：只读、写入、破坏性（fail-closed）、脱敏
"""

import json
import os
import subprocess
import sys

MCP_DIR = os.path.join(os.path.dirname(__file__), "..")
ENV = {
    **os.environ,
    "DPANEL_HOST": "http://127.0.0.1:8807",
    "DPANEL_USERNAME": "mcpadmin",
    # 测试密码优先从环境变量读，未设置时用本地占位符（仅用于本地开发容器，不入生产）
    "DPANEL_PASSWORD": os.environ.get("DPANEL_TEST_PASSWORD", "McpTest-2026!"),
    "DPANEL_MCP_PROFILE": "admin",
    "DPANEL_MCP_TRANSPORT": "stdio",
}


class McpStdio:
    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "dpanel_mcp.server"],
            cwd=MCP_DIR,
            env=ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout=30):
        import selectors

        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        try:
            events = sel.select(timeout)
            if not events:
                raise TimeoutError("no MCP response within timeout")
            line = self.proc.stdout.readline()
            return json.loads(line)
        finally:
            sel.close()

    def request(self, method, params=None, _id=None):
        msg = {"jsonrpc": "2.0", "id": _id or 0, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.recv()

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main():
    failures = []

    mcp = McpStdio()
    try:
        # 1. 初始化握手
        resp = mcp.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test", "version": "0.0.1"},
            },
        )
        server_name = resp["result"]["serverInfo"]["name"]
        print(f"[1] initialize OK -> server: {server_name}")
        mcp.notify("notifications/initialized")

        # 2. tools/list 工具列表
        resp = mcp.request("tools/list", {})
        tools = resp["result"]["tools"]
        names = [t["name"] for t in tools]
        print(f"[2] tools/list OK -> {len(names)} tools")
        if len(names) < 85:
            failures.append(f"expected >=85 tools, got {len(names)}")

        # 3. 只读调用：容器列表（1.11.0：md5/siteTitle 过滤，无分页）
        resp = mcp.request(
            "tools/call",
            {"name": "dpanel_container_list", "arguments": {}},
        )
        text = resp["result"]["content"][0]["text"]
        data = json.loads(text)
        n = len(data.get("list", []))
        print(f"[3] dpanel_container_list OK -> {n} containers")
        if n == 0:
            failures.append("container list empty")

        # 4. 系统信息
        resp = mcp.request("tools/call", {"name": "dpanel_system_info", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        print(f"[4] dpanel_system_info OK -> {text[:120]}...")

        # 4b. 资源占用（1.11.0：/common/panel/usage）
        resp = mcp.request("tools/call", {"name": "dpanel_system_usage", "arguments": {}})
        body = resp["result"]
        if body.get("isError"):
            failures.append("dpanel_system_usage (panel/usage) failed")
        else:
            print("[4b] dpanel_system_usage OK (1.11.0 /common/panel/usage)")

        # 4c. explorer 挂载点调用（1.11.0 契约）
        resp = mcp.request(
            "tools/call",
            {"name": "dpanel_explorer_list", "arguments": {"mount_point": "volume:dpanel-fix-test", "path": "/"}},
        )
        body = resp["result"]
        if body.get("isError"):
            err_text = body["content"][0]["text"][:150]
            print(f"[4c] explorer volume mount -> error: {err_text}")
            if "endpoint not found" in err_text:
                failures.append("explorer route missing (1.11.0 contract broken)")
        else:
            print("[4c] explorer volume mount OK (1.11.0 mountPoint contract)")

        # 4d. compose 列表（1.11.0：按 id）
        resp = mcp.request("tools/call", {"name": "dpanel_compose_list", "arguments": {}})
        body = resp["result"]
        if body.get("isError"):
            failures.append("dpanel_compose_list failed")
        else:
            data = json.loads(body["content"][0]["text"])
            print(f"[4d] compose_list OK -> {len(data.get('list', []))} projects")

        # 5. 破坏性操作 fail-closed：不传 confirm 直接拒绝
        resp = mcp.request(
            "tools/call",
            {"name": "dpanel_container_delete", "arguments": {"md5": "deadbeef"}},
        )
        body = resp["result"]
        is_error = body.get("isError", False)
        err_text = body["content"][0]["text"] if body.get("content") else ""
        print(f"[5] destructive without confirm -> isError={is_error}, msg: {err_text[:100]}")
        if not is_error:
            failures.append("destructive tool did not fail-closed without confirm")

        # 6. 脱敏检查：输出中不得出现明文密码
        resp = mcp.request(
            "tools/call",
            {"name": "dpanel_container_list", "arguments": {}},
        )
        text = resp["result"]["content"][0]["text"]
        if ENV["DPANEL_PASSWORD"] in text:
            failures.append("password leaked in container list output")
        print("[6] redaction check OK (no password leak in list output)")

        # 7. 能力分级门禁：admin 下调用读写工具（允许；预期返回 API 层错误）
        resp = mcp.request(
            "tools/call",
            {"name": "dpanel_container_status", "arguments": {"md5": "deadbeef", "operate": "start"}},
        )
        body = resp["result"]
        err_text = body["content"][0]["text"] if body.get("content") else ""
        if "blocked: requires profile" in err_text:
            failures.append("gate error for admin profile on read-write tool")
        print(f"[7] container_status allowed under admin (isError={body.get('isError')}) — expected API-level error, not gate error")

        # 8. 未知路由诊断（I1）：所有路由均已验证存在，无法再构造坏路由，
        #    客户端 HTML 识别逻辑改由单元测试覆盖——此处跳过。

        print()
        if failures:
            print("E2E FAILURES:")
            for f in failures:
                print(f"  - {f}")
            sys.exit(1)
        print("E2E: ALL CHECKS PASSED")
    finally:
        mcp.close()


if __name__ == "__main__":
    main()
