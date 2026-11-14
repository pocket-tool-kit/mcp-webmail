import json
import os
import shutil
import sys

from fastapi.testclient import TestClient
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from app.config import ROOT
from app.main import create_app


def test_http_auth_origin_mcp_and_ui(settings, db):
    app = create_app(settings, db, enable_sync=False)
    web = {"Authorization": "Bearer " + settings.web_token.get_secret_value()}
    mcp = {"Authorization": "Bearer " + settings.mcp_token.get_secret_value(), "Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.get("/").status_code == 200
        assert client.get("/app.js").status_code == 200
        assert client.get("/data/config.json").status_code == 404
        assert client.get("/api/accounts").status_code == 401
        assert client.get("/api/accounts", headers=mcp).status_code == 401
        assert client.get("/api/accounts", headers=web).status_code == 200
        assert client.post("/api/sync", headers=web | {"Origin": "http://evil.example"}).status_code == 403
        assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
        assert client.post("/api/drafts/1/send", headers=mcp).status_code == 401
        assert client.post("/api/drafts/1/send", headers=web).status_code == 400
        assert client.post("/api/sync", headers=web, content=b"a" * 2_000_001).status_code == 413
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}
        assert client.post("/mcp", headers=web, json=init).status_code == 401
        response = client.post("/mcp", headers=mcp, json=init)
        assert response.status_code == 200, response.text
        assert "serverInfo" in response.json()["result"]
        response = client.post("/mcp", headers=mcp, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assert len(response.json()["result"]["tools"]) == 5
        response = client.post("/mcp", headers=mcp, json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_accounts", "arguments": {}}})
        assert not response.json()["result"].get("isError", False)


async def test_real_stdio_subprocess(tmp_path, settings):
    # A portable copy exercises module-relative paths from a different cwd.
    shutil.copytree(ROOT / "app", tmp_path / "app", ignore=shutil.ignore_patterns("__pycache__"))
    data = tmp_path / "data"
    data.mkdir()
    config = settings.model_dump(mode="json")
    config["web_token"] = "w" * 40
    config["mcp_token"] = "m" * 40
    for account in config["accounts"]:
        account["enabled"] = False
        account["imap"]["password"] = account["smtp"]["password"] = "not-used"
    (data / "config.json").write_text(json.dumps(config), encoding="utf-8")
    params = StdioServerParameters(command=sys.executable, args=["-m", "app.mcp_server"], cwd=str(tmp_path), env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert len(tools.tools) == 5
            result = await session.call_tool("list_accounts", {})
            assert not result.isError
            result = await session.call_tool("send_email", {})
            assert result.isError
