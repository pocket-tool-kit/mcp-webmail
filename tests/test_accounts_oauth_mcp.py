"""v0.3: OAuth2, provider presets, settings, remote hosts and MCP permission levels."""
import json
import shutil
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app import oauth as oauth_module
from app.account_settings import AccountInput, ConfigurationManager, GeneralInput, UnlockInput
from app.config import Settings
from app.imap_sync import SyncService
from app.main import create_app
from app.mcp_server import make_mcp
from app.oauth import AuthorizationFlows, OAuthError, TokenCache
from app.providers import OAUTH_PROVIDERS, PRESETS
from tests.conftest import REAL_OPEN_IMAP, WEB, make_mail
from tests.fakes import smtp_server

MASTER = "test master password 2026!"
BASE = {"list_accounts", "search_emails", "get_email_detail", "get_thread", "create_draft"}
ORGANIZE = BASE | {"mark_emails", "move_emails", "archive_emails"}
FULL = ORGANIZE | {"delete_emails", "send_draft"}


def oauth_account(**changes):
    value = {"id": "ms", "name": "Microsoft", "email": "me@contoso.example", "protocol": "imap", "provider": "microsoft365",
             "auth": "oauth2", "folders": ["*"], "save_sent": False,
             "oauth": {"provider": "microsoft", "client_id": "client-123", "tenant": "common", "client_secret": ""},
             "imap": {"host": "outlook.office365.com", "port": 993, "username": "me@contoso.example", "security": "tls", "password": ""},
             "smtp": {"host": "smtp.office365.com", "port": 587, "username": "me@contoso.example", "security": "starttls", "password": ""}}
    value.update(changes)
    return AccountInput.model_validate(value)


@pytest.fixture
def manager(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"web_token": "w" * 40, "mcp_token": "m" * 40, "accounts": []}), encoding="utf-8")
    value = ConfigurationManager(path)
    value.unlock(UnlockInput(master_password=MASTER, confirmation=MASTER))
    return value


@pytest.fixture
def token_endpoint(monkeypatch):
    """Stands in for the provider's token endpoint; records every request."""
    calls, replies = [], []

    def post_form(url, fields):
        calls.append((url, dict(fields)))
        return replies.pop(0) if replies else {"access_token": f"access-{len(calls)}", "expires_in": 3600}
    monkeypatch.setattr(oauth_module, "post_form", post_form)
    monkeypatch.setattr(oauth_module, "TOKENS", TokenCache())
    monkeypatch.setattr("app.imap_sync.TOKENS", oauth_module.TOKENS)
    monkeypatch.setattr("app.smtp_client.TOKENS", oauth_module.TOKENS)
    return calls, replies


# --- presets -------------------------------------------------------------------
def test_presets_cover_requested_providers_and_validate():
    by_id = {p["id"]: p for p in PRESETS}
    assert {"gmail", "icloud", "microsoft365", "outlook", "generic", "pop3"} <= set(by_id)
    assert by_id["gmail"]["oauth"] == "google" and by_id["icloud"]["oauth"] is None
    assert by_id["microsoft365"]["oauth"] == "microsoft" and by_id["pop3"]["protocol"] == "pop3"
    for preset in PRESETS:
        assert preset["oauth"] in (None, *OAUTH_PROVIDERS)
        for kind in ("imap", "smtp"):
            assert preset[kind]["security"] in ("tls", "starttls") and 1 <= preset[kind]["port"] <= 65535
    for provider in OAUTH_PROVIDERS.values():
        assert provider["authorize"].startswith("https://") and provider["token"].startswith("https://")


# --- configuration ---------------------------------------------------------------
def test_v0_2_encrypted_config_still_unlocks(tmp_path):
    path = tmp_path / "config.json"
    shutil.copyfile(Path(__file__).parent / "data" / "config_v0_2_encrypted.json", path)
    manager = ConfigurationManager(path)
    assert manager.public_state()["mcp_permissions"] == "read_draft"  # new settings default safely
    manager.unlock(UnlockInput(master_password="legacy master password"))
    account = manager.settings.accounts[0]
    assert account.imap.password.get_secret_value() == "legacy-imap-secret"
    assert account.smtp.password.get_secret_value() == "legacy-smtp-secret"
    assert (account.protocol, account.auth, account.folders) == ("imap", "password", ["INBOX", "Sent"])
    manager.save_general(GeneralInput(mcp_permissions="organize"))
    again = ConfigurationManager(path)
    again.unlock(UnlockInput(master_password="legacy master password"))
    assert again.settings.accounts[0].imap.password.get_secret_value() == "legacy-imap-secret"
    assert again.settings.mcp_permissions == "organize"


def test_first_run_choice_general_settings_and_delete(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"web_token": "w" * 40, "mcp_token": "m" * 40, "accounts": []}), encoding="utf-8")
    manager = ConfigurationManager(path)
    with pytest.raises(ValueError, match="ロック"):
        manager.save_general(GeneralInput(mcp_permissions="full"))
    state = manager.unlock(UnlockInput(master_password=MASTER, confirmation=MASTER, mcp_permissions="full"))
    assert state["mcp_permissions"] == "full" and json.loads(path.read_text())["mcp_permissions"] == "full"
    # Unlocking later can never widen the permission.
    other = ConfigurationManager(path)
    other.unlock(UnlockInput(master_password=MASTER, mcp_permissions="read_draft"))
    assert other.settings.mcp_permissions == "full"
    other.save_general(GeneralInput(mcp_permissions="read_draft", mark_read_on_open=False, allowed_hosts=[" PC.Tail.ts.net "]))
    assert (other.settings.mcp_permissions, other.settings.mark_read_on_open, other.settings.allowed_hosts) == ("read_draft", False, ["pc.tail.ts.net"])
    for bad in (["*.example.com"], ["host:8000"], ["a b"], ["https://x.example"]):
        with pytest.raises(ValueError, match="ホスト名"):
            other.save_general(GeneralInput(mcp_permissions="read_draft", allowed_hosts=bad))
    other.save_account(oauth_account())
    assert len(other.delete_account("ms")["accounts"]) == 0
    with pytest.raises(ValueError):
        other.delete_account("ms")


def test_oauth_secrets_encrypted_kept_and_reset(manager):
    state = manager.save_account(oauth_account(oauth={"provider": "google", "client_id": "cid", "client_secret": "google-client-secret"}))
    assert state["accounts"][0]["oauth"] == {"provider": "google", "client_id": "cid", "tenant": "common",
                                             "has_client_secret": True, "signed_in": False}
    assert not manager.settings.accounts[0].credentials_ready
    manager.set_oauth_refresh_token("ms", "refresh-token-value")
    raw = manager.path.read_text()
    assert "refresh-token-value" not in raw and "google-client-secret" not in raw
    assert "refresh-token-value" not in json.dumps(manager.public_state())
    assert manager.settings.accounts[0].credentials_ready
    # Editing unrelated fields keeps the sign-in and the stored client secret.
    manager.save_account(oauth_account(name="Renamed", oauth={"provider": "google", "client_id": "cid", "client_secret": ""}))
    oauth = manager.settings.accounts[0].oauth
    assert oauth.refresh_token.get_secret_value() == "refresh-token-value" and oauth.client_secret.get_secret_value() == "google-client-secret"
    # A restart decrypts both again.
    other = ConfigurationManager(manager.path)
    other.unlock(UnlockInput(master_password=MASTER))
    assert other.settings.accounts[0].oauth.refresh_token.get_secret_value() == "refresh-token-value"
    # A different client registration or mailbox user must sign in again.
    manager.save_account(oauth_account(oauth={"provider": "google", "client_id": "other", "client_secret": ""}))
    oauth = manager.settings.accounts[0].oauth
    assert oauth.refresh_token.get_secret_value() == "" and oauth.client_secret.get_secret_value() == ""
    # Moving ciphertext to another client id is detected.
    manager.set_oauth_refresh_token("ms", "second")
    data = json.loads(manager.path.read_text())
    data["accounts"][0]["oauth"]["client_id"] = "attacker"
    manager.path.write_text(json.dumps(data))
    tampered = ConfigurationManager(manager.path)
    with pytest.raises(ValueError, match="暗号化データ"):
        tampered.unlock(UnlockInput(master_password=MASTER))


def test_account_rules(manager):
    with pytest.raises(ValueError):
        manager.save_account(oauth_account(protocol="pop3"))  # OAuth2 is IMAP only
    with pytest.raises(ValueError, match="パスワードを入力"):
        manager.save_account(oauth_account(auth="password", oauth=None))
    with pytest.raises(Exception):
        Settings.model_validate({"web_token": "w" * 40, "mcp_token": "m" * 40, "allowed_hosts": ["*"]})


# --- OAuth flow --------------------------------------------------------------------
def test_authorization_url_exchange_and_single_use_state(manager, token_endpoint):
    calls, replies = token_endpoint
    manager.save_account(oauth_account())
    account = manager.settings.accounts[0]
    flows = AuthorizationFlows()
    url = flows.start(account, "http://localhost:8000/oauth/callback")
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    assert parsed.netloc == "login.microsoftonline.com" and parsed.path == "/common/oauth2/v2.0/authorize"
    assert query["client_id"] == "client-123" and query["redirect_uri"] == "http://localhost:8000/oauth/callback"
    assert query["code_challenge_method"] == "S256" and "IMAP.AccessAsUser.All" in query["scope"] and "offline_access" in query["scope"]
    replies.append({"access_token": "first-access", "refresh_token": "first-refresh", "expires_in": 3600})
    assert flows.finish(query["state"], "auth-code", manager.settings.find_account) == ("ms", "first-refresh")
    sent = calls[0][1]
    assert sent["grant_type"] == "authorization_code" and sent["code"] == "auth-code" and len(sent["code_verifier"]) >= 43
    assert "client_secret" not in sent  # public client
    with pytest.raises(OAuthError):
        flows.finish(query["state"], "auth-code", manager.settings.find_account)  # replay
    with pytest.raises(OAuthError):
        flows.finish("guessed-state", "auth-code", manager.settings.find_account)
    # Provider errors surface as a short code, never as server text.
    replies.append({"error": "invalid_client", "error_description": "secret detail <script>"})
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(flows.start(account, "http://localhost:8000/oauth/callback")).query))["state"]
    with pytest.raises(OAuthError, match="invalid_client") as caught:
        flows.finish(state, "x", manager.settings.find_account)
    assert "secret detail" not in str(caught.value)
    google = flows.start(manager.settings.accounts[0].model_copy(update={"oauth": account.oauth.model_copy(update={"provider": "google"})}), "http://localhost:8000/oauth/callback")
    assert google.startswith("https://accounts.google.com/") and "access_type=offline" in google and "mail.google.com" in google


def test_token_refresh_cache_and_rotation(manager, token_endpoint):
    calls, replies = token_endpoint
    manager.save_account(oauth_account())
    with pytest.raises(OAuthError, match="サインイン"):
        oauth_module.TOKENS.access_token(manager.settings.accounts[0])
    manager.set_oauth_refresh_token("ms", "refresh-1")
    oauth_module.TOKENS.on_rotate = manager.set_oauth_refresh_token
    replies.append({"access_token": "access-A", "expires_in": 3600, "refresh_token": "refresh-2"})
    assert oauth_module.TOKENS.access_token(manager.settings.accounts[0]) == "access-A"
    assert calls[0][1]["refresh_token"] == "refresh-1" and calls[0][1]["grant_type"] == "refresh_token"
    # The rotated token is persisted (encrypted) and the access token is reused.
    assert manager.settings.accounts[0].oauth.refresh_token.get_secret_value() == "refresh-2"
    assert "refresh-2" not in manager.path.read_text()
    assert oauth_module.TOKENS.access_token(manager.settings.accounts[0]) == "access-A" and len(calls) == 1
    replies.append({"access_token": "short", "expires_in": 30})
    oauth_module.TOKENS.clear()
    assert oauth_module.TOKENS.access_token(manager.settings.accounts[0]) == "short"
    assert oauth_module.TOKENS.access_token(manager.settings.accounts[0]) == "access-3"  # nearly expired -> refreshed
    replies.append({"error": "invalid_grant"})
    oauth_module.TOKENS.clear()
    with pytest.raises(OAuthError, match="再サインイン"):
        oauth_module.TOKENS.access_token(manager.settings.accounts[0])


def test_smtp_uses_xoauth2_on_the_wire(manager, token_endpoint, tls):
    from app.smtp_client import smtp_send
    manager.save_account(oauth_account())
    manager.set_oauth_refresh_token("ms", "refresh-1")
    account = manager.settings.accounts[0]
    server = smtp_server(*tls)
    account.smtp.host, account.smtp.port, account.smtp.security = "localhost", server.start(), "tls"
    try:
        raw = make_mail("OAuth", sender="me@contoso.example", to="a@example.com")
        assert smtp_send(account, raw)["state"] == "accepted"
    finally:
        server.shutdown()
        server.server_close()
    assert server.auth == [("XOAUTH2", "user=me@contoso.example\x01auth=Bearer access-1\x01\x01")]


def test_open_imap_oauth_login(manager, token_endpoint, monkeypatch):
    import app.imap_sync as imap_sync
    manager.save_account(oauth_account())
    manager.set_oauth_refresh_token("ms", "refresh-1")
    client = MagicMock()
    monkeypatch.setattr(imap_sync, "IMAPClient", lambda *a, **k: client)
    # The autouse network guard replaced open_imap; call the real one against a mocked IMAPClient.
    assert REAL_OPEN_IMAP(manager.settings.accounts[0]) is client
    client.oauth2_login.assert_called_once_with("me@contoso.example", "access-1")
    client.login.assert_not_called()


def test_oauth_endpoints_and_callback(manager, token_endpoint, db):
    calls, replies = token_endpoint
    manager.save_account(oauth_account())
    app = create_app(enable_sync=False, configuration=manager, database=db)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.post("/api/oauth/start", json={"account_id": "ms"}).status_code == 401
        assert client.post("/api/oauth/start", headers=WEB, json={"account_id": "nope"}).status_code == 400
        started = client.post("/api/oauth/start", headers=WEB, json={"account_id": "ms"}).json()
        assert started["redirect_uri"] == "http://localhost:8000/oauth/callback"
        state = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(started["url"]).query))["state"]
        # The callback is unauthenticated: only the single-use state admits it.
        bad = client.get("/oauth/callback", params={"state": "<script>alert(1)</script>", "code": "c"})
        assert bad.status_code == 400 and "<script>" not in bad.text
        assert client.get("/oauth/callback").status_code == 400
        replies.append({"access_token": "a", "refresh_token": "stored-refresh", "expires_in": 3600})
        done = client.get("/oauth/callback", params={"state": state, "code": "the-code"})
        assert done.status_code == 200 and "完了" in done.text and "stored-refresh" not in done.text
        settings = client.get("/api/settings", headers=WEB)
        assert settings.json()["accounts"][0]["oauth"]["signed_in"] and "stored-refresh" not in settings.text
        assert client.get("/oauth/callback", params={"state": state, "code": "the-code"}).status_code == 400
        assert [p["id"] for p in client.get("/api/providers", headers=WEB).json()][:2] == ["gmail", "icloud"]
        assert client.get("/api/providers").status_code == 401
    assert manager.settings.accounts[0].oauth.refresh_token.get_secret_value() == "stored-refresh"


async def test_oauth_account_without_sign_in_reports_clearly(manager, db):
    manager.save_account(oauth_account())
    sync = SyncService(manager.settings, db)
    await sync.sync_account(manager.settings.accounts[0])
    assert sync.status["ms"]["locked"] and "サインイン" in sync.status["ms"]["error"]
    with pytest.raises(ValueError, match="OAuth"):
        manager.settings.account("ms")


# --- remote access ---------------------------------------------------------------------
def test_allowed_hosts_and_proxy_https_origin(manager, db):
    app = create_app(enable_sync=False, configuration=manager, database=db)
    remote = {"Host": "pc.tail1234.ts.net"}
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.get("/", headers=remote).status_code == 400  # not allowed yet
        assert client.get("/app.css").status_code == 200
        assert client.put("/api/settings/general", headers=WEB, json={"mcp_permissions": "read_draft", "allowed_hosts": ["pc.tail1234.ts.net"]}).status_code == 200
        assert client.get("/", headers=remote).status_code == 200  # live, no restart
        assert client.get("/api/accounts", headers=remote).status_code == 401
        assert client.get("/api/accounts", headers=WEB | remote).status_code == 200
        # The tunnel terminates TLS: the browser's Origin is https while the app sees http.
        assert client.post("/api/sync", headers=WEB | remote | {"Origin": "https://pc.tail1234.ts.net"}).status_code == 200
        assert client.post("/api/sync", headers=WEB | remote | {"Origin": "https://evil.example"}).status_code == 403
        assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
        assert client.get("/", headers={"Host": "pc.tail1234.ts.net.evil.example"}).status_code == 400
        # MCP is never reachable through a remote name, even with the right token.
        mcp = {"Authorization": "Bearer " + "m" * 40, "Accept": "application/json, text/event-stream"}
        ping = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        assert client.post("/mcp", headers=mcp | remote, json=ping).status_code == 403
        assert client.post("/mcp", headers=mcp, json=ping).status_code == 200
        # OAuth sign-in must happen on the host machine (loopback redirect).
        manager.save_account(oauth_account())
        response = client.post("/api/oauth/start", headers=WEB | remote, json={"account_id": "ms"})
        assert response.status_code == 400 and "localhost" in response.json()["detail"]


# --- MCP permission levels ------------------------------------------------------------------
@pytest.mark.parametrize("level,expected", [("read_draft", BASE), ("organize", ORGANIZE), ("full", FULL)])
async def test_mcp_tools_per_level(account_settings, db, level, expected):
    account_settings.mcp_permissions = level
    server = make_mcp(account_settings, db)
    assert {t.name for t in await server.list_tools()} == expected


async def test_mcp_organize_and_full_tools_act_on_the_mailbox(account_settings, db, imap, monkeypatch):
    account_settings.mcp_permissions = "full"
    await SyncService(account_settings, db).sync_account(account_settings.accounts[0])
    server = make_mcp(account_settings, db)
    rows = {r["subject"]: r["id"] for r in await db.search()}

    async def call(name, **arguments):
        result = await server.call_tool(name, arguments)
        # FastMCP returns (content, structured) or only content blocks depending on the tool.
        return result[1] if isinstance(result, tuple) else json.loads(result[0].text)
    await call("mark_emails", email_ids=[rows["First"]], seen=False, flagged=True)
    assert imap.flags("INBOX", 1) == {b"\\Flagged"}
    await call("move_emails", email_ids=[rows["First"]], folder="Projects")
    assert imap.uids("Projects") == [1]
    await call("archive_emails", email_ids=[rows["Starred"]])
    await call("delete_emails", email_ids=[rows["With file"]])
    assert imap.uids("INBOX") == [] and imap.uids("[Gmail]/ゴミ箱") == [1]

    smtp = MagicMock()
    smtp.sendmail.return_value = {}
    monkeypatch.setattr("app.smtp_client.smtplib.SMTP_SSL", lambda *a, **k: smtp)
    await call("create_draft", account_id="work", to=["a@example.com"], cc=["c@example.com"], subject="From AI", body="text")
    await SyncService(account_settings, db).sync_account(account_settings.accounts[0])
    draft = next(r["id"] for r in await db.search(folder="[Gmail]/下書き"))
    sent = await call("send_draft", email_id=draft)
    assert sent["state"] == "accepted" and sorted(smtp.sendmail.call_args.args[1]) == ["a@example.com", "c@example.com"]
    with pytest.raises(Exception):
        await call("send_draft", email_id=rows["Starred"])  # not a draft
    assert smtp.sendmail.call_count == 1

    # Lowering the level in the Web UI blocks already-registered tools immediately.
    account_settings.mcp_permissions = "read_draft"
    for name, arguments in (("delete_emails", {"email_ids": [draft]}), ("send_draft", {"email_id": draft}),
                            ("mark_emails", {"email_ids": [draft], "seen": True})):
        with pytest.raises(Exception, match="permission"):
            await call(name, **arguments)


def test_mcp_token_cannot_change_settings_or_use_web_actions(manager, db):
    app = create_app(enable_sync=False, configuration=manager, database=db)
    mcp = {"Authorization": "Bearer " + "m" * 40}
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.put("/api/settings/general", headers=mcp, json={"mcp_permissions": "full"}).status_code == 401
        for path in ("/api/emails/delete", "/api/emails/flags", "/api/emails/move", "/api/emails/archive", "/api/send"):
            assert client.post(path, headers=mcp, json={"ids": [1]}).status_code == 401
        assert client.delete("/api/settings/accounts/x", headers=mcp).status_code == 401
    assert manager.settings.mcp_permissions == "read_draft"
