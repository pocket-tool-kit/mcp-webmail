import json
import shutil
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.account_settings import AccountInput, ConfigurationManager, UnlockInput
from app.main import create_app
from app.mcp_server import make_mcp

MASTER = "test master password 2026!"


@pytest.fixture
def manager(tmp_path, settings):
    data = settings.model_dump(mode="json")
    data["web_token"] = "w" * 40
    data["mcp_token"] = "m" * 40
    for account in data["accounts"]:
        account["imap"]["password"] = "private-imap-value"
        account["smtp"]["password"] = "private-smtp-value"
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return ConfigurationManager(path)


def unlock(manager):
    return manager.unlock(UnlockInput(master_password=MASTER, confirmation=MASTER))


def edit_input(manager, **changes):
    value = manager.public_state()["accounts"][0]
    for kind in ("imap", "smtp"):
        value[kind].pop("has_password")
        value[kind]["password"] = ""
    value.update(changes)
    return AccountInput.model_validate(value)


def test_migration_encryption_restart_wrong_password_and_portability(manager, tmp_path):
    assert manager.public_state()["locked"]
    assert manager.settings.accounts[0].imap.password.get_secret_value() == ""
    unlock(manager)
    raw = manager.path.read_text(encoding="utf-8")
    for secret in (MASTER, "private-imap-value", "private-smtp-value"):
        assert secret not in raw
        assert secret not in json.dumps(manager.public_state())
    data = json.loads(raw)
    assert "password" not in data["accounts"][0]["imap"]
    assert data["web_token"] == "w" * 40
    assert manager.settings.accounts[0].imap.password.get_secret_value() == "private-imap-value"
    moved = tmp_path / "copied" / "config.json"
    moved.parent.mkdir()
    shutil.copyfile(manager.path, moved)
    other = ConfigurationManager(moved)
    with pytest.raises(ValueError, match="マスターパスワードが違う"):
        other.unlock(UnlockInput(master_password="incorrect master"))
    assert other.settings.accounts[0].imap.password.get_secret_value() == ""
    unlock(other)
    assert other.settings.accounts[0].smtp.password.get_secret_value() == "private-smtp-value"


def test_edit_preserves_password_and_shared_settings_object(manager):
    unlock(manager)
    reference = manager.settings
    first = json.loads(manager.path.read_text())["accounts"][0]["imap"]["encrypted_password"]
    manager.save_account(edit_input(manager, name="Renamed"))
    assert reference is manager.settings and reference.accounts[0].name == "Renamed"
    assert reference.accounts[0].imap.password.get_secret_value() == "private-imap-value"
    second = json.loads(manager.path.read_text())["accounts"][0]["imap"]["encrypted_password"]
    assert second != first  # random fresh nonce for every encryption
    data = edit_input(manager)
    data.smtp.password = "new-smtp-secret"  # Pydantic assignment is not validated; use model validation below.
    data = AccountInput.model_validate(data.model_dump())
    manager.save_account(data)
    assert reference.accounts[0].smtp.password.get_secret_value() == "new-smtp-secret"


def test_new_account_and_locked_writes(manager):
    with pytest.raises(ValueError, match="ロック"):
        manager.save_account(edit_input(manager))
    unlock(manager)
    data = edit_input(manager, id="new", name="New")
    with pytest.raises(ValueError, match="パスワードを入力"):
        manager.save_account(data)
    value = data.model_dump()
    for kind in ("imap", "smtp"):
        value[kind]["password"] = "new account password"
    manager.save_account(AccountInput.model_validate(value))
    assert len(manager.settings.accounts) == 2


def test_tampered_host_and_ciphertext_fail_closed(manager):
    unlock(manager)
    data = json.loads(manager.path.read_text())
    data["accounts"][0]["imap"]["host"] = "attacker.example"
    manager.path.write_text(json.dumps(data))
    other = ConfigurationManager(manager.path)
    with pytest.raises(ValueError, match="暗号化データ"):
        unlock(other)
    assert other.settings.accounts[0].imap.password.get_secret_value() == ""


def test_stale_writer_and_atomic_failure_preserve_file(manager):
    unlock(manager)
    stale = ConfigurationManager(manager.path)
    unlock(stale)
    manager.save_account(edit_input(manager, name="New name"))
    with pytest.raises(ValueError, match="外部で変更"):
        stale.save_account(edit_input(stale, name="Lost update"))
    original = manager.path.read_bytes()
    with patch("app.account_settings.os.replace", side_effect=OSError("disk failure")):
        with pytest.raises(OSError):
            manager.save_account(edit_input(manager, name="Not committed"))
    assert manager.path.read_bytes() == original
    assert not list(manager.path.parent.glob(".config-*.tmp"))
    assert manager.settings.accounts[0].name == "New name"


def test_stdio_refresh_sees_web_edit(manager):
    unlock(manager)
    stdio = ConfigurationManager(manager.path)
    unlock(stdio)
    manager.save_account(edit_input(manager, name="Updated from Web"))
    stdio.refresh()
    assert stdio.settings.accounts[0].name == "Updated from Web"
    assert stdio.settings.accounts[0].imap.password.get_secret_value() == "private-imap-value"


def test_master_validation_and_throttle(manager):
    for password, confirmation in [("short", "short"), (MASTER, "mismatch"), ("w" * 40, "w" * 40)]:
        with pytest.raises(ValueError):
            manager.unlock(UnlockInput(master_password=password, confirmation=confirmation))
    unlock(manager)
    other = ConfigurationManager(manager.path)
    for _ in range(5):
        with pytest.raises(ValueError):
            other.unlock(UnlockInput(master_password="wrong"))
    with pytest.raises(ValueError, match="60秒"):
        unlock(other)


class EmptyDatabase:
    async def initialize(self):
        pass


def test_web_auth_no_secret_echo_and_save(manager):
    app = create_app(database=EmptyDatabase(), enable_sync=False, configuration=manager)
    web = {"Authorization": "Bearer " + "w" * 40}
    mcp = {"Authorization": "Bearer " + "m" * 40}
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.get("/api/settings").status_code == 401
        assert client.get("/api/settings", headers=mcp).status_code == 401
        response = client.get("/api/settings", headers=web)
        assert "private-imap-value" not in response.text
        assert response.json()["locked"]
        response = client.post("/api/settings/unlock", headers=web,
                               json={"master_password": MASTER, "confirmation": MASTER})
        assert response.status_code == 200 and not response.json()["locked"]
        assert MASTER not in response.text
        value = edit_input(manager, name="Via API").model_dump(mode="json")
        # Blank fields preserve; DTO model serialization masks secrets, so provide real empty values.
        value["imap"]["password"] = value["smtp"]["password"] = ""
        response = client.put("/api/settings/accounts/work", headers=web, json=value)
        assert response.status_code == 200
        assert manager.settings.accounts[0].name == "Via API"
        value["imap"]["port"] = "private-secret-invalid-port"
        response = client.put("/api/settings/accounts/work", headers=web, json=value)
        assert response.status_code == 422
        assert "private-secret-invalid-port" not in response.text
        response = client.post("/api/settings/unlock", headers=web | {"Origin": "https://evil.example"}, json={"master_password": MASTER})
        assert response.status_code == 403


async def test_mcp_has_no_account_or_unlock_tools(manager):
    server = make_mcp(manager.settings, EmptyDatabase(), manager)
    assert {tool.name for tool in await server.list_tools()} == {"list_accounts", "search_emails", "get_email_detail", "get_thread", "create_draft"}
