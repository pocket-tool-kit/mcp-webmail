"""v0.3: folders, mail actions, attachments, composing and sending, POP3."""
import base64
import json
from contextlib import contextmanager
from unittest.mock import MagicMock

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from app.db import Database
from app.imap_sync import SyncService, list_mailboxes
from app.mail_parser import parse_mail, parse_message
from app.main import create_app
from tests.conftest import REAL_OPEN_POP, WEB, make_mail
from tests.fakes import FakeIMAP, pop3_server, smtp_server

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


@contextmanager
def running(settings, db):
    """App without the background loop; tests trigger a sync explicitly."""
    app = create_app(settings, db, enable_sync=False)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        def sync():
            client.portal.call(app.state.sync.sync_account, settings.accounts[0])
            return app.state.sync.status[settings.accounts[0].id]
        client.sync = sync
        yield client


def ids(client, **params):
    rows = client.get("/api/emails", headers=WEB, params=params).json()
    return {r["subject"]: r["id"] for r in rows}


def fake_smtp(monkeypatch, refused=None):
    smtp = MagicMock()
    smtp.sendmail.return_value = refused or {}
    monkeypatch.setattr("app.smtp_client.smtplib.SMTP_SSL", lambda *a, **k: smtp)
    return smtp


# --- folders -----------------------------------------------------------------
def test_roles_from_special_use_names_and_overrides(account_settings):
    account = account_settings.accounts[0]
    plain = FakeIMAP({"INBOX": {}, "Sent Items": {}, "Deleted Items": {}, "Drafts": {}, "Junk": {}, "Archive": {}, "Trash": {}})
    roles = {b["name"]: b["role"] for b in list_mailboxes(plain, account)}
    assert roles["INBOX"] == "inbox" and roles["Sent Items"] == "sent" and roles["Drafts"] == "drafts"
    assert roles["Junk"] == "junk" and roles["Archive"] == "archive"
    # Two candidates for Trash: never guess.
    assert roles["Deleted Items"] == "" and roles["Trash"] == ""
    chosen = account.model_copy(update={"trash_folder": "Deleted Items"})
    assert {b["name"]: b["role"] for b in list_mailboxes(plain, chosen)}["Deleted Items"] == "trash"


def test_sync_all_folders_flags_and_counts(account_settings, db, imap):
    with running(account_settings, db) as client:
        status = client.sync()
        assert status["ok"] and status["drafts_folder"] == "[Gmail]/下書き"
        # \Noselect and the duplicate "All Mail" are not downloaded.
        assert "[Gmail]" not in status["folders"] and "[Gmail]/すべてのメール" not in status["folders"]
        account = client.get("/api/accounts", headers=WEB).json()[0]
        assert [f["role"] for f in account["folders"]][:3] == ["inbox", "drafts", "sent"]
        assert account["unread"] == 2 and account["ready"] and account["signature"] == "山田"
        assert {"name": "[Gmail]/すべてのメール", "role": "all"} in account["mailboxes"]
        rows = client.get("/api/emails", headers=WEB, params={"flagged": True}).json()
        assert [r["subject"] for r in rows] == ["Starred"]
        assert [r["subject"] for r in client.get("/api/emails", headers=WEB, params={"attachments": True}).json()] == ["With file"]
        assert len(client.get("/api/emails", headers=WEB, params={"unread": True}).json()) == 2
        assert list(ids(client, query="bob@example.com")) == ["Starred"]  # recipients are searchable


def test_explicit_folder_list_drops_cache_of_removed_folder(account_settings, db, imap):
    with running(account_settings, db) as client:
        client.sync()
        assert "Old" not in ids(client) and len(ids(client)) == 3
        account_settings.accounts[0].folders = ["Projects"]
        client.sync()
        assert ids(client) == {}  # INBOX is no longer synced, its cache is gone
        assert {f["folder"] for f in client.get("/api/accounts", headers=WEB).json()[0]["folders"]} == {"Projects", "[Gmail]/下書き"}


# --- flags, move, archive, delete -------------------------------------------
def test_flags_move_archive_delete_round_trip(account_settings, db, imap):
    with running(account_settings, db) as client:
        client.sync()
        mail = ids(client)
        assert client.post("/api/emails/flags", headers=WEB, json={"ids": [mail["With file"]], "seen": True, "flagged": True}).status_code == 200
        assert imap.flags("INBOX", 2) == {b"\\Seen", b"\\Flagged"}
        assert client.get(f"/api/emails/{mail['With file']}", headers=WEB).json()["is_flagged"] == 1
        client.post("/api/emails/flags", headers=WEB, json={"ids": [mail["First"]], "seen": False})
        assert imap.flags("INBOX", 1) == set()
        assert client.post("/api/emails/flags", headers=WEB, json={"ids": [mail["First"]]}).status_code == 400

        assert client.post("/api/emails/move", headers=WEB, json={"ids": [mail["First"]], "folder": "Projects"}).json()["moved"] == 1
        assert imap.uids("INBOX") == [2, 3] and imap.uids("Projects") == [1]
        assert client.post("/api/emails/move", headers=WEB, json={"ids": [mail["Starred"]], "folder": "Nowhere"}).status_code == 400
        # Gmail has no Archive folder: archiving lands in All Mail.
        assert client.post("/api/emails/archive", headers=WEB, json={"ids": [mail["Starred"]]}).status_code == 200
        assert imap.uids("INBOX") == [2] and len(imap.uids("[Gmail]/すべてのメール")) == 2

        assert client.post("/api/emails/delete", headers=WEB, json={"ids": [mail["With file"]]}).json() == {"trashed": 1, "deleted": 0}
        assert imap.uids("INBOX") == [] and imap.uids("[Gmail]/ゴミ箱") == [1]
        client.sync()
        trashed = ids(client, folder="[Gmail]/ゴミ箱")["With file"]
        # Deleting inside Trash removes the message for good.
        assert client.post("/api/emails/delete", headers=WEB, json={"ids": [trashed]}).json() == {"trashed": 0, "deleted": 1}
        assert imap.uids("[Gmail]/ゴミ箱") == []
        assert client.post("/api/emails/delete", headers=WEB, json={"ids": [trashed]}).status_code == 400  # already gone


def test_move_without_move_capability_and_changed_uidvalidity(account_settings, db, imap):
    imap.capabilities = set()
    with running(account_settings, db) as client:
        client.sync()
        mail = ids(client)
        imap.folders["INBOX"]["messages"][7] = [make_mail("Other client deleted"), {b"\\Deleted"}]
        client.post("/api/emails/move", headers=WEB, json={"ids": [mail["First"]], "folder": "Projects"})
        assert imap.uids("Projects") == [1] and 1 not in imap.uids("INBOX")
        # Without UID EXPUNGE, a message another client merely marked as deleted must survive.
        assert 7 in imap.uids("INBOX") and imap.flags("INBOX", 7) == {b"\\Deleted"}
        imap.folders["INBOX"]["uidvalidity"] = 99
        response = client.post("/api/emails/flags", headers=WEB, json={"ids": [mail["Starred"]], "seen": True})
        assert response.status_code == 400 and "同期" in response.json()["detail"]
        assert b"\\Seen" not in imap.flags("INBOX", 3)


def test_delete_without_trash_requires_permanent(account_settings, db, monkeypatch):
    server = FakeIMAP({"INBOX": {"messages": {1: [make_mail("Only"), set()]}}})
    monkeypatch.setattr("app.imap_sync.open_imap", lambda account: server)
    with running(account_settings, db) as client:
        client.sync()
        target = ids(client)["Only"]
        response = client.post("/api/emails/delete", headers=WEB, json={"ids": [target]})
        assert response.status_code == 400 and "ごみ箱" in response.json()["detail"]
        assert server.uids("INBOX") == [1]
        assert client.post("/api/emails/delete", headers=WEB, json={"ids": [target], "permanent": True}).json()["deleted"] == 1
        assert server.uids("INBOX") == []


# --- attachments -------------------------------------------------------------
def test_attachment_download_and_inline_images(account_settings, db, imap):
    imap.folders["INBOX"]["messages"][4] = [make_mail("Pretty", html='<p>Hi<img src="cid:logo@x"></p>', inline_png=PNG), set()]
    with running(account_settings, db) as client:
        client.sync()
        mail = ids(client)
        detail = client.get(f"/api/emails/{mail['With file']}", headers=WEB).json()
        assert detail["attachments"] == [{"index": 0, "filename": "報告書.pdf", "content_type": "application/pdf",
                                          "size": 13, "inline": False, "cid": ""}]
        response = client.get(f"/api/emails/{mail['With file']}/attachments/0", headers=WEB)
        assert response.content == b"%PDF-1.4 data"
        # Never rendered in the app origin, whatever the declared type.
        assert response.headers["content-type"] == "application/octet-stream"
        assert response.headers["content-disposition"].startswith("attachment; filename*=UTF-8''%E5%A0%B1")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert client.get(f"/api/emails/{mail['With file']}/attachments/5", headers=WEB).status_code == 400
        assert client.get(f"/api/emails/{mail['With file']}/attachments/0").status_code == 401
        images = client.get(f"/api/emails/{mail['Pretty']}/inline", headers=WEB).json()
        assert images == {"logo@x": "data:image/png;base64," + base64.b64encode(PNG).decode()}
        assert b"\\Seen" not in imap.flags("INBOX", 2)  # reading attachments uses BODY.PEEK


# --- composing and sending ----------------------------------------------------
def test_send_now_with_cc_bcc_attachment_and_sent_copy(account_settings, db, imap, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    payload = {"account_id": "work", "to": ["a@example.com"], "cc": ["c@example.com"], "bcc": ["hidden@example.com"],
               "subject": "見積書の件", "body": "添付をご確認ください。",
               "attachments": [{"filename": "../見積.pdf", "content_type": "application/pdf", "data": base64.b64encode(b"PDF!").decode()}]}
    with running(account_settings, db) as client:
        client.sync()
        assert client.post("/api/send", headers=WEB, json=payload).status_code == 400  # needs the explicit confirmation header
        response = client.post("/api/send", headers=WEB | {"X-Confirm-Send": "human-reviewed"}, json=payload)
        assert response.json() == {"state": "accepted", "refused": []}
        sender, envelope, data = smtp.sendmail.call_args.args
        assert sender == "me@example.com" and sorted(envelope) == ["a@example.com", "c@example.com", "hidden@example.com"]
        assert b"hidden@example.com" not in data and b"Bcc" not in data
        sent = parse_mail(data)
        assert sent["subject"] == "見積書の件" and sent["sender"] == "山田 太郎 <me@example.com>"
        assert json.loads(sent["attachments"])[0]["filename"] == "_見積.pdf"  # no path components
        # A copy is stored in Sent, already read, and keeps the Bcc for the sender's records.
        copy = imap.raw("[Gmail]/送信済みメール", 1)
        assert imap.flags("[Gmail]/送信済みメール", 1) == {b"\\Seen"} and b"hidden@example.com" in copy
        bad = payload | {"attachments": [{"filename": "x", "data": "not base64!"}]}
        assert client.post("/api/send", headers=WEB | {"X-Confirm-Send": "human-reviewed"}, json=bad).status_code == 400
        none = payload | {"to": [], "cc": [], "bcc": [], "attachments": []}
        assert client.post("/api/send", headers=WEB | {"X-Confirm-Send": "human-reviewed"}, json=none).status_code == 400
        assert smtp.sendmail.call_count == 1


def test_save_sent_disabled_and_unknown_outcome_blocks_resend(account_settings, db, imap, monkeypatch):
    account_settings.accounts[0].save_sent = False
    smtp = fake_smtp(monkeypatch)
    confirm = WEB | {"X-Confirm-Send": "human-reviewed"}
    payload = {"account_id": "work", "to": ["a@example.com"], "subject": "s", "body": "b"}
    with running(account_settings, db) as client:
        client.sync()
        assert client.post("/api/send", headers=confirm, json=payload).json()["state"] == "accepted"
        assert imap.uids("[Gmail]/送信済みメール") == []  # the provider keeps its own copy
        smtp.sendmail.side_effect = TimeoutError()
        response = client.post("/api/send", headers=confirm, json=payload)
        assert response.status_code == 400 and "not confirmed" in response.json()["detail"]


async def test_unknown_outcome_is_recorded(account_settings, db, imap, monkeypatch):
    from app.smtp_client import DraftInput, send_now
    smtp = fake_smtp(monkeypatch)
    smtp.sendmail.side_effect = TimeoutError()
    with pytest.raises(ValueError, match="not confirmed"):
        await send_now(account_settings, db, DraftInput(account_id="work", to=["a@example.com"], subject="s", body="b"))
    assert [r["state"] for r in await db.rows("SELECT state FROM send_attempts")] == ["unknown"]
    assert imap.uids("[Gmail]/送信済みメール") == []


def test_reply_all_forward_and_answered_flag(account_settings, db, imap, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    confirm = WEB | {"X-Confirm-Send": "human-reviewed"}
    with running(account_settings, db) as client:
        client.sync()
        mail = ids(client)
        reply = {"account_id": "work", "to": ["alice@example.com"], "cc": ["bob@example.com"], "subject": "Re: Starred",
                 "body": "了解です", "reply_to_email_id": mail["Starred"]}
        assert client.post("/api/send", headers=confirm, json=reply).status_code == 200
        sent = parse_message(smtp.sendmail.call_args.args[2])
        assert sent["In-Reply-To"] == "<Starred@example.com>" and sent["References"] == "<Starred@example.com>"
        assert client.get(f"/api/emails/{mail['Starred']}", headers=WEB).json()["is_answered"] == 1
        forward = {"account_id": "work", "to": ["z@example.com"], "subject": "Fwd: With file", "body": "転送します",
                   "source_attachments": {"email_id": mail["With file"], "indexes": [0]}}
        assert client.post("/api/send", headers=confirm, json=forward).status_code == 200
        attached = json.loads(parse_mail(smtp.sendmail.call_args.args[2])["attachments"])
        assert [(a["filename"], a["size"]) for a in attached] == [("報告書.pdf", 13)]


def test_draft_with_attachment_edit_and_reviewed_send(account_settings, db, imap, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    drafts = "[Gmail]/下書き"
    with running(account_settings, db) as client:
        client.sync()
        parent = ids(client)["First"]
        draft = {"account_id": "work", "to": ["a@example.com"], "subject": "Re: First", "body": "v1", "reply_to_email_id": parent,
                 "attachments": [{"filename": "a.txt", "content_type": "text/plain", "data": base64.b64encode(b"hello").decode()}]}
        assert client.post("/api/drafts", headers=WEB, json=draft).json()["folder"] == drafts
        assert imap.flags(drafts, 1) == {b"\\Draft"}
        client.sync()
        first = ids(client, folder=drafts)["Re: First"]
        detail = client.get(f"/api/emails/{first}", headers=WEB).json()
        assert detail["is_draft"] and detail["attachments"][0]["content_type"] == "application/octet-stream"
        # Edit: new text, keep the attachment, replace the old draft on the server.
        edited = {"account_id": "work", "to": ["a@example.com", "b@example.com"], "subject": "Re: First", "body": "v2",
                  "replace_email_id": first, "source_attachments": {"email_id": first, "indexes": [0]}}
        assert "warnings" not in client.post("/api/drafts", headers=WEB, json=edited).json()
        assert imap.uids(drafts) == [2]
        client.sync()
        second = ids(client, folder=drafts)["Re: First"]
        detail = client.get(f"/api/emails/{second}", headers=WEB).json()
        assert detail["body_text"].strip() == "v2" and detail["in_reply_to"] == "<First@example.com>"
        assert [a["filename"] for a in detail["attachments"]] == ["a.txt"]
        # A message outside Drafts can never be "replaced".
        assert client.post("/api/drafts", headers=WEB, json=edited | {"replace_email_id": parent}).status_code == 400

        response = client.post(f"/api/drafts/{second}/send", headers=WEB | {"X-Confirm-Send": "human-reviewed"})
        assert response.json() == {"state": "accepted", "refused": []}
        assert sorted(smtp.sendmail.call_args.args[1]) == ["a@example.com", "b@example.com"]
        assert imap.uids(drafts) == [] and len(imap.uids("[Gmail]/送信済みメール")) == 1
        assert smtp.sendmail.call_count == 1


def test_draft_changed_on_server_is_not_sent(account_settings, db, imap, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    with running(account_settings, db) as client:
        client.sync()
        client.post("/api/drafts", headers=WEB, json={"account_id": "work", "to": ["a@example.com"], "subject": "D", "body": "x"})
        client.sync()
        draft = ids(client, folder="[Gmail]/下書き")["D"]
        # Another client swaps in an attachment after the user reviewed the cached draft.
        imap.folders["[Gmail]/下書き"]["messages"][1][0] = make_mail("D", sender="me@example.com", to="a@example.com", body="x",
                                                                    attachment=("evil.pdf", b"1"))
        response = client.post(f"/api/drafts/{draft}/send", headers=WEB | {"X-Confirm-Send": "human-reviewed"})
        assert response.status_code == 400 and "changed" in response.json()["detail"]
        assert smtp.sendmail.call_count == 0


# --- POP3 ----------------------------------------------------------------------
@pytest.fixture
def pop_settings(account_settings, tls, monkeypatch):
    monkeypatch.setattr("app.imap_sync.open_pop", REAL_OPEN_POP)
    messages = [("uidl-1", make_mail("Pop one")), ("uidl-2", make_mail("Pop two", body=".leading dot\n本文", attachment=("p.pdf", b"PDF")))]
    server = pop3_server(*tls, messages)
    account = account_settings.accounts[0]
    account.protocol, account.folders = "pop3", ["INBOX"]
    account.imap.host, account.imap.port = "localhost", server.start()
    yield account_settings, server
    server.shutdown()
    server.server_close()


def test_pop3_sync_local_folders_and_send(pop_settings, db, monkeypatch):
    settings, server = pop_settings
    smtp = fake_smtp(monkeypatch)
    with running(settings, db) as client:
        assert client.sync()["ok"]
        mail = ids(client)
        assert set(mail) == {"Pop one", "Pop two"}
        detail = client.get(f"/api/emails/{mail['Pop two']}", headers=WEB).json()
        assert detail["body_text"].startswith(".leading dot") and not detail["is_seen"]
        assert client.get(f"/api/emails/{mail['Pop two']}/attachments/0", headers=WEB).content == b"PDF"
        # A second sync downloads nothing again and never deletes on the server.
        server.commands.clear()
        client.sync()
        assert "RETR" not in server.commands and "DELE" not in server.commands and len(ids(client)) == 2
        server.messages.append(("uidl-3", make_mail("Pop three")))
        client.sync()
        assert "Pop three" in ids(client)

        # Read state, folders, drafts and Sent exist only locally.
        client.post("/api/emails/flags", headers=WEB, json={"ids": [mail["Pop one"]], "seen": True, "flagged": True})
        assert client.get(f"/api/emails/{mail['Pop one']}", headers=WEB).json()["is_flagged"] == 1
        assert client.post("/api/emails/delete", headers=WEB, json={"ids": [mail["Pop one"]]}).json()["trashed"] == 1
        assert client.get(f"/api/emails/{mail['Pop one']}", headers=WEB).json()["folder"] == "Trash"
        assert client.get(f"/api/emails/{mail['Pop one']}/attachments/0", headers=WEB).status_code == 400
        assert client.post("/api/emails/delete", headers=WEB, json={"ids": [mail["Pop one"]]}).json()["deleted"] == 1
        client.sync()
        assert "Pop one" not in ids(client)  # stays deleted locally although the server still has it

        client.post("/api/drafts", headers=WEB, json={"account_id": "work", "to": ["a@example.com"], "subject": "Local draft", "body": "x"})
        draft = ids(client, folder="Drafts")["Local draft"]
        assert client.get(f"/api/emails/{draft}", headers=WEB).json()["is_draft"]
        response = client.post(f"/api/drafts/{draft}/send", headers=WEB | {"X-Confirm-Send": "human-reviewed"})
        assert response.json()["state"] == "accepted" and smtp.sendmail.call_count == 1
        assert ids(client, folder="Drafts") == {} and list(ids(client, folder="Sent")) == ["Local draft"]
        folders = {f["folder"]: f["role"] for f in client.get("/api/accounts", headers=WEB).json()[0]["folders"]}
        assert folders == {"INBOX": "inbox", "Drafts": "drafts", "Sent": "sent", "Archive": "archive", "Trash": "trash"}


def test_pop3_wrong_password_is_reported_without_server_text(pop_settings, db):
    settings, server = pop_settings
    server.credentials = ("me", "different")
    with running(settings, db) as client:
        status = client.sync()
        assert not status["ok"] and "POP3" in status["error"] and "invalid login" not in status["error"]


async def test_local_mail_survives_cache_rebuild(tmp_path):
    database = Database(tmp_path / "mail.db")
    await database.initialize()
    await database.ensure_local_folders("pop")
    raw = make_mail("Kept")
    await database.apply_pop("pop", [("u1", parse_mail(raw), raw)])
    await database.apply_snapshot("imap", "INBOX", 1, {1: 0}, {1: parse_mail(make_mail("Refetchable"))})
    kept = (await database.search(account_id="pop"))[0]["id"]
    await database.update_flags([kept], seen=True, flagged=True)
    async with aiosqlite.connect(database.path) as conn:
        await conn.execute("PRAGMA user_version=1")  # simulate a future parser change
        await conn.commit()
    await database.initialize()
    rows = await database.search()
    assert [r["subject"] for r in rows] == ["Kept"] and rows[0]["is_flagged"] == 1 and rows[0]["is_seen"] == 1
    assert (await database.detail(rows[0]["id"]))["folder_role"] == "inbox"
    assert await database.known_uidls("pop") == {"u1"}  # not downloaded a second time


# --- real SMTP conversation ----------------------------------------------------
def test_password_login_and_delivery_over_tls(account_settings, tls):
    from app.smtp_client import smtp_send
    server = smtp_server(*tls)
    account = account_settings.accounts[0]
    account.smtp.host, account.smtp.port = "localhost", server.start()
    try:
        raw = make_mail("Wire", sender="me@example.com", to="a@example.com", body="line\n.dot line")
        assert smtp_send(account, raw) == {"state": "accepted", "refused": []}
    finally:
        server.shutdown()
        server.server_close()
    assert server.auth[0][0] in {"PLAIN", "LOGIN"}
    envelope, data = server.deliveries[0]
    assert envelope == ["a@example.com"] and b"Subject: Wire" in data
