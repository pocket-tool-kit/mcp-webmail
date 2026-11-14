"""Regression tests for the 2026-11-14 review findings."""
import base64
import imaplib
import smtplib
from unittest.mock import MagicMock

import aiosqlite
import pytest

from app.db import Database
from app.imap_sync import SyncService, snapshot
from app.mail_parser import decode_bytes, parse_mail
from app.smtp_client import DraftInput, build_draft, prepare_send, send_reviewed_draft, smtp_send

CIRCLED = b"\x1b$B%F%9%H-!\x1b(B"  # "テスト①" as Outlook/CP50220 writes ISO-2022-JP


# 1. ISO-2022-JP with NEC special characters
def test_iso2022jp_nec_extensions_body_and_subject():
    assert decode_bytes(CIRCLED, "iso-2022-jp") == "テスト①"
    assert decode_bytes(b"\x1b$B-j\x1b(B", None) == "㈱"
    subject = "=?ISO-2022-JP?B?" + base64.b64encode(CIRCLED).decode() + "?="
    raw = f"Subject: {subject}\r\nContent-Type: text/plain; charset=ISO-2022-JP\r\n\r\n".encode() + CIRCLED
    mail = parse_mail(raw)
    assert mail["subject"] == "テスト①" and mail["body_text"] == "テスト①"
    assert "\x1b" not in mail["subject"]


def test_halfwidth_kana_and_mislabelled_charsets():
    assert decode_bytes(b"\x1b(I1\x1b(B", "iso-2022-jp") == "ｱ"
    assert decode_bytes("日本語".encode("cp932"), "iso-8859-1") == "日本語"
    assert decode_bytes("日本語のメール".encode("euc_jp"), None) == "日本語のメール"
    assert decode_bytes("café".encode("latin-1"), "iso-8859-1") == "café"


# 5. Raw 8-bit headers
def test_raw_8bit_shift_jis_header_and_recipient_name():
    raw = (b"Subject: " + "テスト件名".encode("cp932") + b"\r\nFrom: a@example.com\r\n"
           b"To: " + "山田".encode("cp932") + b" <yamada@example.com>\r\n\r\nbody")
    mail = parse_mail(raw)
    assert mail["subject"] == "テスト件名"
    assert '"name": "山田"' in mail["recipients"] and "yamada@example.com" in mail["recipients"]


# 8. Display and transmission use one recipient parser
def test_encoded_display_name_cannot_inject_address(settings):
    name = "=?utf-8?q?evil=40attacker.example=2C_?="
    raw = (f"From: me@example.com\r\nTo: {name} <ok@example.com>\r\nMessage-ID: <x@example.com>\r\n\r\nhi").encode()
    shown = [r["address"] for r in __import__("json").loads(parse_mail(raw)["recipients"])]
    assert shown == ["ok@example.com"]
    _, envelope = prepare_send(settings.accounts[0], raw)
    assert envelope == ["ok@example.com"]


def test_parser_disagreement_is_refused(settings):
    # An address-looking group construct that the two parsers may read differently
    # must never be sent: either both agree or prepare_send refuses.
    raw = b"From: me@example.com\r\nTo: a@example.com, (comment <b@example.com>) c@example.com\r\n\r\nx"
    try:
        _, envelope = prepare_send(settings.accounts[0], raw)
    except ValueError:
        return
    shown = [r["address"] for r in __import__("json").loads(parse_mail(raw)["recipients"])]
    assert sorted(envelope) == sorted(shown)


# 2. Known-not-sent failures release the one-shot claim
async def _draft(db, settings):
    raw = build_draft(settings.accounts[0], DraftInput(account_id="work", to=["a@example.com"], subject="T", body="B"))
    await db.apply_snapshot("work", "Drafts", 1, {1: True}, {1: parse_mail(raw)})
    return raw, (await db.search())[0]["id"]


async def test_login_failure_is_not_sent_and_retryable(db, settings, monkeypatch):
    raw, email_id = await _draft(db, settings)
    monkeypatch.setattr("app.smtp_client.fetch_reviewed_draft", lambda *a: raw)
    smtp = MagicMock()
    smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad")
    monkeypatch.setattr("app.smtp_client.smtplib.SMTP_SSL", lambda *a, **k: smtp)
    with pytest.raises(ValueError, match="Not sent: SMTP authentication failed"):
        await send_reviewed_draft(settings, db, email_id)
    assert (await db.detail(email_id))["send_state"] is None
    smtp.login.side_effect = None
    smtp.sendmail.return_value = {}
    assert (await send_reviewed_draft(settings, db, email_id))["state"] == "accepted"
    assert (await db.detail(email_id))["send_state"] == "accepted"


async def test_validation_error_does_not_consume_claim(db, settings, monkeypatch):
    raw, email_id = await _draft(db, settings)
    bad = raw.replace(b"From: me@example.com", b"From: other@example.com")
    monkeypatch.setattr("app.smtp_client.fetch_reviewed_draft", lambda *a: bad)
    with pytest.raises(ValueError, match="sender must match"):
        await send_reviewed_draft(settings, db, email_id)
    assert (await db.detail(email_id))["send_state"] is None


def test_disconnect_during_data_is_unknown(settings, monkeypatch):
    smtp = MagicMock()
    smtp.sendmail.side_effect = smtplib.SMTPServerDisconnected()
    monkeypatch.setattr("app.smtp_client.smtplib.SMTP_SSL", lambda *a, **k: smtp)
    raw = b"From: me@example.com\r\nTo: a@example.com\r\n\r\nx"
    with pytest.raises(smtplib.SMTPServerDisconnected):  # not NotSent -> recorded "unknown"
        smtp_send(settings.accounts[0], raw)


# 3. A message that crashes the parser cannot block the folder
def fake_client(bodies, sizes=None):
    client = MagicMock()
    client.select_folder.return_value = {b"UIDVALIDITY": 1}
    client.search.return_value = list(bodies)
    def fetch(ids, fields):
        if fields == ["FLAGS"]:
            return {u: {b"FLAGS": ()} for u in ids}
        if fields == ["RFC822.SIZE"]:
            return {u: {b"RFC822.SIZE": (sizes or {}).get(u, 10)} for u in ids}
        return {u: {b"BODY[]": bodies[u]} for u in ids}
    client.fetch.side_effect = fetch
    return client


def test_unexpected_parser_exception_becomes_placeholder(settings, monkeypatch):
    real = parse_mail
    def flaky(raw):
        if raw == b"BAD":
            raise TypeError("email package bug")
        return real(raw)
    monkeypatch.setattr("app.imap_sync.parse_mail", flaky)
    client = fake_client({1: b"Subject: ok\r\n\r\nx", 2: b"BAD"})
    _, _, messages = snapshot(settings.accounts[0], "INBOX", 1, set(), settings, client)
    assert messages[1]["subject"] == "ok" and messages[2]["subject"] == "[MIME parsing failed]"


def test_network_error_is_not_cached_as_placeholder(settings):
    client = fake_client({1: b"x"})
    client.fetch.side_effect = imaplib.IMAP4.abort("socket closed")
    with pytest.raises(imaplib.IMAP4.abort):
        snapshot(settings.accounts[0], "INBOX", 1, set(), settings, client)


# 4. Folder failures are isolated; one connection per account
async def test_folder_failure_isolated(db, settings, monkeypatch):
    account = settings.accounts[0].model_copy(update={"folders": ["Missing", "INBOX"]})
    settings = settings.model_copy(update={"accounts": [account]})
    client = fake_client({1: b"Subject: hi\r\n\r\nx"})
    client.list_folders.return_value = [((), b"/", "INBOX"), ((b"\\Drafts",), b"/", "Drafts")]
    opened = []
    monkeypatch.setattr("app.imap_sync.open_imap", lambda acc: opened.append(1) or client)
    monkeypatch.setattr("app.imap_sync.close_imap", lambda c: None)
    sync = SyncService(settings, db)
    await sync.sync_account(account)
    status = sync.status["work"]
    assert not status["ok"] and "Missing" in status["error"]
    assert status["folders"]["INBOX"]["ok"] and status["folders"]["Drafts"]["ok"]
    assert len(await db.search(folder="INBOX")) == 1
    assert len(opened) == 1


# Oversize placeholders are re-fetched after raising the limit
async def test_oversize_placeholder_refetched_after_limit_raise(db, settings):
    small = settings.model_copy(update={"max_message_bytes": 2000})
    client = fake_client({1: b"Subject: big\r\n\r\nx"}, sizes={1: 5000})
    result = snapshot(small.accounts[0], "INBOX", None, set(), small, client)
    await db.apply_snapshot("work", "INBOX", *result)
    assert (await db.search())[0]["subject"] == "[Message exceeds size limit]"
    _, known = await db.folder_state("work", "INBOX", 2000)
    assert known == {1}
    _, known = await db.folder_state("work", "INBOX", 10_000)
    assert known == set()
    big = settings.model_copy(update={"max_message_bytes": 10_000})
    result = snapshot(big.accounts[0], "INBOX", 1, known, big, client)
    await db.apply_snapshot("work", "INBOX", *result)
    rows = await db.search()
    assert len(rows) == 1 and rows[0]["subject"] == "big"


# Flag updates touch only changed rows
async def test_flag_updates_only_changed_rows(db, settings):
    await db.apply_snapshot("work", "INBOX", 1, {1: False, 2: False}, {1: parse_mail(b"Subject: a\r\n\r\n"), 2: parse_mail(b"Subject: b\r\n\r\n")})
    calls = []
    real = aiosqlite.Connection.executemany
    async def spy(self, sql, params):
        params = list(params)
        if sql.startswith("UPDATE emails SET is_seen"):
            calls.append(params)
        return await real(self, sql, params)
    aiosqlite.Connection.executemany = spy
    try:
        await db.apply_snapshot("work", "INBOX", 1, {1: True, 2: False}, {})
    finally:
        aiosqlite.Connection.executemany = real
    assert calls == [[(1, "work", "INBOX", 1)]]
    stats = await db.stats(settings.accounts)
    assert stats[0]["unread"] == 1


# Cache is rebuilt when the parser version changes; send guards survive
async def test_old_cache_is_rebuilt_on_upgrade(tmp_path):
    path = tmp_path / "old.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(
            "CREATE TABLE emails(id INTEGER PRIMARY KEY, account_id TEXT, folder TEXT, uid INTEGER, subject TEXT);"
            "INSERT INTO emails VALUES(1,'work','INBOX',1,'mojibake');"
            "CREATE TABLE folders(account_id TEXT, folder TEXT, uidvalidity INTEGER, PRIMARY KEY(account_id,folder));"
            "INSERT INTO folders VALUES('work','INBOX',1);"
            "CREATE TABLE send_attempts(email_id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, message_id TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT, UNIQUE(account_id,message_id));"
            "INSERT INTO send_attempts VALUES(1,'work','<m@x>','unknown',NULL);")
    db = Database(path)
    await db.initialize()
    assert await db.search() == []
    assert await db.rows("SELECT * FROM folders") == []
    assert len(await db.rows("SELECT * FROM send_attempts")) == 1
    await db.initialize()  # idempotent
    await db.apply_snapshot("work", "INBOX", 1, {1: False}, {1: parse_mail(b"Subject: new\r\n\r\n")})
    assert (await db.search())[0]["subject"] == "new"


# Thread lookup (now off-loop, single detail query)
async def test_thread_chain_and_limit(db):
    msgs = {}
    for i in range(1, 6):
        ref = f"In-Reply-To: <m{i-1}@x>\r\n" if i > 1 else ""
        msgs[i] = parse_mail(f"Message-ID: <m{i}@x>\r\n{ref}Subject: s{i}\r\n\r\n".encode())
    msgs[6] = parse_mail(b"Message-ID: <other@x>\r\nSubject: other\r\n\r\n")
    await db.apply_snapshot("work", "INBOX", 1, {i: False for i in msgs}, msgs)
    rows = await db.search(limit=50)
    seed = next(r["id"] for r in rows if r["subject"] == "s5")
    thread = await db.thread(seed)
    assert [r["subject"] for r in thread] == [f"s{i}" for i in range(1, 6)]


# Disabled account mail stays readable; second Web start has a clear error
def test_disabled_account_detail_and_web_lock(settings, db, monkeypatch, tmp_path):
    import asyncio
    from fastapi.testclient import TestClient
    from filelock import FileLock
    from app import main
    asyncio.run(db.apply_snapshot("work", "Drafts", 1, {1: False}, {1: parse_mail(b"Subject: x\r\n\r\n")}))
    disabled = settings.model_copy(update={"accounts": [settings.accounts[0].model_copy(update={"enabled": False})]})
    app = main.create_app(disabled, db, enable_sync=False)
    web = {"Authorization": "Bearer " + settings.web_token.get_secret_value()}
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        email_id = client.get("/api/emails", headers=web).json()[0]["id"]
        response = client.get(f"/api/emails/{email_id}", headers=web)
        assert response.status_code == 200 and response.json()["is_draft"]
    monkeypatch.setattr(main, "DATA", tmp_path)
    holder = FileLock(str(tmp_path / "web.lock"))
    holder.acquire()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            with TestClient(main.create_app(settings, db, enable_sync=True)):
                pass
    finally:
        holder.release()
