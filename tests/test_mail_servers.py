from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from app.imap_sync import drafts_folder, snapshot
from app.mail_parser import parse_mail
from app.smtp_client import DraftInput, append_draft, build_draft, send_reviewed_draft, smtp_send


def test_special_use_japanese_folder_and_append(settings, monkeypatch):
    client = MagicMock()
    client.list_folders.return_value = [((), b"/", "INBOX"), ((b"\\Drafts",), b"/", "[Gmail]/下書き")]
    account = settings.accounts[0].model_copy(update={"drafts_folder": None})
    assert drafts_folder(client, account) == "[Gmail]/下書き"
    @contextmanager
    def fake(account):
        yield client
    monkeypatch.setattr("app.smtp_client.imap_connection", fake)
    raw = build_draft(account, DraftInput(account_id="work", to=["a@example.com"], subject="test", body="本文"))
    assert append_draft(account, raw) == "[Gmail]/下書き"
    client.append.assert_called_once_with("[Gmail]/下書き", raw, flags=(b"\\Draft",))


def test_smtp_bcc_partial_acceptance_and_quit_failure(settings, monkeypatch):
    smtp = MagicMock()
    smtp.sendmail.return_value = {"hidden@example.com": (550, b"rejected")}
    smtp.quit.side_effect = OSError("connection closed after acceptance")
    monkeypatch.setattr("app.smtp_client.smtplib.SMTP_SSL", lambda *args, **kwargs: smtp)
    raw = b"From: me@example.com\r\nTo: a@example.com\r\nBcc: hidden@example.com\r\nMessage-ID: <x@example.com>\r\n\r\nhello"
    result = smtp_send(settings.accounts[0], raw)
    assert result["state"] == "partial"
    args = smtp.sendmail.call_args.args
    assert "hidden@example.com" in args[1]
    assert b"Bcc:" not in args[2]


async def test_send_failure_blocks_retry(db, settings, monkeypatch):
    raw = build_draft(settings.accounts[0], DraftInput(account_id="work", to=["a@example.com"], subject="Test", body="Body"))
    await db.apply_snapshot("work", "Drafts", 1, {1: True}, {1: parse_mail(raw)})
    email_id = (await db.search())[0]["id"]
    monkeypatch.setattr("app.smtp_client.fetch_reviewed_draft", lambda *a: raw)
    smtp = MagicMock(side_effect=TimeoutError())
    monkeypatch.setattr("app.smtp_client.smtp_send", smtp)
    with pytest.raises(ValueError, match="not confirmed"):
        await send_reviewed_draft(settings, db, email_id)
    with pytest.raises(ValueError, match="Already attempted"):
        await send_reviewed_draft(settings, db, email_id)
    assert smtp.call_count == 1
    assert (await db.detail(email_id))["send_state"] == "unknown"


def test_uidvalidity_reset_refetches_known_uid(settings, monkeypatch):
    client = MagicMock()
    client.select_folder.return_value = {b"UIDVALIDITY": 2}
    client.search.return_value = [1]
    def fetch(ids, fields):
        if fields == ["FLAGS"]:
            return {1: {b"FLAGS": (b"\\Seen",)}}
        if fields == ["RFC822.SIZE"]:
            return {1: {b"RFC822.SIZE": 100}}
        return {1: {b"BODY[]": b"Subject: New\r\n\r\nnew mail"}}
    client.fetch.side_effect = fetch
    @contextmanager
    def fake(account):
        yield client
    monkeypatch.setattr("app.imap_sync.imap_connection", fake)
    validity, flags, messages = snapshot(settings.accounts[0], "INBOX", 1, {1}, settings)
    assert validity == 2 and flags[1] and messages[1]["subject"] == "New"
