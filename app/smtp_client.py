from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
import smtplib
import socket
import ssl
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, formataddr, getaddresses, make_msgid

from email_validator import validate_email
from pydantic import Field, field_validator, model_validator

from . import mailbox
from .config import Account, Settings, StrictModel
from .db import Database
from .imap_sync import DRAFT, SEEN, drafts_folder, imap_append, imap_connection, tls_context
from .mail_parser import extract_attachment, parse_mail, parse_message, parse_recipients
from .oauth import OAuthError, TOKENS, xoauth2

MAX_RECIPIENTS = 50


class NotSent(Exception):
    """The SMTP transaction certainly did not deliver the message (safe to retry)."""


class AttachmentInput(StrictModel):
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(default="application/octet-stream", max_length=127)
    data: str = Field(max_length=48_000_000)  # base64

    @field_validator("filename")
    @classmethod
    def plain_name(cls, value):
        value = re.sub(r"[\x00-\x1f\x7f/\\]", "_", value).strip(" .")
        if not value:
            raise ValueError("Invalid filename")
        return value


class SourceAttachments(StrictModel):
    """Attachments copied from a cached email (forwarding, editing a draft)."""
    email_id: int = Field(gt=0)
    indexes: list[int] = Field(max_length=50)


class DraftInput(StrictModel):
    account_id: str
    to: list[str] = Field(default_factory=list, max_length=MAX_RECIPIENTS)
    cc: list[str] = Field(default_factory=list, max_length=MAX_RECIPIENTS)
    bcc: list[str] = Field(default_factory=list, max_length=MAX_RECIPIENTS)
    subject: str = Field(max_length=998)
    body: str = Field(max_length=1_000_000)
    reply_to_email_id: int | None = Field(default=None, gt=0)
    attachments: list[AttachmentInput] = Field(default_factory=list, max_length=20)
    source_attachments: SourceAttachments | None = None
    # An existing draft that this one replaces (deleted after the new one is saved/sent).
    replace_email_id: int | None = Field(default=None, gt=0)

    @field_validator("subject")
    @classmethod
    def no_injection(cls, value):
        if any(c in value for c in "\r\n\x00"):
            raise ValueError("Invalid subject")
        return value

    @field_validator("to", "cc", "bcc")
    @classmethod
    def valid_recipients(cls, values):
        return [validate_email(v, check_deliverability=False, allow_smtputf8=False).normalized for v in values]

    @model_validator(mode="after")
    def bounded(self):
        if len(self.to) + len(self.cc) + len(self.bcc) > MAX_RECIPIENTS:
            raise ValueError("Too many recipients")
        return self


def build_draft(account: Account, data: DraftInput, parent=None, attachments=()) -> bytes:
    """attachments: iterable of (filename, content_type, bytes)."""
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = formataddr((account.display_name, str(account.email))) if account.display_name else str(account.email)
    for name, values in (("To", data.to), ("Cc", data.cc), ("Bcc", data.bcc)):
        if values:
            msg[name] = ", ".join(values)
    msg["Subject"] = data.subject
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(domain=str(account.email).split("@")[-1])
    if parent and parent["message_id"]:
        # Accept only RFC message-id tokens; never copy arbitrary header lines.
        ids = re.findall(r"<[^<>\s]+>", parent["references_header"] + " " + parent["message_id"])
        if ids:
            msg["In-Reply-To"] = ids[-1]
            msg["References"] = " ".join(dict.fromkeys(ids[-30:]))
    msg.set_content(data.body)
    for filename, content_type, content in attachments:
        maintype, _, subtype = content_type.partition("/")
        if not re.fullmatch(r"[\w.+-]+/[\w.+-]+", content_type) or maintype in {"multipart", "message", "text"}:
            # Never let an attachment be re-interpreted as structure or inline text.
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()  # SMTP policy guarantees CRLF including multipart boundaries.


async def compose(settings: Settings, db: Database, data: DraftInput) -> tuple[Account, bytes]:
    account = settings.account(data.account_id)
    parent = await db.detail(data.reply_to_email_id) if data.reply_to_email_id else None
    if parent and parent["account_id"] != account.id:
        raise ValueError("Reply account must match original email")
    if parent is None and data.replace_email_id:
        # An edited reply draft keeps its place in the thread.
        previous = await db.detail(data.replace_email_id)
        if previous["account_id"] == account.id and previous["in_reply_to"]:
            parent = {"message_id": previous["in_reply_to"], "references_header": previous["references_header"]}
    files = []
    if data.source_attachments and data.source_attachments.indexes:
        source = await db.detail(data.source_attachments.email_id)
        if source["account_id"] != account.id:
            raise ValueError("Attachments must come from the same account")
        raw = await mailbox.fetch_raw(settings, db, source)
        for index in dict.fromkeys(data.source_attachments.indexes):
            info, content = extract_attachment(raw, index)
            files.append((info["filename"], info["content_type"], content))
    for item in data.attachments:
        try:
            files.append((item.filename, item.content_type, base64.b64decode(item.data, validate=True)))
        except (binascii.Error, ValueError):
            raise ValueError("添付ファイルのデータが不正です。") from None
    raw = build_draft(account, data, parent, files)
    if len(raw) > settings.max_message_bytes:
        raise ValueError("メールがサイズ上限（max_message_bytes）を超えています。添付を減らしてください。")
    return account, raw


def append_draft(account, raw):
    with imap_connection(account) as client:
        folder = drafts_folder(client, account)
        client.append(folder, raw, flags=(b"\\Draft",))
        return folder


async def _replaced_draft(settings, db, data: DraftInput, account):
    if not data.replace_email_id:
        return None
    old = await db.detail(data.replace_email_id)
    if old["account_id"] != account.id or old["folder_role"] != "drafts" and old["folder"] != account.drafts_folder:
        raise ValueError("Only a draft of the same account can be replaced")
    return old


async def _discard(settings, db, mail) -> str | None:
    """Best-effort removal of a superseded/sent draft. Returns a warning or None."""
    try:
        await mailbox.delete(settings, db, [mail["id"]], permanent=True)
    except Exception:
        return "元の下書きを削除できませんでした。下書きフォルダを確認してください。"
    return None


async def create_draft(settings: Settings, db: Database, data: DraftInput):
    account, raw = await compose(settings, db, data)
    old = await _replaced_draft(settings, db, data, account)
    if account.protocol == "pop3":
        await db.ensure_local_folders(account.id)
        await db.local_insert(account.id, "Drafts", parse_mail(raw), raw)
        folder = "Drafts"
    else:
        try:
            folder = await asyncio.to_thread(append_draft, account, raw)
        except Exception:
            # APPEND may have succeeded before disconnect. Never retry automatically.
            raise ValueError("Draft save not confirmed; check Drafts before retrying") from None
    result = {"saved": True, "account_id": account.id, "folder": folder,
              "message_id": parse_mail(raw)["message_id"], "note": "Appears after next Web sync; not sent"}
    if old:
        warning = await _discard(settings, db, old)
        if warning:
            result["warnings"] = [warning]
    return result


def fetch_reviewed_draft(account, mail, max_bytes):
    with imap_connection(account) as client:
        if mail["folder"] != drafts_folder(client, account):
            raise ValueError("Only messages in the actual Drafts folder can be sent")
        selected = client.select_folder(mail["folder"], readonly=True)
        if int(selected[b"UIDVALIDITY"]) != mail["uidvalidity"]:
            raise ValueError("Folder changed; sync and review again")
        uid = mail["uid"]
        sizes = client.fetch([uid], ["RFC822.SIZE"])
        if uid not in sizes or sizes[uid][b"RFC822.SIZE"] > max_bytes:
            raise ValueError("Draft missing or too large")
        item = client.fetch([uid], ["BODY.PEEK[]"]).get(uid, {})
        raw = item.get(b"BODY[]")
        if not raw:
            raise ValueError("Draft disappeared")
        live = parse_mail(raw)
        for key in ("message_id", "subject", "sender", "body_text", "body_html", "has_attachments"):
            if live[key] != mail[key]:
                raise ValueError("Draft changed; sync and review again")
        if json.loads(live["recipients"]) != mail["recipients"]:
            raise ValueError("Draft recipients changed; sync and review again")
        # The reviewed attachment list (names, types, sizes) must be what is sent.
        if json.loads(live["attachments"]) != mail.get("attachments", []):
            raise ValueError("Draft attachments changed; sync and review again")
        return raw


def prepare_send(account, raw):
    """Validate a draft for sending without any network I/O.

    Returns (message to transmit, envelope recipients). Runs before the send
    claim so that a rejected draft is never recorded as "outcome unknown".
    """
    msg = BytesParser(policy=policy.SMTP).parsebytes(raw)
    # Reject ambiguous/resend headers rather than risk sending to hidden targets.
    if any(k.lower().startswith("resent-") for k in msg.keys()):
        raise ValueError("Resent headers are not supported")
    for key in ("From", "To", "Cc", "Bcc"):
        if len(msg.get_all(key, [])) > 1:
            raise ValueError("Duplicate address headers")
    senders = getaddresses([str(msg.get("From", ""))])
    if len(senders) != 1 or senders[0][1].lower() != str(account.email).lower():
        raise ValueError("Draft sender must match account email")
    # The reviewed list (same parser as the UI) is the envelope. The SMTP-policy
    # parser must agree exactly, otherwise display and transmission could differ.
    reviewed = [r["address"] for r in parse_recipients(parse_message(raw))]
    structured = []
    for key in ("To", "Cc", "Bcc"):
        if key in msg:
            try:
                structured += [a.addr_spec for a in msg[key].addresses]
            except Exception:
                raise ValueError("Unparseable recipient header") from None
    if sorted(a.lower() for a in reviewed) != sorted(a.lower() for a in structured if a):
        raise ValueError("Ambiguous recipient headers; recreate the draft")
    if not 1 <= len(reviewed) <= MAX_RECIPIENTS:
        raise ValueError("Invalid recipient count")
    recipients = [validate_email(a, check_deliverability=False, allow_smtputf8=False).normalized for a in reviewed]
    # SMTP sends the original MIME structure, including attachments. Bcc is
    # envelope-only and is removed from the transmitted message.
    if "Bcc" in msg:
        del msg["Bcc"]
    return msg, recipients


def _not_sent_reason(exc):
    if isinstance(exc, OAuthError):
        return str(exc)
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication failed"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "all recipients refused"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "sender refused"
    if isinstance(exc, smtplib.SMTPDataError):
        return "message rejected by server"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed"
    if isinstance(exc, ssl.SSLError):
        return "TLS error"
    if isinstance(exc, socket.gaierror):
        return "SMTP host name not resolved"
    if isinstance(exc, ConnectionRefusedError):
        return "SMTP connection refused"
    if isinstance(exc, TimeoutError):
        return "SMTP connection timed out"
    return f"SMTP not reached ({type(exc).__name__})"


def smtp_login(account):
    """Connect, negotiate TLS and authenticate. The caller closes the client."""
    endpoint = account.smtp
    context = tls_context()
    client = (smtplib.SMTP_SSL(endpoint.host, endpoint.port, timeout=30, context=context)
              if endpoint.security == "tls" else smtplib.SMTP(endpoint.host, endpoint.port, timeout=30))
    try:
        client.ehlo()
        if endpoint.security == "starttls":
            client.starttls(context=context)
            client.ehlo()
        if account.auth == "oauth2":
            token = TOKENS.access_token(account)
            client.auth("XOAUTH2", lambda challenge=None: xoauth2(endpoint.username, token), initial_response_ok=True)
        else:
            client.login(endpoint.username, endpoint.password.get_secret_value())
    except BaseException:
        client.close()
        raise
    return client


def check_smtp(account) -> dict:
    try:
        client = smtp_login(account)
    except Exception as exc:
        return {"ok": False, "error": _not_sent_reason(exc)}
    try:
        client.quit()
    except Exception:
        client.close()
    return {"ok": True}


def smtp_send(account, raw):
    msg, recipients = prepare_send(account, raw)
    client = None
    try:
        # Phase 1: connect / TLS / login. Nothing can have been delivered yet.
        try:
            client = smtp_login(account)
        except Exception as exc:
            raise NotSent(_not_sent_reason(exc)) from None
        # Phase 2: transaction. Explicit server rejections are definite; any
        # other failure (disconnect/timeout during DATA) is "outcome unknown".
        try:
            refused = client.sendmail(str(account.email), recipients, msg.as_bytes(policy=policy.SMTP))
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError,
                smtplib.SMTPHeloError, smtplib.SMTPNotSupportedError) as exc:
            raise NotSent(_not_sent_reason(exc)) from None
        return {"state": "partial" if refused else "accepted", "refused": list(refused)}
    finally:
        # A QUIT failure after DATA acceptance must not turn success into failure.
        if client is not None:
            try:
                client.quit()
            except Exception:
                client.close()


async def _after_send(settings, db, account, raw, draft, replied_id=None) -> list[str]:
    """Sent copy, draft cleanup, \\Answered. Failures never change the send result."""
    warnings = []
    if account.protocol == "pop3":
        await db.ensure_local_folders(account.id)
        await db.local_insert(account.id, "Sent", parse_mail(raw), raw)
    elif account.save_sent:
        sent = await db.role_folder(account.id, "sent")
        try:
            if not sent:
                raise ValueError()
            await asyncio.to_thread(imap_append, account, sent, raw, (SEEN,))
        except Exception:
            warnings.append("送信済みフォルダへ保存できませんでした。アカウント設定の送信済みフォルダを確認してください。")
    if draft:
        warning = await _discard(settings, db, draft)
        if warning:
            warnings.append(warning)
    if replied_id:
        try:
            await db.update_flags([replied_id], answered=True)
        except Exception:
            pass
    return warnings


async def _transmit(settings, db, account, raw, claim, draft, replied_id=None):
    prepare_send(account, raw)  # validation errors must not consume the one-shot claim
    await db.claim_send(claim)
    try:
        result = await asyncio.to_thread(smtp_send, account, raw)
    except NotSent as exc:
        await db.release_send(claim)
        raise ValueError(f"Not sent: {exc}. Nothing was delivered; fix the cause and send again") from None
    except Exception:
        await db.finish_send(claim, "unknown")
        raise ValueError("Send outcome not confirmed. Automatic retry blocked; check server/Sent before resending") from None
    await db.finish_send(claim, result["state"])
    warnings = await _after_send(settings, db, account, raw, draft, replied_id)
    if warnings:
        result["warnings"] = warnings
    return result


async def send_reviewed_draft(settings: Settings, db: Database, email_id: int):
    """Send a draft that already exists in Drafts, after re-checking it on the server."""
    mail = await db.detail(email_id)
    account = settings.account(mail["account_id"])
    if account.protocol == "pop3":
        if mail["folder_role"] != "drafts":
            raise ValueError("Only messages in the actual Drafts folder can be sent")
        raw = await db.raw(mail)
    else:
        raw = await asyncio.to_thread(fetch_reviewed_draft, account, mail, settings.max_message_bytes)
    return await _transmit(settings, db, account, raw, mail, mail)


async def send_now(settings: Settings, db: Database, data: DraftInput):
    """Send a message composed in the Web UI by the authenticated user."""
    account, raw = await compose(settings, db, data)
    old = await _replaced_draft(settings, db, data, account)
    claim = {"account_id": account.id, "message_id": parse_mail(raw)["message_id"], "id": None}
    return await _transmit(settings, db, account, raw, claim, old, data.reply_to_email_id)
