from __future__ import annotations

import asyncio
import json
import re
import smtplib
import socket
import ssl
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses, make_msgid

from email_validator import validate_email
from pydantic import Field, field_validator

from .config import Account, Settings, StrictModel
from .db import Database
from .imap_sync import drafts_folder, imap_connection
from .mail_parser import parse_mail, parse_message, parse_recipients


class NotSent(Exception):
    """The SMTP transaction certainly did not deliver the message (safe to retry)."""


class DraftInput(StrictModel):
    account_id: str
    to: list[str] = Field(min_length=1, max_length=50)
    subject: str = Field(max_length=998)
    body: str = Field(max_length=1_000_000)
    reply_to_email_id: int | None = Field(default=None, gt=0)

    @field_validator("subject")
    @classmethod
    def no_injection(cls, value):
        if any(c in value for c in "\r\n\x00"):
            raise ValueError("Invalid subject")
        return value

    @field_validator("to")
    @classmethod
    def valid_recipients(cls, values):
        return [validate_email(v, check_deliverability=False, allow_smtputf8=False).normalized for v in values]


def build_draft(account: Account, data: DraftInput, parent=None) -> bytes:
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = str(account.email)
    msg["To"] = ", ".join(data.to)
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
    return msg.as_bytes()  # SMTP policy guarantees CRLF including multipart boundaries.


def append_draft(account, raw):
    with imap_connection(account) as client:
        folder = drafts_folder(client, account)
        client.append(folder, raw, flags=(b"\\Draft",))
        return folder


async def create_draft(settings: Settings, db: Database, data: DraftInput):
    account = settings.account(data.account_id)
    parent = await db.detail(data.reply_to_email_id) if data.reply_to_email_id else None
    if parent and parent["account_id"] != account.id:
        raise ValueError("Reply account must match original email")
    raw = build_draft(account, data, parent)
    try:
        folder = await asyncio.to_thread(append_draft, account, raw)
    except Exception:
        # APPEND may have succeeded before disconnect. Never retry automatically.
        raise ValueError("Draft save not confirmed; check Drafts before retrying") from None
    return {"saved": True, "account_id": account.id, "folder": folder,
            "message_id": parse_mail(raw)["message_id"], "note": "Appears after next Web sync; not sent"}


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
    if not 1 <= len(reviewed) <= 50:
        raise ValueError("Invalid recipient count")
    recipients = [validate_email(a, check_deliverability=False, allow_smtputf8=False).normalized for a in reviewed]
    # SMTP sends the original MIME structure, including attachments. Bcc is
    # envelope-only and is removed from the transmitted message.
    if "Bcc" in msg:
        del msg["Bcc"]
    return msg, recipients


def _not_sent_reason(exc):
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


def smtp_send(account, raw):
    msg, recipients = prepare_send(account, raw)
    endpoint = account.smtp
    context = ssl.create_default_context()
    client = None
    try:
        # Phase 1: connect / TLS / login. Nothing can have been delivered yet.
        try:
            client = (smtplib.SMTP_SSL(endpoint.host, endpoint.port, timeout=30, context=context)
                      if endpoint.security == "tls" else smtplib.SMTP(endpoint.host, endpoint.port, timeout=30))
            client.ehlo()
            if endpoint.security == "starttls":
                client.starttls(context=context)
                client.ehlo()
            client.login(endpoint.username, endpoint.password.get_secret_value())
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


async def send_reviewed_draft(settings: Settings, db: Database, email_id: int):
    mail = await db.detail(email_id)
    account = settings.account(mail["account_id"])
    if mail["has_attachments"]:
        raise ValueError("Attachment review is not supported; send this draft from another client")
    raw = await asyncio.to_thread(fetch_reviewed_draft, account, mail, settings.max_message_bytes)
    prepare_send(account, raw)  # validation errors must not consume the one-shot claim
    await db.claim_send(mail)
    try:
        result = await asyncio.to_thread(smtp_send, account, raw)
    except NotSent as exc:
        await db.release_send(email_id)
        raise ValueError(f"Not sent: {exc}. Nothing was delivered; fix the cause and send again") from None
    except Exception:
        await db.finish_send(email_id, "unknown")
        raise ValueError("Send outcome not confirmed. Automatic retry blocked; check server/Sent before resending") from None
    await db.finish_send(email_id, result["state"])
    return result
