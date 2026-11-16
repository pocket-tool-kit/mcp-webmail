"""Mail operations shared by the Web API and (permission-gated) MCP tools.

IMAP accounts change the server first and then mirror the change in the
cache; POP3 accounts only have local state.
"""
from __future__ import annotations

import asyncio
import base64
from collections import defaultdict

from .config import Settings
from .db import Database
from .imap_sync import imap_delete, imap_fetch_raw, imap_move, imap_set_flags
from .mail_parser import extract_attachment

MAX_BATCH = 500
INLINE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
MAX_INLINE_BYTES = 8_000_000


async def _groups(settings: Settings, db: Database, email_ids):
    email_ids = list(dict.fromkeys(int(i) for i in email_ids))
    if not 1 <= len(email_ids) <= MAX_BATCH:
        raise ValueError("Select between 1 and 500 emails")
    rows = await db.details(email_ids)
    if len(rows) != len(email_ids):
        raise ValueError("Email not found; refresh the list")
    groups = defaultdict(list)
    for row in rows:
        groups[(row["account_id"], row["folder"])].append(row)
    return [(settings.account(account_id), folder, mails) for (account_id, folder), mails in groups.items()]


def _uids(mails):
    return [m["uid"] for m in mails]


def _ids(mails):
    return [m["id"] for m in mails]


async def set_flags(settings, db, email_ids, seen=None, flagged=None):
    if seen is None and flagged is None:
        raise ValueError("Nothing to change")
    count = 0
    for account, folder, mails in await _groups(settings, db, email_ids):
        if account.protocol == "imap":
            await asyncio.to_thread(imap_set_flags, account, folder, mails[0]["uidvalidity"], _uids(mails), seen, flagged)
        await db.update_flags(_ids(mails), seen=seen, flagged=flagged)
        count += len(mails)
    return {"updated": count}


async def _move_group(db, account, folder, mails, target):
    if target == folder:
        return
    if account.protocol == "imap":
        await asyncio.to_thread(imap_move, account, folder, mails[0]["uidvalidity"], _uids(mails), target)
        # The messages get new UIDs in the target; the next sync caches them there.
        await db.delete_emails(_ids(mails))
    else:
        if target not in {b["name"] for b in await db.mailboxes(account.id)}:
            raise ValueError("移動先フォルダがありません。")
        await db.local_move(_ids(mails), target)


async def move(settings, db, email_ids, target: str):
    if not target or any(c in target for c in "\r\n\x00"):
        raise ValueError("Invalid target folder")
    count = 0
    for account, folder, mails in await _groups(settings, db, email_ids):
        await _move_group(db, account, folder, mails, target)
        count += len(mails)
    return {"moved": count, "folder": target}


async def archive(settings, db, email_ids):
    count = 0
    for account, folder, mails in await _groups(settings, db, email_ids):
        # Gmail has no Archive folder: archiving means "only in All Mail".
        target = await db.role_folder(account.id, "archive", "all")
        if not target:
            raise ValueError("アーカイブ用フォルダが見つかりません。アカウント設定でアーカイブフォルダを指定してください。")
        await _move_group(db, account, folder, mails, target)
        count += len(mails)
    return {"moved": count}


async def delete(settings, db, email_ids, permanent=False):
    """Move to Trash; messages already in Trash (or permanent=True) are removed for good."""
    result = {"trashed": 0, "deleted": 0}
    for account, folder, mails in await _groups(settings, db, email_ids):
        trash = await db.role_folder(account.id, "trash")
        if not permanent and trash and folder != trash:
            await _move_group(db, account, folder, mails, trash)
            result["trashed"] += len(mails)
            continue
        if not permanent and not trash:
            raise ValueError("ごみ箱フォルダが見つかりません。アカウント設定でごみ箱フォルダを指定するか、完全に削除してください。")
        if account.protocol == "imap":
            await asyncio.to_thread(imap_delete, account, folder, mails[0]["uidvalidity"], _uids(mails))
        await db.delete_emails(_ids(mails))
        result["deleted"] += len(mails)
    return result


async def fetch_raw(settings, db, mail) -> bytes:
    account = settings.account(mail["account_id"])
    if account.protocol == "pop3":
        return await db.raw(mail)
    return await asyncio.to_thread(imap_fetch_raw, account, mail["folder"], mail["uidvalidity"], mail["uid"],
                                   settings.max_message_bytes)


async def attachment(settings, db, email_id: int, index: int):
    mail = await db.detail(email_id)
    return extract_attachment(await fetch_raw(settings, db, mail), index)


async def inline_images(settings, db, email_id: int) -> dict:
    """cid -> data: URI for images referenced by an HTML mail (bounded)."""
    mail = await db.detail(email_id)
    wanted = [a for a in mail["attachments"] if a["cid"] and a["content_type"] in INLINE_IMAGE_TYPES]
    if not wanted:
        return {}
    raw = await fetch_raw(settings, db, mail)
    result, total = {}, 0
    for item in wanted:
        info, content = extract_attachment(raw, item["index"])
        total += len(content)
        if total > MAX_INLINE_BYTES:
            break
        result[info["cid"]] = f"data:{info['content_type']};base64," + base64.b64encode(content).decode("ascii")
    return result
