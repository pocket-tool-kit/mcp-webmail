from __future__ import annotations

import asyncio
import imaplib
import logging
import socket
import ssl
from contextlib import contextmanager

from imapclient import IMAPClient
from imapclient.exceptions import LoginError

from .config import Account, Settings
from .db import Database
from .mail_parser import parse_mail, placeholder

log = logging.getLogger(__name__)


class FolderMissing(Exception):
    pass


def open_imap(account: Account) -> IMAPClient:
    endpoint = account.imap
    client = IMAPClient(endpoint.host, port=endpoint.port,
                        ssl=endpoint.security == "tls", ssl_context=ssl.create_default_context(), timeout=30)
    try:
        if endpoint.security == "starttls":
            client.starttls(ssl.create_default_context())
        client.login(endpoint.username, endpoint.password.get_secret_value())
    except BaseException:
        close_imap(client)
        raise
    return client


def close_imap(client):
    try:
        client.logout()
    except Exception:
        try:
            client.shutdown()
        except Exception:
            pass


@contextmanager
def imap_connection(account: Account):
    client = open_imap(account)
    try:
        yield client
    finally:
        close_imap(client)


def drafts_folder(client, account: Account) -> str:
    folders = client.list_folders()  # imapclient transparently handles modified UTF-7.
    names = [name for _, _, name in folders]
    if account.drafts_folder:
        if account.drafts_folder not in names:
            raise ValueError("Configured drafts_folder does not exist on server")
        return account.drafts_folder
    for flags, _, name in folders:
        if any((f.decode() if isinstance(f, bytes) else f).lower() == "\\drafts" for f in flags):
            return name
    candidates = [n for n in names if n.lower() in {"drafts", "inbox.drafts", "[gmail]/drafts", "[gmail]/下書き", "下書き"}]
    if len(candidates) == 1:
        return candidates[0]
    raise ValueError("Cannot identify Drafts; set drafts_folder to exact server folder name")


def list_folders_and_drafts(client, account):
    available = [name for _, _, name in client.list_folders()]
    try:
        draft = drafts_folder(client, account)
    except ValueError:
        draft = None
    return available, draft


def discover(account):
    with imap_connection(account) as client:
        return list_folders_and_drafts(client, account)


def _snapshot(client, account, folder, previous, known, settings):
    selected = client.select_folder(folder, readonly=True)
    validity = int(selected[b"UIDVALIDITY"])
    all_uids = client.search(["ALL"])
    flags = {}
    # Chunk to avoid huge IMAP command lines and response buffers.
    for start in range(0, len(all_uids), 500):
        for uid, item in client.fetch(all_uids[start:start + 500], ["FLAGS"]).items():
            flags[uid] = b"\\Seen" in item.get(b"FLAGS", ())
    if validity != previous:
        known = set()
    new = sorted(set(flags) - known, reverse=True)[:settings.sync_batch]
    messages = {}
    for uid in new:
        # Network/protocol errors propagate: the folder is retried next cycle
        # and nothing is cached wrongly. Only content problems become placeholders.
        size = client.fetch([uid], ["RFC822.SIZE"]).get(uid, {}).get(b"RFC822.SIZE")
        if not isinstance(size, int):
            continue  # expunged meanwhile
        if size > settings.max_message_bytes:
            # Cache a bounded placeholder so an oversized email cannot starve
            # older messages; it is re-fetched if max_message_bytes is raised.
            messages[uid] = placeholder("[Message exceeds size limit]", "Content not cached.",
                                        oversize_limit=settings.max_message_bytes)
            continue
        raw = client.fetch([uid], ["BODY.PEEK[]"]).get(uid, {}).get(b"BODY[]")
        if raw is None:
            continue
        try:
            messages[uid] = parse_mail(raw)
        except Exception:
            # Any parser bug on one hostile/broken message must not block the folder.
            log.warning("MIME parsing failed account=%s uid=%s", account.id, uid)
            messages[uid] = placeholder("[MIME parsing failed]", "Open in another mail client.")
    return validity, flags, messages


def snapshot(account, folder, previous, known, settings, client=None):
    if client is not None:
        return _snapshot(client, account, folder, previous, known, settings)
    with imap_connection(account) as own:
        return _snapshot(own, account, folder, previous, known, settings)


def describe_error(exc) -> str:
    """Short diagnostic category; never includes server text or credentials."""
    checks = [
        (LoginError, "認証失敗"), (FolderMissing, "フォルダがサーバーにありません"),
        (ssl.SSLCertVerificationError, "TLS証明書エラー"), (ssl.SSLError, "TLSエラー"),
        (socket.gaierror, "ホスト名を解決できません"), (ConnectionRefusedError, "接続拒否"),
        (TimeoutError, "タイムアウト"), (imaplib.IMAP4.abort, "接続が切断されました"),
        (imaplib.IMAP4.error, "IMAPエラー"), (OSError, "通信エラー"),
    ]
    for kind, label in checks:
        if isinstance(exc, kind):
            return f"{label} ({type(exc).__name__})"
    return type(exc).__name__


def _connection_broken(exc) -> bool:
    return isinstance(exc, (OSError, imaplib.IMAP4.abort))


class SyncService:
    def __init__(self, settings: Settings, db: Database):
        self.settings, self.db = settings, db
        self.wake = asyncio.Event()
        self.stopping = False
        self.status = {}

    async def sync_account(self, account):
        if not account.imap.password.get_secret_value():
            self.status[account.id] = {"ok": False, "error": "アカウント設定でマスターパスワードを入力してください。", "locked": True}
            return
        status = {"ok": True, "drafts_folder": None, "folders": {}}
        client = None
        try:
            client = await asyncio.to_thread(open_imap, account)  # one login per account per cycle
            available, draft = await asyncio.to_thread(list_folders_and_drafts, client, account)
            status["drafts_folder"] = draft
            for folder in dict.fromkeys(account.folders + ([draft] if draft else [])):
                if self.stopping:
                    break
                try:
                    if folder not in available:
                        raise FolderMissing()
                    previous, known = await self.db.folder_state(account.id, folder, self.settings.max_message_bytes)
                    result = await asyncio.to_thread(snapshot, account, folder, previous, known, self.settings, client)
                    await self.db.apply_snapshot(account.id, folder, *result)
                    status["folders"][folder] = {"ok": True}
                except Exception as exc:
                    # One folder failing must not stop the others.
                    status["folders"][folder] = {"ok": False, "error": describe_error(exc)}
                    log.warning("Sync failed account=%s folder_error=%s", account.id, type(exc).__name__)
                    if _connection_broken(exc):
                        await asyncio.to_thread(close_imap, client)
                        client = None
                        client = await asyncio.to_thread(open_imap, account)
        except Exception as exc:
            # Do not log server text or credentials.
            status["ok"] = False
            status["error"] = describe_error(exc)
            log.warning("Sync failed account=%s type=%s", account.id, type(exc).__name__)
        finally:
            if client is not None:
                await asyncio.to_thread(close_imap, client)
        failed = {name: value["error"] for name, value in status["folders"].items() if not value["ok"]}
        if failed:
            status["ok"] = False
            detail = " / ".join(f"{name}: {error}" for name, error in failed.items())
            status["error"] = f"{status['error']} / {detail}" if "error" in status else detail
        self.status[account.id] = status

    async def run(self):
        while not self.stopping:
            self.wake.clear()
            for account in self.settings.accounts:
                if not account.enabled or self.stopping:
                    continue
                await self.sync_account(account)
            if not self.stopping:
                try:
                    await asyncio.wait_for(self.wake.wait(), self.settings.sync_interval)
                except TimeoutError:
                    pass

    def stop(self):
        self.stopping = True
        self.wake.set()
