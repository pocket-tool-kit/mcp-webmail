from __future__ import annotations

import asyncio
import imaplib
import logging
import poplib
import socket
import ssl
from contextlib import contextmanager

from imapclient import IMAPClient
from imapclient.exceptions import LoginError

from .config import Account, Settings
from .db import FLAG_ANSWERED, FLAG_FLAGGED, FLAG_SEEN, Database
from .mail_parser import parse_mail, placeholder
from .oauth import OAuthError, TOKENS

log = logging.getLogger(__name__)

SEEN, FLAGGED, ANSWERED, DELETED, DRAFT = b"\\Seen", b"\\Flagged", b"\\Answered", b"\\Deleted", b"\\Draft"
ROLE_FLAGS = {"\\drafts": "drafts", "\\sent": "sent", "\\trash": "trash", "\\junk": "junk",
              "\\archive": "archive", "\\all": "all"}
# Used only when the server does not advertise SPECIAL-USE and exactly one name matches.
ROLE_NAMES = {
    "drafts": {"drafts", "inbox.drafts", "[gmail]/drafts", "[gmail]/下書き", "下書き"},
    "sent": {"sent", "sent items", "sent messages", "sent mail", "inbox.sent", "[gmail]/sent mail",
             "[gmail]/送信済みメール", "送信済み", "送信済みメール", "送信済みアイテム"},
    "trash": {"trash", "deleted items", "deleted messages", "inbox.trash", "[gmail]/trash", "[gmail]/ゴミ箱",
              "ゴミ箱", "ごみ箱", "削除済みアイテム"},
    "junk": {"junk", "spam", "junk e-mail", "junk email", "inbox.junk", "[gmail]/spam", "[gmail]/迷惑メール", "迷惑メール"},
    "archive": {"archive", "archives", "inbox.archive", "アーカイブ"},
}


class FolderMissing(Exception):
    pass


def tls_context():
    return ssl.create_default_context()


def open_imap(account: Account) -> IMAPClient:
    endpoint = account.imap
    client = IMAPClient(endpoint.host, port=endpoint.port,
                        ssl=endpoint.security == "tls", ssl_context=tls_context(), timeout=30)
    try:
        if endpoint.security == "starttls":
            client.starttls(tls_context())
        if account.auth == "oauth2":
            client.oauth2_login(endpoint.username, TOKENS.access_token(account))
        else:
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


def _flag_names(flags):
    return {(f.decode("ascii", "replace") if isinstance(f, bytes) else str(f)).lower() for f in flags}


def drafts_folder(client, account: Account) -> str:
    folders = client.list_folders()  # imapclient transparently handles modified UTF-7.
    names = [name for _, _, name in folders]
    if account.drafts_folder:
        if account.drafts_folder not in names:
            raise ValueError("Configured drafts_folder does not exist on server")
        return account.drafts_folder
    for flags, _, name in folders:
        if "\\drafts" in _flag_names(flags):
            return name
    candidates = [n for n in names if n.lower() in ROLE_NAMES["drafts"]]
    if len(candidates) == 1:
        return candidates[0]
    raise ValueError("Cannot identify Drafts; set drafts_folder to exact server folder name")


def list_mailboxes(client, account: Account) -> list[dict]:
    """All selectable folders with a role: explicit setting, SPECIAL-USE, then a unique known name."""
    listed = [(_flag_names(flags), name) for flags, _, name in client.list_folders()]
    boxes = [{"name": name, "role": "inbox" if name.upper() == "INBOX" else "", "flags": flags}
             for flags, name in listed if "\\noselect" not in flags and "\\nonexistent" not in flags]
    names = {b["name"] for b in boxes}
    configured = {"drafts": account.drafts_folder, "sent": account.sent_folder,
                  "trash": account.trash_folder, "archive": account.archive_folder}
    taken = set()
    for role, name in configured.items():
        if name and name in names:
            next(b for b in boxes if b["name"] == name)["role"] = role
            taken.add(role)
    for box in boxes:
        if box["role"]:
            continue
        for flag, role in ROLE_FLAGS.items():
            if flag in box["flags"] and role not in taken:
                box["role"] = role
                taken.add(role)
                break
    for role, known in ROLE_NAMES.items():
        if role in taken:
            continue
        candidates = [b for b in boxes if not b["role"] and b["name"].lower() in known]
        if len(candidates) == 1:
            candidates[0]["role"] = role
    return [{"name": b["name"], "role": b["role"]} for b in boxes]


def list_folders_and_drafts(client, account):
    available = [name for _, _, name in client.list_folders()]
    try:
        draft = drafts_folder(client, account)
    except ValueError:
        draft = None
    return available, draft


def _snapshot(client, account, folder, previous, known, settings):
    selected = client.select_folder(folder, readonly=True)
    validity = int(selected[b"UIDVALIDITY"])
    all_uids = client.search(["ALL"])
    flags = {}
    # Chunk to avoid huge IMAP command lines and response buffers.
    for start in range(0, len(all_uids), 500):
        for uid, item in client.fetch(all_uids[start:start + 500], ["FLAGS"]).items():
            present = item.get(b"FLAGS", ())
            flags[uid] = ((FLAG_SEEN if SEEN in present else 0) | (FLAG_FLAGGED if FLAGGED in present else 0)
                          | (FLAG_ANSWERED if ANSWERED in present else 0))
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


# --- mailbox changes requested by the user -------------------------------
def _select_checked(client, folder, uidvalidity, readonly=False):
    selected = client.select_folder(folder, readonly=readonly)
    if int(selected[b"UIDVALIDITY"]) != uidvalidity:
        raise ValueError("フォルダの状態が変わりました。同期後にもう一度操作してください。")


def _capable(client, name):
    try:
        return bool(client.has_capability(name))
    except Exception:
        return False


def _expunge(client, uids):
    if _capable(client, "UIDPLUS"):
        client.add_flags(uids, [DELETED], silent=True)
        client.expunge(uids)  # UID EXPUNGE: only these messages
        return
    # Plain EXPUNGE removes every \\Deleted message in the folder. Messages that
    # another client only marked as deleted must survive, so their mark is
    # lifted for the duration of the EXPUNGE and then restored.
    wanted = set(uids)
    others = [uid for uid in client.search(["DELETED"]) if uid not in wanted]
    if others:
        client.remove_flags(others, [DELETED], silent=True)
    try:
        client.add_flags(uids, [DELETED], silent=True)
        client.expunge()
    finally:
        if others:
            client.add_flags(others, [DELETED], silent=True)


def imap_set_flags(account, folder, uidvalidity, uids, seen=None, flagged=None):
    with imap_connection(account) as client:
        _select_checked(client, folder, uidvalidity)
        for value, flag in ((seen, SEEN), (flagged, FLAGGED)):
            if value is True:
                client.add_flags(uids, [flag], silent=True)
            elif value is False:
                client.remove_flags(uids, [flag], silent=True)


def imap_move(account, folder, uidvalidity, uids, target):
    with imap_connection(account) as client:
        if target not in [name for _, _, name in client.list_folders()]:
            raise ValueError("移動先フォルダがサーバーにありません。")
        _select_checked(client, folder, uidvalidity)
        if _capable(client, "MOVE"):
            client.move(uids, target)
        else:
            client.copy(uids, target)
            _expunge(client, uids)


def imap_delete(account, folder, uidvalidity, uids):
    with imap_connection(account) as client:
        _select_checked(client, folder, uidvalidity)
        _expunge(client, uids)


def imap_fetch_raw(account, folder, uidvalidity, uid, max_bytes):
    with imap_connection(account) as client:
        _select_checked(client, folder, uidvalidity, readonly=True)
        size = client.fetch([uid], ["RFC822.SIZE"]).get(uid, {}).get(b"RFC822.SIZE")
        if not isinstance(size, int):
            raise ValueError("メールがサーバーに見つかりません。同期してください。")
        if size > max_bytes:
            raise ValueError("メールがサイズ上限を超えています。")
        raw = client.fetch([uid], ["BODY.PEEK[]"]).get(uid, {}).get(b"BODY[]")
        if not raw:
            raise ValueError("メールがサーバーに見つかりません。同期してください。")
        return raw


def imap_append(account, folder, raw, flags):
    with imap_connection(account) as client:
        client.append(folder, raw, flags=flags)


# --- POP3 -------------------------------------------------------------------
def open_pop(account: Account):
    endpoint = account.imap
    if endpoint.security == "tls":
        client = poplib.POP3_SSL(endpoint.host, endpoint.port, timeout=30, context=tls_context())
    else:
        client = poplib.POP3(endpoint.host, endpoint.port, timeout=30)
    try:
        if endpoint.security == "starttls":
            client.stls(context=tls_context())
        client.user(endpoint.username)
        client.pass_(endpoint.password.get_secret_value())
    except BaseException:
        close_pop(client)
        raise
    return client


def close_pop(client):
    try:
        client.quit()
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def pop_fetch(account, known, settings):
    """Download messages not seen before. Nothing is ever deleted on the server."""
    client = open_pop(account)
    try:
        listing = {}
        for line in client.uidl()[1]:
            number, _, uidl = line.decode("utf-8", "replace").partition(" ")
            if uidl:
                listing[int(number)] = uidl
        sizes = {}
        for line in client.list()[1]:
            number, _, size = line.decode("ascii", "replace").partition(" ")
            sizes[int(number)] = int(size)
        items = []
        # Higher message numbers are newer.
        for number in sorted((n for n, u in listing.items() if u not in known), reverse=True)[:settings.sync_batch]:
            if sizes.get(number, 0) > settings.max_message_bytes:
                items.append((listing[number], placeholder("[Message exceeds size limit]", "Content not cached.",
                                                           oversize_limit=settings.max_message_bytes), None))
                continue
            raw = b"\r\n".join(client.retr(number)[1]) + b"\r\n"
            try:
                items.append((listing[number], parse_mail(raw), raw))
            except Exception:
                log.warning("MIME parsing failed account=%s", account.id)
                items.append((listing[number], placeholder("[MIME parsing failed]", "Open in another mail client."), raw))
        return items
    finally:
        close_pop(client)


def describe_error(exc) -> str:
    """Short diagnostic category; never includes server text or credentials."""
    if isinstance(exc, OAuthError):
        return str(exc)  # already a fixed, safe message
    checks = [
        (LoginError, "認証失敗"), (poplib.error_proto, "POP3エラー（認証失敗など）"),
        (FolderMissing, "フォルダがサーバーにありません"),
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


def check_incoming(account: Account) -> dict:
    """Log in to the incoming server; used by the account form."""
    try:
        if account.protocol == "pop3":
            close_pop(open_pop(account))
            return {"ok": True, "folders": ["INBOX"]}
        with imap_connection(account) as client:
            return {"ok": True, "folders": [b["name"] for b in list_mailboxes(client, account)]}
    except Exception as exc:
        return {"ok": False, "error": describe_error(exc)}


class SyncService:
    def __init__(self, settings: Settings, db: Database):
        self.settings, self.db = settings, db
        self.wake = asyncio.Event()
        self.stopping = False
        self.status = {}

    async def sync_pop(self, account):
        status = {"ok": True, "drafts_folder": "Drafts", "folders": {}}
        try:
            await self.db.ensure_local_folders(account.id)
            known = await self.db.known_uidls(account.id)
            items = await asyncio.to_thread(pop_fetch, account, known, self.settings)
            await self.db.apply_pop(account.id, items)
            status["folders"]["INBOX"] = {"ok": True}
        except Exception as exc:
            status["ok"] = False
            status["error"] = describe_error(exc)
            log.warning("Sync failed account=%s type=%s", account.id, type(exc).__name__)
        self.status[account.id] = status

    async def sync_account(self, account):
        if not account.credentials_ready:
            message = ("アカウント設定でロック解除、またはOAuthサインインを行ってください。" if account.auth == "oauth2"
                       else "アカウント設定でマスターパスワードを入力してください。")
            self.status[account.id] = {"ok": False, "error": message, "locked": True}
            return
        if account.protocol == "pop3":
            await self.sync_pop(account)
            return
        status = {"ok": True, "drafts_folder": None, "folders": {}}
        client = None
        try:
            client = await asyncio.to_thread(open_imap, account)  # one login per account per cycle
            boxes = await asyncio.to_thread(list_mailboxes, client, account)
            available = {b["name"] for b in boxes}
            if account.drafts_folder and account.drafts_folder not in available:
                draft = None
            else:
                draft = next((b["name"] for b in boxes if b["role"] == "drafts"), None)
            status["drafts_folder"] = draft
            if account.sync_all_folders:
                # "All Mail" duplicates every other folder; it stays a move target only.
                wanted = [b["name"] for b in boxes if b["role"] != "all"]
            else:
                wanted = list(dict.fromkeys(account.folders + ([draft] if draft else [])))
            await self.db.save_mailboxes(account.id, boxes, set(wanted))
            for folder in wanted:
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
            for account in list(self.settings.accounts):
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
