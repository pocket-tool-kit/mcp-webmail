from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from .config import ALL_FOLDERS, DATA
from .mail_parser import PARSER_VERSION, parse_mail

# The cache is derived from IMAP. When the parser changes, cached rows are
# dropped and re-fetched (send_attempts is kept: it guards against resends).
# POP3/local mail is not re-fetchable; it is re-parsed from raw_messages.
SCHEMA_VERSION = PARSER_VERSION
FLAG_SEEN, FLAG_FLAGGED, FLAG_ANSWERED = 1, 2, 4
ROLE_ORDER = {"inbox": 0, "drafts": 1, "sent": 2, "archive": 3, "all": 4, "junk": 5, "trash": 6, "": 9}
LOCAL_FOLDERS = [("INBOX", "inbox"), ("Drafts", "drafts"), ("Sent", "sent"), ("Archive", "archive"), ("Trash", "trash")]
SCHEMA = [
    """CREATE TABLE IF NOT EXISTS emails (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 account_id TEXT NOT NULL, folder TEXT NOT NULL, uid INTEGER NOT NULL,
 message_id TEXT NOT NULL DEFAULT '', in_reply_to TEXT NOT NULL DEFAULT '',
 subject TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT '',
 recipients TEXT NOT NULL DEFAULT '[]', date_ts INTEGER NOT NULL DEFAULT 0,
 body_text TEXT NOT NULL DEFAULT '', body_html TEXT NOT NULL DEFAULT '',
 has_attachments BOOLEAN NOT NULL DEFAULT 0, is_seen BOOLEAN NOT NULL DEFAULT 0,
 references_header TEXT NOT NULL DEFAULT '', reply_to TEXT NOT NULL DEFAULT '',
 oversize_limit INTEGER NOT NULL DEFAULT 0,
 is_flagged BOOLEAN NOT NULL DEFAULT 0, is_answered BOOLEAN NOT NULL DEFAULT 0,
 attachments TEXT NOT NULL DEFAULT '[]',
 UNIQUE(account_id, folder, uid)
)""",
    "CREATE INDEX IF NOT EXISTS emails_date ON emails(date_ts DESC, id DESC)",
    "CREATE INDEX IF NOT EXISTS emails_thread ON emails(account_id, message_id)",
    # One row per folder the server lists. uidvalidity stays NULL until the
    # folder has been synchronized; role is a SPECIAL-USE style label.
    """CREATE TABLE IF NOT EXISTS folders (
 account_id TEXT NOT NULL, folder TEXT NOT NULL, uidvalidity INTEGER,
 role TEXT NOT NULL DEFAULT '', synced BOOLEAN NOT NULL DEFAULT 1,
 PRIMARY KEY(account_id, folder)
)""",
    # POP3 has no folders or server-side state: messages are kept locally.
    """CREATE TABLE IF NOT EXISTS raw_messages (
 account_id TEXT NOT NULL, folder TEXT NOT NULL, uid INTEGER NOT NULL, raw BLOB NOT NULL,
 PRIMARY KEY(account_id, folder, uid)
)""",
    """CREATE TABLE IF NOT EXISTS pop_uidl (
 account_id TEXT NOT NULL, uidl TEXT NOT NULL, PRIMARY KEY(account_id, uidl)
)""",
    # Keyed by (account_id, Message-ID) only. emails.id is NOT stable: a cache
    # rebuild drops the table and AUTOINCREMENT restarts, so ids get reused.
    # email_id is kept for information only.
    """CREATE TABLE IF NOT EXISTS send_attempts (
 account_id TEXT NOT NULL, message_id TEXT NOT NULL, email_id INTEGER,
 state TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(account_id, message_id)
)""",
]
# v0.2 and earlier used email_id as the primary key.
LEGACY_SEND_ATTEMPTS_MIGRATION = [
    "ALTER TABLE send_attempts RENAME TO send_attempts_legacy",
    SCHEMA[-1],
    """INSERT OR IGNORE INTO send_attempts(account_id,message_id,email_id,state,created_at)
 SELECT account_id,message_id,email_id,state,COALESCE(created_at,CURRENT_TIMESTAMP)
 FROM send_attempts_legacy WHERE message_id<>''""",
    "DROP TABLE send_attempts_legacy",
]
CONTENT_COLUMNS = ["message_id", "in_reply_to", "subject", "sender", "recipients", "date_ts", "body_text",
                   "body_html", "has_attachments", "references_header", "reply_to", "oversize_limit", "attachments"]
_DEFAULTS = {"oversize_limit": 0, "attachments": "[]"}
INSERT_SQL = (f"INSERT INTO emails(account_id,folder,uid,is_seen,is_flagged,is_answered,{','.join(CONTENT_COLUMNS)}) "
              f"VALUES({','.join('?' for _ in range(6 + len(CONTENT_COLUMNS)))}) "
              f"ON CONFLICT(account_id,folder,uid) DO UPDATE SET "
              + ",".join(f"{c}=excluded.{c}" for c in CONTENT_COLUMNS))
MAX_THREAD = 500


def _content(mail):
    return tuple(mail.get(c, _DEFAULTS[c]) if c in _DEFAULTS else mail[c] for c in CONTENT_COLUMNS)


def _thread_component(headers, seed):
    """Connected component over shared Message-ID tokens (CPU work, off-loop)."""
    def ids(value):
        return set(re.findall(r"<[^<>\s]+>", value))
    tokens = {r["id"]: ids(r["message_id"] + " " + r["in_reply_to"] + " " + r["references_header"]) for r in headers}
    by_token = defaultdict(list)
    for key, values in tokens.items():
        for token in values:
            by_token[token].append(key)
    chosen, queue, visited = {seed}, [seed], set()
    while queue:
        for token in tokens.get(queue.pop(), ()):
            if token in visited:
                continue
            visited.add(token)
            for other in by_token[token]:
                if other not in chosen:
                    chosen.add(other)
                    if len(chosen) > MAX_THREAD:
                        raise ValueError("Thread exceeds 500 messages; narrow with search")
                    queue.append(other)
    return chosen


class Database:
    def __init__(self, path: Path | None = None):
        self.path = path or DATA / "mail.db"

    @asynccontextmanager
    async def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        async with aiosqlite.connect(self.path, timeout=5) as db:
            db.row_factory = aiosqlite.Row
            # journal_mode=WAL is persistent in the file and set once in initialize().
            await db.execute("PRAGMA busy_timeout=5000")
            try:
                yield db
            except BaseException:
                await db.rollback()
                raise

    async def initialize(self):
        async with self.connect() as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("BEGIN IMMEDIATE")
            version = (await (await db.execute("PRAGMA user_version")).fetchone())[0]
            rebuild = version < SCHEMA_VERSION
            local = []
            if rebuild:
                # Concurrent starters serialize on BEGIN IMMEDIATE; only the first rebuilds.
                tables = {r[0] for r in await (await db.execute("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
                if {"emails", "raw_messages"} <= tables:
                    # Local-only mail keeps its flags across the rebuild.
                    local = await (await db.execute(
                        "SELECT r.account_id,r.folder,r.uid,r.raw,e.is_seen,e.is_flagged,e.is_answered FROM raw_messages r "
                        "JOIN emails e USING(account_id,folder,uid)")).fetchall()
                await db.execute("DROP TABLE IF EXISTS emails")
                if "folders" in tables:
                    kept = await (await db.execute(
                        "SELECT account_id,folder,role FROM folders WHERE (account_id,folder) IN "
                        "(SELECT account_id,folder FROM raw_messages)")).fetchall() if "raw_messages" in tables else []
                    await db.execute("DROP TABLE folders")
                else:
                    kept = []
            columns = await (await db.execute("PRAGMA table_info(send_attempts)")).fetchall()
            if any(c["name"] == "email_id" and c["pk"] for c in columns):
                for statement in LEGACY_SEND_ATTEMPTS_MIGRATION:
                    await db.execute(statement)
            for statement in SCHEMA:
                await db.execute(statement)
            if rebuild:
                for row in kept:
                    await db.execute("INSERT OR IGNORE INTO folders(account_id,folder,uidvalidity,role) VALUES(?,?,1,?)", tuple(row))
                for account_id, folder, uid, raw, seen, flagged, answered in local:
                    try:
                        mail = parse_mail(bytes(raw))
                    except Exception:
                        continue
                    await db.execute(INSERT_SQL, (account_id, folder, uid, seen, flagged, answered, *_content(mail)))
                await db.execute(f"PRAGMA user_version={int(SCHEMA_VERSION)}")
            await db.commit()

    async def rows(self, sql, args=()):
        async with self.connect() as db:
            async with db.execute(sql, args) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    async def folder_state(self, account_id, folder, max_bytes=None):
        state = await self.rows("SELECT uidvalidity FROM folders WHERE account_id=? AND folder=?", (account_id, folder))
        ids = await self.rows("SELECT uid, oversize_limit FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
        # An oversize placeholder cached under a smaller limit is re-fetched once
        # the limit is raised.
        known = {r["uid"] for r in ids
                 if not (max_bytes is not None and 0 < r["oversize_limit"] < max_bytes)}
        return (state[0]["uidvalidity"] if state else None), known

    async def apply_snapshot(self, account_id, folder, uidvalidity, flags, messages):
        """flags maps uid -> bitmask of FLAG_* (a plain bool means "seen")."""
        # IMAP I/O has already completed. A short single write transaction makes
        # UIDVALIDITY reset, pruning, flag updates and inserts visible atomically.
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            cursor = await db.execute("SELECT uidvalidity FROM folders WHERE account_id=? AND folder=?", (account_id, folder))
            previous = await cursor.fetchone()
            if previous and previous[0] is not None and previous[0] != uidvalidity:
                await db.execute("DELETE FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
            await db.execute("INSERT INTO folders(account_id,folder,uidvalidity) VALUES(?,?,?) ON CONFLICT(account_id,folder) "
                             "DO UPDATE SET uidvalidity=excluded.uidvalidity, synced=1", (account_id, folder, uidvalidity))
            cursor = await db.execute("SELECT uid, is_seen, is_flagged, is_answered FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
            current = {r[0]: (bool(r[1]), bool(r[2]), bool(r[3])) for r in await cursor.fetchall()}
            stale = [(account_id, folder, uid) for uid in current if uid not in flags]
            await db.executemany("DELETE FROM emails WHERE account_id=? AND folder=? AND uid=?", stale)
            bits = {uid: int(value) for uid, value in flags.items()}
            # Write only flags that actually changed; large folders stay cheap.
            changed = [(bits[uid] & FLAG_SEEN, account_id, folder, uid) for uid in bits
                       if uid in current and current[uid][0] != bool(bits[uid] & FLAG_SEEN)]
            await db.executemany("UPDATE emails SET is_seen=? WHERE account_id=? AND folder=? AND uid=?", changed)
            marks = [(bool(bits[uid] & FLAG_FLAGGED), bool(bits[uid] & FLAG_ANSWERED), account_id, folder, uid) for uid in bits
                     if uid in current and current[uid][1:] != (bool(bits[uid] & FLAG_FLAGGED), bool(bits[uid] & FLAG_ANSWERED))]
            if marks:
                await db.executemany("UPDATE emails SET is_flagged=?, is_answered=? WHERE account_id=? AND folder=? AND uid=?", marks)
            # IMAP content for a UID is immutable, so replacing a row only happens
            # for re-fetches (e.g. an oversize placeholder after raising the limit).
            await db.executemany(INSERT_SQL, [
                (account_id, folder, uid, bits[uid] & FLAG_SEEN, bool(bits[uid] & FLAG_FLAGGED),
                 bool(bits[uid] & FLAG_ANSWERED), *_content(mail))
                for uid, mail in messages.items() if uid in bits])
            await db.commit()

    async def save_mailboxes(self, account_id, mailboxes, synced):
        """Record the server's folder list and drop cache for folders no longer synced."""
        names = {m["name"] for m in mailboxes}
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            cursor = await db.execute("SELECT folder FROM folders WHERE account_id=?", (account_id,))
            for (folder,) in await cursor.fetchall():
                if folder not in names:
                    await db.execute("DELETE FROM folders WHERE account_id=? AND folder=?", (account_id, folder))
                if folder not in names or folder not in synced:
                    await db.execute("DELETE FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
            for box in mailboxes:
                keep = box["name"] in synced
                await db.execute(
                    "INSERT INTO folders(account_id,folder,uidvalidity,role,synced) VALUES(?,?,NULL,?,?) "
                    "ON CONFLICT(account_id,folder) DO UPDATE SET role=excluded.role, synced=excluded.synced, "
                    "uidvalidity=CASE WHEN excluded.synced THEN uidvalidity ELSE NULL END",
                    (account_id, box["name"], box["role"], keep))
            await db.commit()

    async def mailboxes(self, account_id):
        rows = await self.rows("SELECT folder AS name, role, synced FROM folders WHERE account_id=?", (account_id,))
        return sorted(rows, key=lambda r: (ROLE_ORDER.get(r["role"], 9), r["name"].lower()))

    async def role_folder(self, account_id, *roles):
        for role in roles:
            rows = await self.rows("SELECT folder FROM folders WHERE account_id=? AND role=? ORDER BY folder LIMIT 1", (account_id, role))
            if rows:
                return rows[0]["folder"]
        return None

    async def search(self, query="", account_id=None, limit=20, folder=None, offset=0,
                     unread=False, flagged=False, attachments=False):
        if not 1 <= limit <= 200 or offset < 0 or len(query) > 500:
            raise ValueError("Invalid search bounds")
        clauses, args = [], []
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' OR body_text LIKE ? ESCAPE '\\' "
                           "OR recipients LIKE ? ESCAPE '\\')")
            # recipients is JSON text: escape the needle the same way json.dumps does.
            needle = json.dumps(query, ensure_ascii=False)[1:-1].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            args.extend([f"%{escaped}%"] * 3 + [f"%{needle}%"])
        for name, value in (("account_id", account_id), ("folder", folder)):
            if value is not None:
                clauses.append(f"{name}=?")
                args.append(value)
        for enabled, clause in ((unread, "is_seen=0"), (flagged, "is_flagged=1"), (attachments, "has_attachments=1")):
            if enabled:
                clauses.append(clause)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return await self.rows(
            "SELECT id,account_id,folder,uid,subject,sender,recipients,date_ts,is_seen,is_flagged,is_answered,has_attachments,"
            "substr(body_text,1,180) AS snippet FROM emails" + where + " ORDER BY date_ts DESC,id DESC LIMIT ? OFFSET ?",
            (*args, limit, offset))

    DETAIL_SQL = ("SELECT e.*, f.uidvalidity, f.role AS folder_role, (SELECT state FROM send_attempts s WHERE e.message_id<>'' AND "
                  "s.account_id=e.account_id AND s.message_id=e.message_id) AS send_state "
                  "FROM emails e JOIN folders f USING(account_id,folder) WHERE e.id IN ({})")

    async def details(self, email_ids):
        email_ids = list(email_ids)
        if not email_ids:
            return []
        rows = await self.rows(self.DETAIL_SQL.format(",".join("?" for _ in email_ids)), email_ids)
        for row in rows:
            row["recipients"] = json.loads(row["recipients"])
            row["attachments"] = json.loads(row["attachments"])
        return rows

    async def detail(self, email_id):
        rows = await self.details([email_id])
        if not rows:
            raise ValueError("Email not found")
        return rows[0]

    async def stats(self, accounts):
        result = []
        for account in accounts:
            counts = await self.rows("SELECT folder,count(*) AS total,sum(CASE WHEN is_seen=0 THEN 1 ELSE 0 END) AS unread FROM emails WHERE account_id=? GROUP BY folder", (account.id,))
            boxes = await self.mailboxes(account.id)
            roles = {b["name"]: b["role"] for b in boxes}
            by_name = {r["folder"]: r for r in counts}
            # Include folders before their first email arrives.
            for name in set(f for f in account.folders if f != ALL_FOLDERS) | {b["name"] for b in boxes if b["synced"]}:
                by_name.setdefault(name, {"folder": name, "total": 0, "unread": 0})
            for name, row in by_name.items():
                row["role"] = roles.get(name, "inbox" if name.upper() == "INBOX" else "")
            result.append({"id": account.id, "name": account.name, "email": str(account.email),
                           "enabled": account.enabled, "protocol": account.protocol,
                           "folders": sorted(by_name.values(), key=lambda x: (ROLE_ORDER.get(x["role"], 9), x["folder"].lower())),
                           "mailboxes": [{"name": b["name"], "role": b["role"]} for b in boxes],
                           "total": sum(r["total"] for r in counts), "unread": sum(r["unread"] for r in counts)})
        return result

    async def thread(self, email_id):
        seed = await self.detail(email_id)
        # Header-only graph first, bodies only for connected messages. Bound a
        # corrupt/hostile graph; never merge messages from different accounts.
        headers = await self.rows("SELECT id,message_id,in_reply_to,references_header FROM emails WHERE account_id=?", (seed["account_id"],))
        chosen = await asyncio.to_thread(_thread_component, headers, email_id)
        result = await self.details(chosen)
        return sorted(result, key=lambda r: (r["date_ts"], r["id"]))

    # --- local mutations -------------------------------------------------
    async def update_flags(self, email_ids, seen=None, flagged=None, answered=None):
        updates = [(name, int(value)) for name, value in
                   (("is_seen", seen), ("is_flagged", flagged), ("is_answered", answered)) if value is not None]
        email_ids = list(email_ids)
        if not updates or not email_ids:
            return
        marks = ",".join("?" for _ in email_ids)
        async with self.connect() as db:
            await db.execute(f"UPDATE emails SET {','.join(n + '=?' for n, _ in updates)} WHERE id IN ({marks})",
                             (*(v for _, v in updates), *email_ids))
            await db.commit()

    async def delete_emails(self, email_ids):
        """Forget cached rows (and any locally stored raw message)."""
        email_ids = list(email_ids)
        if not email_ids:
            return
        marks = ",".join("?" for _ in email_ids)
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            await db.execute(f"DELETE FROM raw_messages WHERE (account_id,folder,uid) IN "
                             f"(SELECT account_id,folder,uid FROM emails WHERE id IN ({marks}))", email_ids)
            await db.execute(f"DELETE FROM emails WHERE id IN ({marks})", email_ids)
            await db.commit()

    async def purge_account(self, account_id):
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            for table in ("emails", "folders", "raw_messages", "pop_uidl"):
                await db.execute(f"DELETE FROM {table} WHERE account_id=?", (account_id,))
            await db.commit()

    # --- POP3 / local store ----------------------------------------------
    async def ensure_local_folders(self, account_id):
        async with self.connect() as db:
            for name, role in LOCAL_FOLDERS:
                await db.execute("INSERT INTO folders(account_id,folder,uidvalidity,role,synced) VALUES(?,?,1,?,1) "
                                 "ON CONFLICT(account_id,folder) DO UPDATE SET role=excluded.role, uidvalidity=1, synced=1",
                                 (account_id, name, role))
            await db.commit()

    async def known_uidls(self, account_id):
        return {r["uidl"] for r in await self.rows("SELECT uidl FROM pop_uidl WHERE account_id=?", (account_id,))}

    async def _local_insert(self, db, account_id, folder, mail, raw, seen, flagged=False):
        cursor = await db.execute("SELECT COALESCE(MAX(uid),0)+1 FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
        uid = (await cursor.fetchone())[0]
        await db.execute(INSERT_SQL, (account_id, folder, uid, int(seen), int(flagged), 0, *_content(mail)))
        if raw is not None:
            await db.execute("INSERT OR REPLACE INTO raw_messages VALUES(?,?,?,?)", (account_id, folder, uid, raw))
        return uid

    async def local_insert(self, account_id, folder, mail, raw, seen=True):
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            uid = await self._local_insert(db, account_id, folder, mail, raw, seen)
            await db.commit()
            return uid

    async def apply_pop(self, account_id, items):
        """items: (uidl, parsed mail, raw or None). One short transaction."""
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            for uidl, mail, raw in items:
                cursor = await db.execute("INSERT OR IGNORE INTO pop_uidl VALUES(?,?)", (account_id, uidl))
                if cursor.rowcount:
                    await self._local_insert(db, account_id, "INBOX", mail, raw, seen=False)
            await db.commit()

    async def local_move(self, email_ids, target):
        email_ids = list(email_ids)
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            for email_id in email_ids:
                cursor = await db.execute("SELECT account_id,folder,uid FROM emails WHERE id=?", (email_id,))
                row = await cursor.fetchone()
                if not row or row[1] == target:
                    continue
                cursor = await db.execute("SELECT COALESCE(MAX(uid),0)+1 FROM emails WHERE account_id=? AND folder=?", (row[0], target))
                uid = (await cursor.fetchone())[0]
                await db.execute("UPDATE emails SET folder=?, uid=? WHERE id=?", (target, uid, email_id))
                await db.execute("UPDATE raw_messages SET folder=?, uid=? WHERE account_id=? AND folder=? AND uid=?",
                                 (target, uid, row[0], row[1], row[2]))
            await db.commit()

    async def raw(self, mail):
        rows = await self.rows("SELECT raw FROM raw_messages WHERE account_id=? AND folder=? AND uid=?",
                               (mail["account_id"], mail["folder"], mail["uid"]))
        if not rows:
            raise ValueError("このメールの原本は保存されていません。")
        return bytes(rows[0]["raw"])

    # --- send guard --------------------------------------------------------
    async def claim_send(self, mail):
        if not mail["message_id"]:
            raise ValueError("Draft has no Message-ID; create a new draft before sending")
        async with self.connect() as db:
            try:
                await db.execute("INSERT INTO send_attempts(account_id,message_id,email_id,state) VALUES(?,?,?,'in_progress')", (mail["account_id"], mail["message_id"], mail.get("id")))
                await db.commit()
            except aiosqlite.IntegrityError:
                raise ValueError("Already attempted; check Sent/server before any manual resend") from None

    async def release_send(self, mail):
        """Drop a claim whose SMTP transaction certainly delivered nothing."""
        async with self.connect() as db:
            await db.execute("DELETE FROM send_attempts WHERE account_id=? AND message_id=? AND state='in_progress'",
                             (mail["account_id"], mail["message_id"]))
            await db.commit()

    async def finish_send(self, mail, state):
        async with self.connect() as db:
            await db.execute("UPDATE send_attempts SET state=? WHERE account_id=? AND message_id=?",
                             (state, mail["account_id"], mail["message_id"]))
            await db.commit()
