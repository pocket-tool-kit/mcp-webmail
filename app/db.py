from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from .config import DATA
from .mail_parser import PARSER_VERSION

# The cache is derived from IMAP. When the parser changes, cached rows are
# dropped and re-fetched (send_attempts is kept: it guards against resends).
SCHEMA_VERSION = PARSER_VERSION
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
 UNIQUE(account_id, folder, uid)
)""",
    "CREATE INDEX IF NOT EXISTS emails_date ON emails(date_ts DESC, id DESC)",
    "CREATE INDEX IF NOT EXISTS emails_thread ON emails(account_id, message_id)",
    """CREATE TABLE IF NOT EXISTS folders (
 account_id TEXT NOT NULL, folder TEXT NOT NULL, uidvalidity INTEGER NOT NULL,
 PRIMARY KEY(account_id, folder)
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
                   "body_html", "has_attachments", "references_header", "reply_to", "oversize_limit"]
MAX_THREAD = 500


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
            if version < SCHEMA_VERSION:
                # Concurrent starters serialize on BEGIN IMMEDIATE; only the first rebuilds.
                await db.execute("DROP TABLE IF EXISTS emails")
                exists = await (await db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='folders'")).fetchone()
                if exists:
                    await db.execute("DELETE FROM folders")
            columns = await (await db.execute("PRAGMA table_info(send_attempts)")).fetchall()
            if any(c["name"] == "email_id" and c["pk"] for c in columns):
                for statement in LEGACY_SEND_ATTEMPTS_MIGRATION:
                    await db.execute(statement)
            for statement in SCHEMA:
                await db.execute(statement)
            if version < SCHEMA_VERSION:
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
        # IMAP I/O has already completed. A short single write transaction makes
        # UIDVALIDITY reset, pruning, flag updates and inserts visible atomically.
        async with self.connect() as db:
            await db.execute("BEGIN IMMEDIATE")
            cursor = await db.execute("SELECT uidvalidity FROM folders WHERE account_id=? AND folder=?", (account_id, folder))
            previous = await cursor.fetchone()
            if previous and previous[0] != uidvalidity:
                await db.execute("DELETE FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
            await db.execute("INSERT INTO folders VALUES(?,?,?) ON CONFLICT(account_id,folder) DO UPDATE SET uidvalidity=excluded.uidvalidity", (account_id, folder, uidvalidity))
            cursor = await db.execute("SELECT uid, is_seen FROM emails WHERE account_id=? AND folder=?", (account_id, folder))
            current = {r[0]: bool(r[1]) for r in await cursor.fetchall()}
            stale = [(account_id, folder, uid) for uid in current if uid not in flags]
            await db.executemany("DELETE FROM emails WHERE account_id=? AND folder=? AND uid=?", stale)
            # Write only flags that actually changed; large folders stay cheap.
            changed = [(int(seen), account_id, folder, uid) for uid, seen in flags.items()
                       if uid in current and current[uid] != bool(seen)]
            await db.executemany("UPDATE emails SET is_seen=? WHERE account_id=? AND folder=? AND uid=?", changed)
            # IMAP content for a UID is immutable, so replacing a row only happens
            # for re-fetches (e.g. an oversize placeholder after raising the limit).
            updates = ",".join(f"{c}=excluded.{c}" for c in CONTENT_COLUMNS)
            sql = (f"INSERT INTO emails(account_id,folder,uid,is_seen,{','.join(CONTENT_COLUMNS)}) "
                   f"VALUES({','.join('?' for _ in range(4 + len(CONTENT_COLUMNS)))}) "
                   f"ON CONFLICT(account_id,folder,uid) DO UPDATE SET {updates}")
            await db.executemany(sql, [(account_id, folder, uid, int(flags.get(uid, False)),
                                        *(mail.get(c, 0) if c == "oversize_limit" else mail[c] for c in CONTENT_COLUMNS))
                                       for uid, mail in messages.items() if uid in flags])
            await db.commit()

    async def search(self, query="", account_id=None, limit=20, folder=None, offset=0):
        if not 1 <= limit <= 200 or offset < 0 or len(query) > 500:
            raise ValueError("Invalid search bounds")
        clauses, args = [], []
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' OR body_text LIKE ? ESCAPE '\\')")
            args.extend([f"%{escaped}%"] * 3)
        for name, value in (("account_id", account_id), ("folder", folder)):
            if value is not None:
                clauses.append(f"{name}=?")
                args.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return await self.rows("SELECT id,account_id,folder,uid,subject,sender,date_ts,is_seen,has_attachments,substr(body_text,1,180) AS snippet FROM emails" + where + " ORDER BY date_ts DESC,id DESC LIMIT ? OFFSET ?", (*args, limit, offset))

    DETAIL_SQL = ("SELECT e.*, f.uidvalidity, (SELECT state FROM send_attempts s WHERE e.message_id<>'' AND "
                  "s.account_id=e.account_id AND s.message_id=e.message_id) AS send_state "
                  "FROM emails e JOIN folders f USING(account_id,folder) WHERE e.id IN ({})")

    async def details(self, email_ids):
        email_ids = list(email_ids)
        if not email_ids:
            return []
        rows = await self.rows(self.DETAIL_SQL.format(",".join("?" for _ in email_ids)), email_ids)
        for row in rows:
            row["recipients"] = json.loads(row["recipients"])
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
            # Include folders before their first email arrives.
            known = await self.rows("SELECT folder FROM folders WHERE account_id=?", (account.id,))
            by_name = {r["folder"]: r for r in counts}
            for name in set(account.folders + [r["folder"] for r in known]):
                by_name.setdefault(name, {"folder": name, "total": 0, "unread": 0})
            result.append({"id": account.id, "name": account.name, "email": str(account.email),
                           "enabled": account.enabled, "folders": sorted(by_name.values(), key=lambda x: x["folder"]),
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

    async def claim_send(self, mail):
        if not mail["message_id"]:
            raise ValueError("Draft has no Message-ID; create a new draft before sending")
        async with self.connect() as db:
            try:
                await db.execute("INSERT INTO send_attempts(account_id,message_id,email_id,state) VALUES(?,?,?,'in_progress')", (mail["account_id"], mail["message_id"], mail["id"]))
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
