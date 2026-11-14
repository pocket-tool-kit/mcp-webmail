from __future__ import annotations

import asyncio
import secrets
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from filelock import FileLock, Timeout
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import DATA, ROOT, load_config
from .db import Database
from .imap_sync import SyncService
from .mcp_server import make_mcp
from .smtp_client import DraftInput, create_draft, send_reviewed_draft


def create_app(settings=None, database=None, enable_sync=True):
    os.umask(0o077)
    settings, db = settings or load_config(), database or Database()
    sync = SyncService(settings, db)
    mcp = make_mcp(settings, db)
    mcp_app = mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(app):
        await db.initialize()
        # A second Web worker must not produce stale competing snapshots.
        lock = FileLock(str(DATA / "web.lock")) if enable_sync else None
        if lock:
            try:
                lock.acquire(timeout=0)
            except Timeout:
                raise RuntimeError("Another Web server is already running for this data/ directory "
                                   "(data/web.lock). Stop it before starting a second one.") from None
        task = None
        try:
            async with mcp.session_manager.run():
                if enable_sync:
                    task = asyncio.create_task(sync.run())
                yield
                sync.stop()
                if task:
                    await task
        finally:
            sync.stop()
            if task and not task.done():
                await task
            if lock:
                lock.release()

    app = FastAPI(title="Portable Webmail", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db, app.state.sync = db, sync

    @app.middleware("http")
    async def security(request: Request, call_next):
        path = request.url.path
        is_mcp = path == "/mcp" or path.startswith("/mcp/")
        if path.startswith("/api/") or is_mcp:
            expected = settings.mcp_token if is_mcp else settings.web_token
            supplied = request.headers.get("authorization", "")
            if not secrets.compare_digest(supplied.encode(), ("Bearer " + expected.get_secret_value()).encode()):
                return JSONResponse({"detail": "Authentication required"}, status_code=401)
            origin = request.headers.get("origin")
            if origin and origin != f"{request.url.scheme}://{request.headers.get('host', '')}":
                return JSONResponse({"detail": "Cross-origin access denied"}, status_code=403)
            if request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse({"detail": "Cross-site access denied"}, status_code=403)
        # Bound request bodies even when Content-Length is absent/chunked.
        if request.method in {"POST", "PUT", "PATCH"}:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 2_000_000:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self' about:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    @app.exception_handler(ValueError)
    async def bad_input(request, error):
        return JSONResponse({"detail": str(error)}, status_code=400)

    @app.exception_handler(Exception)
    async def server_error(request, error):
        return JSONResponse({"detail": "Operation failed; inspect configuration/connectivity"}, status_code=500)

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "static" / "index.html")

    @app.get("/app.js")
    async def javascript():
        return FileResponse(ROOT / "static" / "app.js", media_type="text/javascript")

    @app.get("/api/accounts")
    async def accounts():
        return await db.stats(settings.accounts)

    @app.get("/api/emails")
    async def emails(query: str = Query(default="", max_length=500), account_id: str | None = None,
                     folder: str | None = None, limit: int = Query(default=50, ge=1, le=200),
                     offset: int = Query(default=0, ge=0)):
        return await db.search(query, account_id, limit, folder, offset)

    @app.get("/api/emails/{email_id}")
    async def detail(email_id: int):
        mail = await db.detail(email_id)
        draft = sync.status.get(mail["account_id"], {}).get("drafts_folder")
        if not draft:
            # Cached mail of a disabled/removed account stays readable.
            account = settings.find_account(mail["account_id"])
            draft = account.drafts_folder if account else None
        mail["is_draft"] = bool(draft) and mail["folder"] == draft
        return mail

    @app.get("/api/emails/{email_id}/thread")
    async def thread(email_id: int):
        return await db.thread(email_id)

    @app.post("/api/drafts")
    async def draft(data: DraftInput):
        result = await create_draft(settings, db, data)
        sync.wake.set()
        return result

    @app.post("/api/drafts/{email_id}/send")
    async def send(email_id: int, request: Request):
        if request.headers.get("x-confirm-send") != "human-reviewed":
            raise HTTPException(400, "Review the draft before sending")
        result = await send_reviewed_draft(settings, db, email_id)
        sync.wake.set()
        return result

    @app.get("/api/sync")
    async def sync_status():
        return sync.status

    @app.post("/api/sync")
    async def trigger_sync():
        sync.wake.set()
        return {"scheduled": True}

    # The child owns /mcp. Mount at root LAST to avoid /mcp/mcp or redirects.
    app.mount("/", mcp_app)
    return app
