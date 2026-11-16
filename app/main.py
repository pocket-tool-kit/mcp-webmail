from __future__ import annotations

import asyncio
import html
import secrets
import os
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from filelock import FileLock, Timeout
from pydantic import Field

from . import mailbox
from .config import DATA, ROOT, StrictModel, load_config
from .db import Database
from .imap_sync import SyncService, check_incoming
from .mcp_server import make_mcp
from .oauth import AuthorizationFlows, OAuthError, TOKENS
from .providers import PRESETS
from .smtp_client import DraftInput, check_smtp, create_draft, send_now, send_reviewed_draft
from .account_settings import AccountInput, ConfigurationManager, GeneralInput, UnlockInput

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
LARGE_BODY_PATHS = {"/api/drafts", "/api/send"}


class IdsInput(StrictModel):
    ids: list[int] = Field(min_length=1, max_length=500)


class FlagsInput(IdsInput):
    seen: bool | None = None
    flagged: bool | None = None


class MoveInput(IdsInput):
    folder: str = Field(min_length=1, max_length=500)


class DeleteInput(IdsInput):
    permanent: bool = False


class OAuthStartInput(StrictModel):
    account_id: str


def _hostname(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("["):
        return value.split("]")[0] + "]"
    return value.rsplit(":", 1)[0] if ":" in value else value


def create_app(settings=None, database=None, enable_sync=True, configuration=None):
    os.umask(0o077)
    configuration = configuration or (ConfigurationManager() if settings is None else None)
    settings, db = (configuration.settings if configuration else settings), database or Database()
    sync = SyncService(settings, db)
    mcp = make_mcp(settings, db, configuration)
    mcp_app = mcp.streamable_http_app()
    flows = AuthorizationFlows()
    if configuration:
        # Providers may rotate refresh tokens during background sync.
        TOKENS.on_rotate = configuration.set_oauth_refresh_token

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
        # DNS-rebinding guard: loopback names plus hosts the user explicitly
        # allowed (a Tailscale / tunnel name that proxies to this server).
        host = request.headers.get("host", "")
        if _hostname(host) not in LOOPBACK_HOSTS | set(settings.allowed_hosts):
            return JSONResponse({"detail": "Invalid host header"}, status_code=400)
        path = request.url.path
        is_mcp = path == "/mcp" or path.startswith("/mcp/")
        if is_mcp and _hostname(host) not in LOOPBACK_HOSTS:
            # Remote names are for the Web UI only; MCP stays on this machine.
            return JSONResponse({"detail": "MCP is available on localhost only"}, status_code=403)
        if path.startswith("/api/") or is_mcp:
            expected = settings.mcp_token if is_mcp else settings.web_token
            supplied = request.headers.get("authorization", "")
            if not secrets.compare_digest(supplied.encode(), ("Bearer " + expected.get_secret_value()).encode()):
                return JSONResponse({"detail": "Authentication required"}, status_code=401)
            origin = request.headers.get("origin")
            # A TLS-terminating proxy forwards plain HTTP, so the scheme may differ.
            if origin and origin not in (f"http://{host}", f"https://{host}"):
                return JSONResponse({"detail": "Cross-origin access denied"}, status_code=403)
            if request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse({"detail": "Cross-site access denied"}, status_code=403)
        # Bound request bodies even when Content-Length is absent/chunked.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            limit = 45_000_000 if path in LARGE_BODY_PATHS else 2_000_000
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > limit:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self' about:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        return response

    @app.exception_handler(ValueError)
    async def bad_input(request, error):
        return JSONResponse({"detail": str(error)}, status_code=400)

    @app.exception_handler(OAuthError)
    async def oauth_failed(request, error):
        return JSONResponse({"detail": str(error)}, status_code=400)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # FastAPI's default response includes raw input, including passwords.
        return JSONResponse({"detail": "入力形式を確認してください。必須項目・文字数・メールアドレス・ポート番号が不正です。"}, status_code=422)

    @app.exception_handler(Exception)
    async def server_error(request, error):
        return JSONResponse({"detail": "Operation failed; inspect configuration/connectivity"}, status_code=500)

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "static" / "index.html")

    @app.get("/app.js")
    async def javascript():
        return FileResponse(ROOT / "static" / "app.js", media_type="text/javascript")

    @app.get("/app.css")
    async def stylesheet():
        return FileResponse(ROOT / "static" / "app.css", media_type="text/css")

    @app.get("/api/accounts")
    async def accounts():
        result = await db.stats(settings.accounts)
        for item, account in zip(result, settings.accounts):
            item["signature"] = account.signature
            item["ready"] = account.enabled and account.credentials_ready
        return result

    @app.get("/api/providers")
    async def providers():
        return PRESETS

    def config_manager():
        if configuration is None:
            raise HTTPException(503, "Account management is unavailable in this embedded app")
        return configuration

    @app.get("/api/settings")
    async def account_settings():
        return await asyncio.to_thread(config_manager().public_state)

    @app.post("/api/settings/unlock")
    async def unlock(data: UnlockInput):
        result = await asyncio.to_thread(config_manager().unlock, data)
        sync.status.clear()
        sync.wake.set()
        return result

    @app.put("/api/settings/general")
    async def save_general(data: GeneralInput):
        return await asyncio.to_thread(config_manager().save_general, data)

    @app.put("/api/settings/accounts/{account_id}")
    async def save_account(account_id: str, data: AccountInput):
        if account_id != data.id:
            raise HTTPException(400, "Account ID mismatch")
        result = await asyncio.to_thread(config_manager().save_account, data)
        sync.status.pop(account_id, None)
        sync.wake.set()
        return result

    @app.delete("/api/settings/accounts/{account_id}")
    async def delete_account(account_id: str):
        result = await asyncio.to_thread(config_manager().delete_account, account_id)
        await db.purge_account(account_id)
        sync.status.pop(account_id, None)
        return result

    @app.post("/api/settings/accounts/{account_id}/test")
    async def test_account(account_id: str):
        config_manager()
        account = settings.find_account(account_id)
        if account is None:
            raise ValueError("Unknown account")
        if not account.credentials_ready:
            raise ValueError("ロック解除（OAuth2の場合はサインイン）後に接続テストを行ってください。")
        incoming = await asyncio.to_thread(check_incoming, account)
        outgoing = await asyncio.to_thread(check_smtp, account)
        return {"incoming": incoming, "smtp": outgoing}

    @app.post("/api/oauth/start")
    async def oauth_start(data: OAuthStartInput, request: Request):
        manager = config_manager()
        if manager.public_state()["locked"]:
            raise ValueError("先にマスターパスワードでロックを解除してください。")
        account = settings.find_account(data.account_id)
        if account is None:
            raise ValueError("Unknown account")
        # The provider redirects the browser to a loopback URL, so the sign-in
        # must run in a browser on the machine that hosts this server.
        if _hostname(request.headers.get("host", "")) not in LOOPBACK_HOSTS:
            raise ValueError("OAuthサインインは、このサーバーを動かしているPC上のブラウザ（http://localhost:8000）で行ってください。")
        redirect = f"http://localhost:{request.url.port or 8000}/oauth/callback"
        return {"url": flows.start(account, redirect), "redirect_uri": redirect}

    def _page(message: str, status: int = 200):
        body = ("<!doctype html><html lang=\"ja\"><meta charset=\"utf-8\"><title>Portable Webmail</title>"
                f"<body><h1>Portable Webmail</h1><p>{html.escape(message)}</p></body></html>")
        return HTMLResponse(body, status_code=status)

    @app.get("/oauth/callback")
    async def oauth_callback(state: str = Query(default="", max_length=200), code: str = Query(default="", max_length=4096)):
        # Unauthenticated by design: the single-use random state is the capability.
        if configuration is None or not state or not code:
            return _page("サインインは完了しませんでした。アカウント設定からやり直してください。", 400)
        try:
            account_id, refresh = await asyncio.to_thread(flows.finish, state, code, settings.find_account)
            await asyncio.to_thread(configuration.set_oauth_refresh_token, account_id, refresh)
        except (OAuthError, ValueError) as error:
            return _page(str(error), 400)
        sync.status.pop(account_id, None)
        sync.wake.set()
        return _page("サインインが完了しました。このタブを閉じて、Webメールの画面に戻ってください。")

    @app.get("/api/emails")
    async def emails(query: str = Query(default="", max_length=500), account_id: str | None = None,
                     folder: str | None = None, limit: int = Query(default=50, ge=1, le=200),
                     offset: int = Query(default=0, ge=0), unread: bool = False, flagged: bool = False,
                     attachments: bool = False):
        return await db.search(query, account_id, limit, folder, offset, unread, flagged, attachments)

    @app.get("/api/emails/{email_id}")
    async def detail(email_id: int):
        mail = await db.detail(email_id)
        draft = sync.status.get(mail["account_id"], {}).get("drafts_folder")
        if not draft:
            # Cached mail of a disabled/removed account stays readable.
            account = settings.find_account(mail["account_id"])
            draft = account.drafts_folder if account else None
        mail["is_draft"] = mail["folder_role"] == "drafts" or (bool(draft) and mail["folder"] == draft)
        return mail

    @app.get("/api/emails/{email_id}/thread")
    async def thread(email_id: int):
        return await db.thread(email_id)

    @app.get("/api/emails/{email_id}/attachments/{index}")
    async def download_attachment(email_id: int, index: int):
        info, content = await mailbox.attachment(settings, db, email_id, index)
        # Always a download: attacker-controlled content never renders in this origin.
        return Response(content, media_type="application/octet-stream", headers={
            "Content-Disposition": "attachment; filename*=UTF-8''" + quote(info["filename"], safe="")})

    @app.get("/api/emails/{email_id}/inline")
    async def inline(email_id: int):
        return await mailbox.inline_images(settings, db, email_id)

    @app.post("/api/emails/flags")
    async def flags(data: FlagsInput):
        return await mailbox.set_flags(settings, db, data.ids, data.seen, data.flagged)

    @app.post("/api/emails/move")
    async def move(data: MoveInput):
        result = await mailbox.move(settings, db, data.ids, data.folder)
        sync.wake.set()
        return result

    @app.post("/api/emails/archive")
    async def archive(data: IdsInput):
        result = await mailbox.archive(settings, db, data.ids)
        sync.wake.set()
        return result

    @app.post("/api/emails/delete")
    async def delete(data: DeleteInput):
        result = await mailbox.delete(settings, db, data.ids, data.permanent)
        sync.wake.set()
        return result

    @app.post("/api/drafts")
    async def draft(data: DraftInput):
        result = await create_draft(settings, db, data)
        sync.wake.set()
        return result

    def _confirmed(request: Request):
        if request.headers.get("x-confirm-send") != "human-reviewed":
            raise HTTPException(400, "Review the draft before sending")

    @app.post("/api/send")
    async def send_composed(data: DraftInput, request: Request):
        _confirmed(request)
        result = await send_now(settings, db, data)
        sync.wake.set()
        return result

    @app.post("/api/drafts/{email_id}/send")
    async def send(email_id: int, request: Request):
        _confirmed(request)
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
