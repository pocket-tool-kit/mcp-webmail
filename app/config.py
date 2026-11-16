from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, model_validator
from filelock import FileLock

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CONFIG = DATA / "config.json"

# "*" in Account.folders means "every selectable folder the server lists".
ALL_FOLDERS = "*"
McpPermissions = Literal["read_draft", "organize", "full"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Endpoint(StrictModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[^\s/\\]+$")
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1)
    password: SecretStr = SecretStr("")
    encrypted_password: SecretStr | None = None
    security: Literal["tls", "starttls"] = "tls"


class OAuthConfig(StrictModel):
    """OAuth2 client registered by the user; tokens never leave data/config.json."""
    provider: Literal["google", "microsoft"]
    client_id: str = Field(min_length=1, max_length=300, pattern=r"^[\x21-\x7e]+$")
    tenant: str = Field(default="common", pattern=r"^[A-Za-z0-9.-]{1,100}$")
    client_secret: SecretStr = SecretStr("")
    encrypted_client_secret: SecretStr | None = None
    refresh_token: SecretStr = SecretStr("")
    encrypted_refresh_token: SecretStr | None = None


class Account(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    enabled: bool = True
    # The incoming endpoint keeps its historical key "imap" also for POP3.
    protocol: Literal["imap", "pop3"] = "imap"
    provider: str = Field(default="generic", pattern=r"^[a-z0-9_-]{1,32}$")
    auth: Literal["password", "oauth2"] = "password"
    oauth: OAuthConfig | None = None
    imap: Endpoint
    smtp: Endpoint
    folders: list[str] = Field(default_factory=lambda: ["INBOX"], min_length=1)
    drafts_folder: str | None = None
    sent_folder: str | None = None
    trash_folder: str | None = None
    archive_folder: str | None = None
    # Gmail and Microsoft store SMTP submissions in Sent themselves.
    save_sent: bool = True
    display_name: str = Field(default="", max_length=100)
    signature: str = Field(default="", max_length=4000)

    @model_validator(mode="after")
    def valid_account(self):
        named = [self.drafts_folder, self.sent_folder, self.trash_folder, self.archive_folder]
        for folder in self.folders + [f for f in named if f]:
            if not folder or any(c in folder for c in "\r\n\x00"):
                raise ValueError("Invalid folder name")
        if any(c in self.display_name for c in "\r\n\x00"):
            raise ValueError("Invalid display name")
        if self.auth == "oauth2" and (self.oauth is None or self.protocol != "imap"):
            raise ValueError("OAuth2 needs an OAuth client and IMAP")
        return self

    @property
    def credentials_ready(self) -> bool:
        if self.auth == "oauth2":
            return bool(self.oauth and self.oauth.refresh_token.get_secret_value())
        return bool(self.imap.password.get_secret_value() and self.smtp.password.get_secret_value())

    @property
    def sync_all_folders(self) -> bool:
        return ALL_FOLDERS in self.folders


class EncryptionMetadata(StrictModel):
    version: Literal[1] = 1
    salt: str = Field(max_length=128)
    verifier: str = Field(max_length=256)


class Settings(StrictModel):
    credential_encryption: EncryptionMetadata | None = None
    web_token: SecretStr = Field(min_length=32)
    mcp_token: SecretStr = Field(min_length=32)
    # What MCP clients (AI) may do: read+draft, also organize, or also send/delete.
    mcp_permissions: McpPermissions = "read_draft"
    mark_read_on_open: bool = True
    # Extra Host names accepted besides loopback, e.g. a Tailscale or
    # Cloudflare Tunnel name that proxies to 127.0.0.1:8000.
    allowed_hosts: list[str] = Field(default_factory=list, max_length=20)
    sync_interval: int = Field(default=60, ge=10, le=86400)
    max_message_bytes: int = Field(default=25_000_000, ge=1024, le=100_000_000)
    sync_batch: int = Field(default=100, ge=1, le=1000)
    accounts: list[Account] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique(self):
        if len({a.id for a in self.accounts}) != len(self.accounts):
            raise ValueError("Duplicate account id")
        if self.web_token.get_secret_value() == self.mcp_token.get_secret_value():
            raise ValueError("Web and MCP tokens must differ")
        for host in self.allowed_hosts:
            # Exact names only: a wildcard would defeat DNS-rebinding protection.
            if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
                raise ValueError("Invalid allowed host")
        return self

    def find_account(self, account_id: str) -> Account | None:
        """Lookup including disabled accounts (for reading already-cached mail)."""
        return next((a for a in self.accounts if a.id == account_id), None)

    def account(self, account_id: str) -> Account:
        for account in self.accounts:
            if account.id == account_id and account.enabled:
                if not account.credentials_ready:
                    if account.auth == "oauth2":
                        raise ValueError("アカウント設定画面でロック解除とOAuthサインインを行ってください。")
                    raise ValueError("アカウント設定画面で暗号化設定・ロック解除を行ってください。")
                return account
        raise ValueError("Unknown or disabled account")


def load_config() -> Settings:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Web and stdio may start simultaneously; do not read a half-written sample.
    with FileLock(str(DATA / "config.lock"), timeout=10):
        return _load_config_locked()


def _load_config_locked() -> Settings:
    if not CONFIG.exists():
        example = {
            "web_token": secrets.token_urlsafe(32),
            "mcp_token": secrets.token_urlsafe(32),
            "mcp_permissions": "read_draft",
            "sync_interval": 60, "max_message_bytes": 25_000_000, "sync_batch": 100,
            "accounts": [],
        }
        try:
            fd = os.open(CONFIG, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(example, out, ensure_ascii=False, indent=2)
                out.write("\n")
    try:
        return Settings.model_validate_json(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        # Never include pydantic's input values (passwords/tokens) in logs.
        raise RuntimeError("data/config.json is invalid; check README and configuration") from None
