from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, model_validator
from filelock import FileLock

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CONFIG = DATA / "config.json"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Endpoint(StrictModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[^\s/\\]+$")
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1)
    password: SecretStr = SecretStr("")
    encrypted_password: SecretStr | None = None
    security: Literal["tls", "starttls"] = "tls"


class Account(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    enabled: bool = True
    imap: Endpoint
    smtp: Endpoint
    folders: list[str] = Field(default_factory=lambda: ["INBOX"], min_length=1)
    drafts_folder: str | None = None

    @model_validator(mode="after")
    def valid_folders(self):
        for folder in self.folders + ([self.drafts_folder] if self.drafts_folder else []):
            if not folder or any(c in folder for c in "\r\n\x00"):
                raise ValueError("Invalid folder name")
        return self


class EncryptionMetadata(StrictModel):
    version: Literal[1] = 1
    salt: str = Field(max_length=128)
    verifier: str = Field(max_length=256)


class Settings(StrictModel):
    credential_encryption: EncryptionMetadata | None = None
    web_token: SecretStr = Field(min_length=32)
    mcp_token: SecretStr = Field(min_length=32)
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
        return self

    def find_account(self, account_id: str) -> Account | None:
        """Lookup including disabled accounts (for reading already-cached mail)."""
        return next((a for a in self.accounts if a.id == account_id), None)

    def account(self, account_id: str) -> Account:
        for account in self.accounts:
            if account.id == account_id and account.enabled:
                if not account.imap.password.get_secret_value() or not account.smtp.password.get_secret_value():
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
            "sync_interval": 60, "max_message_bytes": 25_000_000, "sync_batch": 100,
            "accounts": [{
                "id": "example", "name": "サンプル（設定後にenabledをtrueに変更）",
                "email": "you@example.com", "enabled": False,
                "imap": {"host": "imap.example.com", "port": 993,
                         "username": "you@example.com", "password": "APP_PASSWORD", "security": "tls"},
                "smtp": {"host": "smtp.example.com", "port": 465,
                         "username": "you@example.com", "password": "APP_PASSWORD", "security": "tls"},
                "folders": ["INBOX"], "drafts_folder": None,
            }],
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
