"""Web-only account management; one atomic config, no persisted decryption key."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from filelock import FileLock
from pydantic import EmailStr, Field, SecretStr

from .config import (Account, CONFIG, EncryptionMetadata, Endpoint, McpPermissions, OAuthConfig, Settings,
                     StrictModel, load_config)

CHECK = b"portable-webmail-credentials-v1"


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def derive(password: str, salt: bytes) -> bytes:
    if len(salt) != 16:
        raise ValueError("Invalid encryption metadata")
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode("utf-8"))


def encrypt(key: bytes, value: str, context: str) -> str:
    nonce = os.urandom(12)
    return encode(nonce + AESGCM(key).encrypt(nonce, value.encode("utf-8"), context.encode()))


def decrypt(key: bytes, value: str, context: str) -> str:
    raw = decode(value)
    return AESGCM(key).decrypt(raw[:12], raw[12:], context.encode()).decode("utf-8")


def endpoint_context(account, kind):
    ep = getattr(account, kind)
    # Prevent changing a host/user in a stolen config to exfiltrate its password.
    return json.dumps(["v1", account.id, kind, ep.host, ep.port, ep.username, ep.security], separators=(",", ":"))


def secret_slots(account):
    """Every stored secret as (holder, json section, plain attr, AEAD context)."""
    for kind in ("imap", "smtp"):
        yield getattr(account, kind), kind, "password", endpoint_context(account, kind)
    if account.oauth:
        for slot in ("client_secret", "refresh_token"):
            # Bound to the client and provider so a token cannot be replayed elsewhere.
            yield account.oauth, "oauth", slot, json.dumps(
                ["v1", account.id, "oauth", slot, account.oauth.provider, account.oauth.client_id, account.oauth.tenant],
                separators=(",", ":"))


class UnlockInput(StrictModel):
    master_password: SecretStr = Field(min_length=1, max_length=1024)
    confirmation: SecretStr | None = Field(default=None, max_length=1024)
    # Only honoured during the very first setup.
    mcp_permissions: McpPermissions | None = None


class GeneralInput(StrictModel):
    mcp_permissions: McpPermissions
    mark_read_on_open: bool = True
    allowed_hosts: list[str] = Field(default_factory=list, max_length=20)


class EndpointInput(StrictModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[^\s/\\]+$")
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1, max_length=500)
    security: str = Field(pattern=r"^(tls|starttls)$")
    # Empty means keep existing, and is never returned by the read API.
    password: SecretStr = Field(default=SecretStr(""), max_length=4096)


class OAuthInput(StrictModel):
    provider: Literal["google", "microsoft"]
    client_id: str = Field(min_length=1, max_length=300, pattern=r"^[\x21-\x7e]+$")
    tenant: str = Field(default="common", pattern=r"^[A-Za-z0-9.-]{1,100}$")
    # Empty means keep existing (or none, for public clients).
    client_secret: SecretStr = Field(default=SecretStr(""), max_length=4096)


class AccountInput(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    enabled: bool = True
    protocol: Literal["imap", "pop3"] = "imap"
    provider: str = Field(default="generic", pattern=r"^[a-z0-9_-]{1,32}$")
    auth: Literal["password", "oauth2"] = "password"
    oauth: OAuthInput | None = None
    folders: list[str] = Field(default_factory=lambda: ["INBOX"], min_length=1, max_length=100)
    drafts_folder: str | None = None
    sent_folder: str | None = None
    trash_folder: str | None = None
    archive_folder: str | None = None
    save_sent: bool = True
    display_name: str = Field(default="", max_length=100)
    signature: str = Field(default="", max_length=4000)
    imap: EndpointInput
    smtp: EndpointInput


class ConfigurationManager:
    def __init__(self, path: Path = CONFIG):
        self.path = path
        self._mutex = threading.RLock()
        self._key = None
        self._failures = 0
        self._blocked_until = 0.0
        if path == CONFIG and not path.exists():
            load_config()
        self._disk = self._read()
        self._revision = self._digest()
        self.settings = self._disk.model_copy(deep=True)
        # Existing plaintext is read only for explicit migration, never exposed
        # to IMAP/SMTP while the user has not enabled encryption.
        self._replace_runtime(self._disk, None)

    def _read(self):
        try:
            value = Settings.model_validate_json(self.path.read_text(encoding="utf-8"))
            for account in value.accounts:
                for holder, _, slot, _ in secret_slots(account):
                    plain = getattr(holder, slot).get_secret_value()
                    stored = getattr(holder, "encrypted_" + slot)
                    if (value.credential_encryption and plain) or (not value.credential_encryption and stored):
                        raise ValueError()
            return value
        except Exception:
            raise ValueError("設定ファイルが不正です。暗号化後はpasswordを手入力せず、登録画面を使用してください。") from None

    def _digest(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def _replace_runtime(self, settings, key):
        runtime = settings.model_copy(deep=True)
        for account in runtime.accounts:
            for holder, _, slot, context in secret_slots(account):
                stored = getattr(holder, "encrypted_" + slot)
                value = decrypt(key, stored.get_secret_value(), context) if key and stored else ""
                setattr(holder, slot, SecretStr(value))
        # Keep the Settings object shared by sync / REST / HTTP MCP alive.
        for name in Settings.model_fields:
            setattr(self.settings, name, getattr(runtime, name))

    def _write(self, settings, key):
        # Both cross-process and in-process serialization are required.
        with FileLock(str(self.path.parent / "config.lock"), timeout=10):
            if self._digest() != self._revision:
                raise ValueError("設定が外部で変更されました。アプリを再起動して再入力してください。")
            document = settings.model_dump(mode="json")
            for name in ("web_token", "mcp_token"):
                document[name] = getattr(settings, name).get_secret_value()
            for account in document["accounts"]:
                source = settings.find_account(account["id"])
                for holder, section, slot, context in secret_slots(source):
                    account[section].pop(slot, None)
                    account[section]["encrypted_" + slot] = encrypt(key, getattr(holder, slot).get_secret_value(), context)
            serialized = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
            disk = Settings.model_validate_json(serialized)
            descriptor, temporary = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=self.path.parent)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as out:
                    out.write(serialized)
                    out.flush()
                    os.fsync(out.fileno())
                # The temporary file contains ciphertext only. No plaintext backup.
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            self._disk, self._revision, self._key = disk, self._digest(), key
            self._replace_runtime(disk, key)

    def public_state(self):
        with self._mutex:
            accounts = []
            for account in self._disk.accounts:
                item = account.model_dump(mode="json", exclude={"imap", "smtp", "oauth"})
                for kind in ("imap", "smtp"):
                    ep = getattr(account, kind)
                    item[kind] = ep.model_dump(mode="json", exclude={"password", "encrypted_password"})
                    item[kind]["has_password"] = bool(ep.encrypted_password or ep.password.get_secret_value())
                item["oauth"] = None
                if account.oauth:
                    runtime = self.settings.find_account(account.id)
                    item["oauth"] = {
                        "provider": account.oauth.provider, "client_id": account.oauth.client_id,
                        "tenant": account.oauth.tenant,
                        "has_client_secret": bool(runtime and runtime.oauth and runtime.oauth.client_secret.get_secret_value()),
                        "signed_in": bool(runtime and runtime.oauth and runtime.oauth.refresh_token.get_secret_value()),
                    }
                accounts.append(item)
            return {"encrypted": self._disk.credential_encryption is not None,
                    "locked": self._key is None, "accounts": accounts,
                    "mcp_permissions": self._disk.mcp_permissions,
                    "mark_read_on_open": self._disk.mark_read_on_open,
                    "allowed_hosts": list(self._disk.allowed_hosts)}

    def refresh(self):
        """stdio processes see Web edits without persisting or sharing the key."""
        with self._mutex, FileLock(str(self.path.parent / "config.lock"), timeout=10):
            revision = self._digest()
            if revision == self._revision:
                return
            disk = self._read()
            key = self._key if disk.credential_encryption == self._disk.credential_encryption else None
            try:
                self._replace_runtime(disk, key)
            except Exception:
                self._replace_runtime(disk, None)
                self._key = None
                raise ValueError("暗号化設定が変更されています。再起動してロックを解除してください。") from None
            self._disk, self._revision, self._key = disk, revision, key

    def unlock(self, data: UnlockInput):
        with self._mutex:
            if time.monotonic() < self._blocked_until:
                raise ValueError("試行回数が多いため、60秒後に再試行してください。")
            password = data.master_password.get_secret_value()
            metadata = self._disk.credential_encryption
            if not metadata:
                if len(password) < 12 or not data.confirmation or password != data.confirmation.get_secret_value():
                    raise ValueError("新しいマスターパスワードは12文字以上とし、確認欄にも同じ値を入力してください。")
                if password in (self._disk.web_token.get_secret_value(), self._disk.mcp_token.get_secret_value()):
                    raise ValueError("マスターパスワードにはWeb/MCPトークンと異なる値を指定してください。")
                salt = os.urandom(16)
                key = derive(password, salt)
                candidate = self._disk.model_copy(deep=True)
                candidate.credential_encryption = EncryptionMetadata(salt=encode(salt), verifier=encrypt(key, CHECK.decode(), "verifier:v1"))
                if data.mcp_permissions:
                    candidate.mcp_permissions = data.mcp_permissions
                self._write(candidate, key)
            else:
                try:
                    key = derive(password, decode(metadata.salt))
                    if decrypt(key, metadata.verifier, "verifier:v1") != CHECK.decode():
                        raise ValueError()
                    # Decrypt all before publishing any runtime changes.
                    self._replace_runtime(self._disk, key)
                except Exception:
                    self._failures += 1
                    if self._failures >= 5:
                        self._blocked_until = time.monotonic() + 60
                        self._failures = 0
                    raise ValueError("マスターパスワードが違うか、暗号化データが変更されています。") from None
                self._key = key
            self._failures = 0
            return self.public_state()

    def _editable(self):
        if self._key is None:
            raise ValueError("先にマスターパスワードでロックを解除してください。")
        return self.settings.model_copy(deep=True)

    def save_account(self, data: AccountInput):
        with self._mutex:
            candidate = self._editable()
            old = candidate.find_account(data.id)
            document = data.model_dump(exclude={"imap", "smtp", "oauth"})
            for kind, label in (("imap", "受信サーバー（IMAP/POP3）"), ("smtp", "SMTP")):
                value = getattr(data, kind)
                password = value.password.get_secret_value()
                if not password and old:
                    password = getattr(old, kind).password.get_secret_value()
                if not password and data.auth == "password":
                    label = kind.upper() if data.protocol == "imap" else label
                    raise ValueError(f"{label}のパスワードを入力してください。")
                document[kind] = Endpoint(**value.model_dump(exclude={"password"}), password=SecretStr(password))
            if data.oauth:
                previous = old.oauth if old else None
                same_client = bool(previous and (previous.provider, previous.client_id, previous.tenant) ==
                                   (data.oauth.provider, data.oauth.client_id, data.oauth.tenant))
                secret = data.oauth.client_secret.get_secret_value() or (previous.client_secret.get_secret_value() if same_client else "")
                # A sign-in belongs to one client registration and mailbox user.
                keep = same_client and old.imap.username == data.imap.username
                document["oauth"] = OAuthConfig(
                    provider=data.oauth.provider, client_id=data.oauth.client_id, tenant=data.oauth.tenant,
                    client_secret=SecretStr(secret),
                    refresh_token=SecretStr(previous.refresh_token.get_secret_value() if keep else ""))
            try:
                account = Account.model_validate(document)
            except Exception:
                raise ValueError("アカウント設定を確認してください。フォルダ名に改行は使用できません。OAuth2はIMAPでのみ利用できます。") from None
            candidate.accounts = [account if a.id == account.id else a for a in candidate.accounts]
            if old is None:
                candidate.accounts.append(account)
            self._write(candidate, self._key)
            return self.public_state()

    def delete_account(self, account_id: str):
        with self._mutex:
            candidate = self._editable()
            if candidate.find_account(account_id) is None:
                raise ValueError("Unknown account")
            candidate.accounts = [a for a in candidate.accounts if a.id != account_id]
            self._write(candidate, self._key)
            return self.public_state()

    def save_general(self, data: GeneralInput):
        with self._mutex:
            candidate = self._editable()
            candidate.mcp_permissions = data.mcp_permissions
            candidate.mark_read_on_open = data.mark_read_on_open
            candidate.allowed_hosts = [h.strip().lower() for h in data.allowed_hosts if h.strip()]
            try:
                Settings.model_validate(candidate.model_dump())
            except Exception:
                raise ValueError("許可するホスト名を確認してください（例: pc.tailnet.ts.net）。ワイルドカードやポート番号は指定できません。") from None
            self._write(candidate, self._key)
            return self.public_state()

    def set_oauth_refresh_token(self, account_id: str, token: str):
        with self._mutex:
            candidate = self._editable()
            account = candidate.find_account(account_id)
            if account is None or account.oauth is None:
                raise ValueError("Unknown OAuth account")
            account.oauth.refresh_token = SecretStr(token)
            self._write(candidate, self._key)
            return self.public_state()
