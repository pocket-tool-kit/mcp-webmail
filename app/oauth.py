"""OAuth2 authorization-code flow (PKCE, loopback redirect) and XOAUTH2 tokens.

The user registers their own OAuth client with Google / Microsoft. Refresh
tokens are stored encrypted in config.json; access tokens stay in memory.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .providers import OAUTH_PROVIDERS

FLOW_LIFETIME = 600


class OAuthError(Exception):
    """Safe-to-display OAuth failure; never contains tokens or server text."""


def post_form(url: str, fields: dict) -> dict:
    """POST a token request. Only fixed provider HTTPS endpoints are called."""
    if not url.startswith("https://"):
        raise OAuthError("OAuthエンドポイントが不正です")
    request = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode("ascii"),
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
            body = response.read(1_000_000)
    except urllib.error.HTTPError as error:
        body = error.read(1_000_000)
    except Exception as error:
        raise OAuthError(f"OAuthサーバーへ接続できません ({type(error).__name__})") from None
    try:
        data = json.loads(body)
    except Exception:
        raise OAuthError("OAuthサーバーの応答を解釈できません") from None
    if not isinstance(data, dict):
        raise OAuthError("OAuthサーバーの応答を解釈できません")
    return data


def _endpoints(oauth):
    provider = OAUTH_PROVIDERS[oauth.provider]
    return {k: (v.format(tenant=oauth.tenant) if isinstance(v, str) else v) for k, v in provider.items()}


def _error_code(data) -> str:
    # Provider error codes are short identifiers; anything else is suppressed.
    code = str(data.get("error", "unknown"))
    return code if code.replace("_", "").isalnum() and len(code) <= 40 else "unknown"


def xoauth2(username: str, access_token: str) -> str:
    return f"user={username}\x01auth=Bearer {access_token}\x01\x01"


class AuthorizationFlows:
    """Pending browser sign-ins keyed by an unguessable single-use state."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending = {}

    def start(self, account, redirect_uri: str) -> str:
        oauth = account.oauth
        if account.auth != "oauth2" or oauth is None:
            raise ValueError("このアカウントはOAuth2を使用していません。")
        endpoints = _endpoints(oauth)
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
        with self._lock:
            now = time.monotonic()
            self._pending = {k: v for k, v in self._pending.items() if v["expires"] > now}
            self._pending[state] = {"account_id": account.id, "verifier": verifier, "redirect_uri": redirect_uri,
                                    "client_id": oauth.client_id, "expires": now + FLOW_LIFETIME}
        query = {"client_id": oauth.client_id, "response_type": "code", "redirect_uri": redirect_uri,
                 "scope": endpoints["scope"], "state": state, "code_challenge": challenge,
                 "code_challenge_method": "S256", "login_hint": account.imap.username, **endpoints["extra"]}
        return endpoints["authorize"] + "?" + urllib.parse.urlencode(query)

    def finish(self, state: str, code: str, find_account) -> tuple[str, str]:
        """Exchange the code. Returns (account_id, refresh_token)."""
        with self._lock:
            flow = self._pending.pop(state, None)
        if not flow or flow["expires"] < time.monotonic():
            raise OAuthError("サインインの有効期限が切れたか、不正な要求です。もう一度やり直してください。")
        account = find_account(flow["account_id"])
        if account is None or account.oauth is None or account.oauth.client_id != flow["client_id"]:
            raise OAuthError("アカウント設定が変更されました。もう一度やり直してください。")
        oauth = account.oauth
        fields = {"grant_type": "authorization_code", "code": code, "redirect_uri": flow["redirect_uri"],
                  "client_id": oauth.client_id, "code_verifier": flow["verifier"]}
        if oauth.client_secret.get_secret_value():
            fields["client_secret"] = oauth.client_secret.get_secret_value()
        data = post_form(_endpoints(oauth)["token"], fields)
        refresh = data.get("refresh_token")
        if not isinstance(refresh, str) or not refresh:
            if "error" in data:
                raise OAuthError(f"サインインに失敗しました ({_error_code(data)})")
            raise OAuthError("リフレッシュトークンが返されませんでした。アプリ登録のスコープと種類を確認してください。")
        TOKENS.remember(account, refresh, data)
        return account.id, refresh


class TokenCache:
    """In-memory access tokens, refreshed on demand from the stored refresh token."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tokens = {}
        # Called as on_rotate(account_id, new_refresh_token) when a provider rotates it.
        self.on_rotate = None

    @staticmethod
    def _key(account, refresh):
        return (account.id, account.oauth.client_id, hashlib.sha256(refresh.encode()).hexdigest())

    def remember(self, account, refresh, data):
        token, lifetime = data.get("access_token"), data.get("expires_in", 0)
        if isinstance(token, str) and token:
            try:
                expires = time.monotonic() + max(0, int(lifetime))
            except (TypeError, ValueError):
                expires = time.monotonic()
            with self._lock:
                self._tokens[self._key(account, refresh)] = (token, expires)

    def access_token(self, account) -> str:
        oauth = account.oauth
        refresh = oauth.refresh_token.get_secret_value() if oauth else ""
        if not refresh:
            raise OAuthError("OAuthサインインが必要です")
        key = self._key(account, refresh)
        with self._lock:
            cached = self._tokens.get(key)
            if cached and cached[1] - 60 > time.monotonic():
                return cached[0]
        fields = {"grant_type": "refresh_token", "refresh_token": refresh, "client_id": oauth.client_id}
        if oauth.client_secret.get_secret_value():
            fields["client_secret"] = oauth.client_secret.get_secret_value()
        endpoints = _endpoints(oauth)
        if oauth.provider == "microsoft":
            fields["scope"] = endpoints["scope"]
        data = post_form(endpoints["token"], fields)
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            code = _error_code(data)
            if code == "invalid_grant":
                raise OAuthError("OAuthの再サインインが必要です (invalid_grant)")
            raise OAuthError(f"アクセストークンを取得できません ({code})")
        rotated = data.get("refresh_token")
        if isinstance(rotated, str) and rotated and rotated != refresh:
            self.remember(account, rotated, data)
            if self.on_rotate:
                try:
                    self.on_rotate(account.id, rotated)
                except Exception:
                    pass  # the old refresh token normally stays valid; retry on next rotation
        self.remember(account, refresh, data)
        return token

    def clear(self):
        with self._lock:
            self._tokens.clear()


TOKENS = TokenCache()
