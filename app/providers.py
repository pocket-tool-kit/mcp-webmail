"""Server presets shown in the account form. Values are suggestions the user can edit."""
from __future__ import annotations

PRESETS = [
    {"id": "gmail", "label": "Gmail / Google Workspace", "protocol": "imap",
     "imap": {"host": "imap.gmail.com", "port": 993, "security": "tls"},
     "smtp": {"host": "smtp.gmail.com", "port": 465, "security": "tls"},
     "oauth": "google", "tenant": "common", "save_sent": False, "folders": ["*"],
     "note": "2段階認証を有効にして「アプリ パスワード」を発行するか、OAuth2を使用します。送信済みはGmailが自動保存します。"},
    {"id": "icloud", "label": "iCloudメール", "protocol": "imap",
     "imap": {"host": "imap.mail.me.com", "port": 993, "security": "tls"},
     "smtp": {"host": "smtp.mail.me.com", "port": 587, "security": "starttls"},
     "oauth": None, "tenant": "common", "save_sent": True, "folders": ["*"],
     "note": "Apple Accountで「アプリ用パスワード」を発行して入力します（通常のパスワードは使えません）。"},
    {"id": "microsoft365", "label": "Microsoft 365（Exchange Online）", "protocol": "imap",
     "imap": {"host": "outlook.office365.com", "port": 993, "security": "tls"},
     "smtp": {"host": "smtp.office365.com", "port": 587, "security": "starttls"},
     "oauth": "microsoft", "tenant": "common", "save_sent": False, "folders": ["*"],
     "note": "パスワード認証は廃止済みのためOAuth2が必要です。組織の管理者がIMAPとSMTP AUTHを許可している必要があります。"},
    {"id": "outlook", "label": "Outlook.com / Hotmail", "protocol": "imap",
     "imap": {"host": "outlook.office365.com", "port": 993, "security": "tls"},
     "smtp": {"host": "smtp-mail.outlook.com", "port": 587, "security": "starttls"},
     "oauth": "microsoft", "tenant": "consumers", "save_sent": False, "folders": ["*"],
     "note": "OAuth2が必要です。Microsoft Entraで個人アカウント対応のアプリを登録してください。"},
    {"id": "generic", "label": "その他のIMAPサーバー", "protocol": "imap",
     "imap": {"host": "", "port": 993, "security": "tls"},
     "smtp": {"host": "", "port": 465, "security": "tls"},
     "oauth": None, "tenant": "common", "save_sent": True, "folders": ["*"],
     "note": "プロバイダーが案内するIMAP/SMTPサーバー名を入力します。"},
    {"id": "pop3", "label": "POP3サーバー（受信のみ・サーバーに残す）", "protocol": "pop3",
     "imap": {"host": "", "port": 995, "security": "tls"},
     "smtp": {"host": "", "port": 465, "security": "tls"},
     "oauth": None, "tenant": "common", "save_sent": True, "folders": ["INBOX"],
     "note": "POP3は受信トレイのみ取得し、サーバー上のメールは削除しません。下書き・送信済み・ごみ箱・既読状態はこのPC内だけに保存します。"},
]

OAUTH_PROVIDERS = {
    "google": {
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "scope": "https://mail.google.com/",
        "extra": {"access_type": "offline", "prompt": "consent"},
    },
    "microsoft": {
        "authorize": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "scope": "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access",
        "extra": {"prompt": "select_account"},
    },
}
