import pytest

from app.config import Settings
from app.db import Database


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Tests never reach real mail servers; individual tests install fakes."""
    def refuse(account):
        raise ConnectionRefusedError("network disabled in tests")
    monkeypatch.setattr("app.imap_sync.open_imap", refuse)
    monkeypatch.setattr("app.imap_sync.open_pop", refuse)


@pytest.fixture
def settings():
    return Settings.model_validate({
        "web_token": "w" * 40, "mcp_token": "m" * 40,
        "accounts": [{"id": "work", "name": "Work", "email": "me@example.com",
            "drafts_folder": "Drafts",
            "imap": {"host": "imap.example.com", "port": 993, "username": "me", "password": "secret"},
            "smtp": {"host": "smtp.example.com", "port": 465, "username": "me", "password": "secret"}}],
    })


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "mail.db")
    await database.initialize()
    return database


# --- v0.3 fixtures ----------------------------------------------------------
from email import policy  # noqa: E402
from email.message import EmailMessage  # noqa: E402

from app import imap_sync  # noqa: E402
from tests.fakes import FakeIMAP, make_certificate  # noqa: E402

REAL_OPEN_POP = imap_sync.open_pop
REAL_OPEN_IMAP = imap_sync.open_imap
WEB = {"Authorization": "Bearer " + "w" * 40}


def make_mail(subject="Hello", sender="alice@example.com", to="me@example.com", body="本文です", mid=None,
              cc=None, attachment=None, html=None, inline_png=None, reply_to=None, references=None):
    msg = EmailMessage(policy=policy.SMTP)
    msg["Subject"], msg["From"], msg["To"] = subject, sender, to
    if cc:
        msg["Cc"] = cc
    msg["Message-ID"] = mid or f"<{subject.replace(' ', '-')}@example.com>"
    msg["Date"] = "Mon, 16 Nov 2026 10:00:00 +0900"
    if reply_to:
        msg["In-Reply-To"] = reply_to
        msg["References"] = references or reply_to
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
        if inline_png:
            msg.get_payload()[1].add_related(inline_png, maintype="image", subtype="png", cid="<logo@x>", disposition="inline")
    if attachment:
        msg.add_attachment(attachment[1], maintype="application", subtype="pdf", filename=attachment[0])
    return msg.as_bytes()


@pytest.fixture
def account_settings():
    """One IMAP account that syncs every folder and relies on role detection."""
    return Settings.model_validate({
        "web_token": "w" * 40, "mcp_token": "m" * 40,
        "accounts": [{"id": "work", "name": "Work", "email": "me@example.com", "folders": ["*"],
            "display_name": "山田 太郎", "signature": "山田",
            "imap": {"host": "imap.example.com", "port": 993, "username": "me", "password": "secret"},
            "smtp": {"host": "smtp.example.com", "port": 465, "username": "me", "password": "secret"}}],
    })


@pytest.fixture
def imap(monkeypatch):
    """Gmail-like mailbox layout served by an in-memory IMAP double."""
    server = FakeIMAP({
        "INBOX": {"messages": {
            1: [make_mail("First"), {b"\\Seen"}],
            2: [make_mail("With file", attachment=("報告書.pdf", b"%PDF-1.4 data")), set()],
            3: [make_mail("Starred", cc="bob@example.com, me@example.com"), {b"\\Flagged"}],
        }},
        "[Gmail]": {"flags": (b"\\Noselect",)},
        "[Gmail]/下書き": {"flags": (b"\\Drafts",)},
        "[Gmail]/送信済みメール": {"flags": (b"\\Sent",)},
        "[Gmail]/ゴミ箱": {"flags": (b"\\Trash",)},
        "[Gmail]/すべてのメール": {"flags": (b"\\All",), "messages": {9: [make_mail("Old"), {b"\\Seen"}]}},
        "Projects": {},
    })

    def connect(account):
        server.logins += 1
        return server
    monkeypatch.setattr("app.imap_sync.open_imap", connect)
    return server


@pytest.fixture
def tls(tmp_path, monkeypatch):
    """Certificate for the local fake servers, trusted only inside the test."""
    import ssl
    cert, key = make_certificate(tmp_path)

    def context():
        value = ssl.create_default_context()
        value.load_verify_locations(str(cert))
        return value
    monkeypatch.setattr("app.imap_sync.tls_context", context)
    monkeypatch.setattr("app.smtp_client.tls_context", context)
    return cert, key
