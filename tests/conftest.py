import pytest

from app.config import Settings
from app.db import Database


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
