import sqlite3
from email.message import EmailMessage

import app


def make_raw(subject="Hello", body="Plain body"):
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.com>"
    msg["To"] = "receiver@example.com"
    msg["Subject"] = subject
    msg["Date"] = "Tue, 01 Jan 2030 12:00:00 +0000"
    msg.set_content(body)
    return msg.as_bytes()


def test_parse_mime_headers_and_plain_body():
    parsed = app.parse_email(make_raw("Café", "hello\nworld"))
    assert parsed["subject"] == "Café"
    assert parsed["from"] == "Sender <sender@example.com>"
    assert parsed["body"] == "hello\nworld"


def test_first_sync_baselines_without_importing(monkeypatch, tmp_path):
    db = app.Database(str(tmp_path / "db.sqlite"))
    db.init()
    account_id = db.add_account("a@example.com", "secret", "A")

    class FakeIMAP:
        def __init__(self, *args, **kwargs): pass
        def login(self, *_): return "OK", []
        def select(self, *_args, **_kwargs): return "OK", []
        def uid(self, command, *_args):
            if command == "search": return "OK", [b"10 11 12"]
            raise AssertionError(command)
        def logout(self): pass

    monkeypatch.setattr(app, "db", db)
    monkeypatch.setattr(app.imaplib, "IMAP4_SSL", FakeIMAP)
    app.sync_account(db.account(account_id))
    assert db.account(account_id)["last_seen_uid"] == 12
    assert db.new_emails(None, 100) == []


def test_incremental_sync_persists_uid_and_queues_new_mail(monkeypatch, tmp_path):
    db = app.Database(str(tmp_path / "db.sqlite"))
    db.init()
    account_id = db.add_account("a@example.com", "secret", "A")
    db.set_last_seen_uid(account_id, 12)
    raw = make_raw()

    class FakeIMAP:
        def __init__(self, *args, **kwargs): pass
        def login(self, *_): return "OK", []
        def select(self, *_args, **_kwargs): return "OK", []
        def uid(self, command, uid, *_args):
            if command == "search": return "OK", [b"10 11 12 13"]
            if command == "fetch": return "OK", [(b"meta", raw)]
            raise AssertionError(command)
        def logout(self): pass

    monkeypatch.setattr(app, "db", db)
    monkeypatch.setattr(app.imaplib, "IMAP4_SSL", FakeIMAP)
    app.sync_account(db.account(account_id))
    rows = db.new_emails(None, 100)
    assert len(rows) == 1
    assert rows[0]["uid"] == 13
    assert db.account(account_id)["last_seen_uid"] == 13


def test_mark_processed_never_returns_again(tmp_path, monkeypatch):
    db = app.Database(str(tmp_path / "db.sqlite"))
    db.init()
    account_id = db.add_account("a@example.com", "secret", "A")
    monkeypatch.setattr(app, "db", db)
    email_id = db.save_email(account_id, 1, {"subject": "x", "body": "b"})
    assert email_id
    assert len(db.new_emails(None, 10)) == 1
    assert db.mark_processed([email_id], "done") == 1
    assert db.new_emails(None, 10) == []
    assert db.email(email_id)["note"] == "done"


def test_mcp_bearer_auth_and_tools_list(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    db = app.Database(str(tmp_path / "db.sqlite"))
    db.init()
    monkeypatch.setattr(app, "db", db)
    monkeypatch.setattr(app, "MCP_BEARER_TOKEN", "token")
    with TestClient(app.app) as client:
        denied = client.post(
            "/mcp",
            headers={"host": "localhost", "content-type": "application/json"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert denied.status_code == 401
        allowed = client.post(
            "/mcp",
            headers={
                "host": "localhost",
                "authorization": "Bearer token",
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert allowed.status_code == 200
        names = {tool["name"] for tool in allowed.json()["result"]["tools"]}
        assert {"list_new_emails", "get_email", "mark_processed", "get_instructions"} <= names
