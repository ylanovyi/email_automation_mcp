from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import imaplib
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from typing import Any
from urllib.parse import quote

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

load_dotenv()

APP_NAME = "Gmail Inbox Triage MCP"
DB_PATH = os.getenv("DATABASE_PATH", "data/app.db")
MCP_BEARER_TOKEN = os.getenv("MCP_BEARER_TOKEN", "change-me")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me")
ADMIN_SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET", ADMIN_PASSWORD)
DEFAULT_POLL_INTERVAL = max(10, int(os.getenv("POLL_INTERVAL_SECONDS", "60")))
PORT = int(os.getenv("PORT", "8000"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", f"http://localhost:{PORT}").rstrip("/")
MCP_ISSUER_URL = os.getenv("MCP_ISSUER_URL", PUBLIC_BASE_URL).rstrip("/")
MCP_RESOURCE_URL = os.getenv("MCP_RESOURCE_URL", f"{PUBLIC_BASE_URL}/mcp").rstrip("/")
MCP_SCOPE = os.getenv("MCP_SCOPE", "gmail:triage")

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(APP_NAME)


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------

class Database:
    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    app_password TEXT NOT NULL,
                    label TEXT NOT NULL,
                    instructions TEXT NOT NULL DEFAULT '',
                    last_seen_uid INTEGER,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS emails (
                    id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    uid INTEGER NOT NULL,
                    from_addr TEXT NOT NULL DEFAULT '',
                    to_addr TEXT NOT NULL DEFAULT '',
                    date TEXT NOT NULL DEFAULT '',
                    subject TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','processed')),
                    processed_at TEXT,
                    note TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(account_id, uid)
                );
                CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status, created_at);
                CREATE INDEX IF NOT EXISTS idx_emails_account ON emails(account_id, uid);
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    level TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    metadata TEXT NOT NULL,
                    client_secret TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_pending (
                    request_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    state TEXT,
                    scopes TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_provided_explicitly INTEGER NOT NULL,
                    resource TEXT,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_codes (
                    code TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    code_challenge TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_provided_explicitly INTEGER NOT NULL,
                    resource TEXT,
                    subject TEXT
                );
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    token TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('access','refresh')),
                    client_id TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    expires_at REAL,
                    resource TEXT,
                    subject TEXT,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES('global_instructions','')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES('poll_interval_seconds',?)",
                (str(DEFAULT_POLL_INTERVAL),),
            )

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def log(self, level: str, event: str, detail: str = "") -> None:
        # Never accept or persist an app password in log text.
        redacted = re.sub(r"(?i)(password|app_password)\s*[:=]\s*\S+", r"\1=[redacted]", detail)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO activity_log(created_at,level,event,detail) VALUES(?,?,?,?)",
                (self.now(), level.upper(), event, redacted[:2000]),
            )
        logger.log(getattr(logging, level.upper(), logging.INFO), "%s: %s", event, redacted)

    def setting(self, key: str, default: str = "") -> str:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def accounts(self, enabled_only: bool = False) -> list[sqlite3.Row]:
        query = "SELECT * FROM accounts"
        if enabled_only:
            query += " WHERE enabled=1"
        query += " ORDER BY label COLLATE NOCASE, email COLLATE NOCASE"
        with self.connect() as conn:
            return conn.execute(query).fetchall()

    def account(self, account_id: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()

    def account_by_label_or_email(self, value: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM accounts WHERE lower(label)=lower(?) OR lower(email)=lower(?) LIMIT 1",
                (value, value),
            ).fetchone()

    def add_account(self, email: str, app_password: str, label: str, instructions: str = "") -> str:
        account_id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO accounts(id,email,app_password,label,instructions,created_at) VALUES(?,?,?,?,?,?)",
                (account_id, email.strip(), app_password, label.strip() or email.strip(), instructions.strip(), self.now()),
            )
        return account_id

    def update_account(self, account_id: str, *, email: str, label: str, instructions: str, app_password: str | None = None) -> None:
        with self.connect() as conn:
            if app_password:
                conn.execute(
                    "UPDATE accounts SET email=?,label=?,instructions=?,app_password=? WHERE id=?",
                    (email.strip(), label.strip() or email.strip(), instructions.strip(), app_password, account_id),
                )
            else:
                conn.execute(
                    "UPDATE accounts SET email=?,label=?,instructions=? WHERE id=?",
                    (email.strip(), label.strip() or email.strip(), instructions.strip(), account_id),
                )

    def delete_account(self, account_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))

    def save_email(self, account_id: str, uid: int, values: dict[str, str]) -> str | None:
        email_id = str(uuid.uuid4())
        with self.connect() as conn:
            try:
                conn.execute(
                    """INSERT INTO emails(id,account_id,uid,from_addr,to_addr,date,subject,body,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        email_id,
                        account_id,
                        uid,
                        values.get("from", ""),
                        values.get("to", ""),
                        values.get("date", ""),
                        values.get("subject", ""),
                        values.get("body", ""),
                        self.now(),
                    ),
                )
            except sqlite3.IntegrityError:
                return None
        return email_id

    def set_last_seen_uid(self, account_id: str, uid: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE accounts SET last_seen_uid=? WHERE id=?", (uid, account_id))

    def new_emails(self, account: str | None, limit: int) -> list[sqlite3.Row]:
        params: list[Any] = []
        where = ["e.status='new'"]
        if account:
            where.append("(lower(a.label)=lower(?) OR lower(a.email)=lower(?))")
            params += [account, account]
        params.append(max(1, min(limit, 100)))
        with self.connect() as conn:
            return conn.execute(
                f"""SELECT e.*, a.label AS account_label, a.email AS account_email, a.instructions AS account_instructions
                    FROM emails e JOIN accounts a ON a.id=e.account_id
                    WHERE {' AND '.join(where)} ORDER BY e.created_at ASC LIMIT ?""",
                params,
            ).fetchall()

    def email(self, email_id: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                """SELECT e.*, a.label AS account_label, a.email AS account_email, a.instructions AS account_instructions
                   FROM emails e JOIN accounts a ON a.id=e.account_id WHERE e.id=?""",
                (email_id,),
            ).fetchone()

    def mark_processed(self, ids: list[str], note: str | None) -> int:
        if not ids:
            return 0
        now = self.now()
        with self.connect() as conn:
            placeholders = ",".join("?" * len(ids))
            cur = conn.execute(
                f"UPDATE emails SET status='processed', processed_at=?, note=? WHERE id IN ({placeholders})",
                [now, (note or "").strip()[:2000], *ids],
            )
            return cur.rowcount

    def queue_rows(self, limit: int = 200) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """SELECT e.*, a.label AS account_label FROM emails e JOIN accounts a ON a.id=e.account_id
                   ORDER BY e.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()

    def counts(self) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute("SELECT status, COUNT(*) c FROM emails GROUP BY status").fetchall()
            return {row["status"]: row["c"] for row in rows}

    def logs(self, limit: int = 100) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # OAuth state is kept in the same SQLite database as the queue. This makes
    # the authorization code and registered client survive normal restarts on a
    # host with persistent storage (such as the included Render disk).
    def oauth_client(self, client_id: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()

    def save_oauth_client(self, client: OAuthClientInformationFull) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO oauth_clients(client_id,metadata,client_secret,created_at)
                   VALUES(?,?,?,?)""",
                (client.client_id, client.model_dump_json(), client.client_secret, self.now()),
            )

    def oauth_pending(self, request_id: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM oauth_pending WHERE request_id=?", (request_id,)).fetchone()
            if row and float(row["expires_at"]) < time.time():
                conn.execute("DELETE FROM oauth_pending WHERE request_id=?", (request_id,))
                return None
            return row

    def save_oauth_pending(self, request_id: str, client_id: str, params: AuthorizationParams) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO oauth_pending(request_id,client_id,state,scopes,code_challenge,redirect_uri,
                   redirect_uri_provided_explicitly,resource,expires_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    request_id,
                    client_id,
                    params.state,
                    json.dumps(params.scopes or []),
                    params.code_challenge,
                    str(params.redirect_uri),
                    int(params.redirect_uri_provided_explicitly),
                    params.resource,
                    time.time() + 600,
                ),
            )

    def delete_oauth_pending(self, request_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM oauth_pending WHERE request_id=?", (request_id,))

    def save_oauth_code(self, code: AuthorizationCode) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO oauth_codes(code,client_id,scopes,expires_at,code_challenge,redirect_uri,
                   redirect_uri_provided_explicitly,resource,subject) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    code.code,
                    code.client_id,
                    json.dumps(code.scopes),
                    code.expires_at,
                    code.code_challenge,
                    str(code.redirect_uri),
                    int(code.redirect_uri_provided_explicitly),
                    code.resource,
                    code.subject,
                ),
            )

    def oauth_code(self, code: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM oauth_codes WHERE code=?", (code,)).fetchone()

    def delete_oauth_code(self, code: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM oauth_codes WHERE code=?", (code,))

    def save_oauth_token(self, token: str, kind: str, client_id: str, scopes: list[str], expires_at: float | None, resource: str | None, subject: str | None) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO oauth_tokens(token,kind,client_id,scopes,expires_at,resource,subject)
                   VALUES(?,?,?,?,?,?,?)""",
                (token, kind, client_id, json.dumps(scopes), expires_at, resource, subject),
            )

    def oauth_token(self, token: str, kind: str | None = None) -> sqlite3.Row | None:
        with self.connect() as conn:
            query = "SELECT * FROM oauth_tokens WHERE token=? AND revoked=0"
            params: list[Any] = [token]
            if kind:
                query += " AND kind=?"
                params.append(kind)
            row = conn.execute(query, params).fetchone()
            if row and row["expires_at"] is not None and float(row["expires_at"]) < time.time():
                return None
            return row

    def revoke_oauth_token(self, token: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE oauth_tokens SET revoked=1 WHERE token=?", (token,))


db = Database(DB_PATH)


# ---------------------------------------------------------------------------
# IMAP polling and MIME parsing
# ---------------------------------------------------------------------------

def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    result: list[str] = []
    for fragment, charset in decode_header(value):
        if isinstance(fragment, bytes):
            try:
                result.append(fragment.decode(charset or "utf-8", errors="replace"))
            except LookupError:
                result.append(fragment.decode("utf-8", errors="replace"))
        else:
            result.append(fragment)
    return "".join(result).strip()


def decode_part(part: Any) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def parse_email(raw: bytes) -> dict[str, str]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    text_body = ""
    html_body = ""
    parts = list(message.walk()) if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type().lower()
        value = decode_part(part)
        if content_type == "text/plain" and not text_body:
            text_body = value
        elif content_type == "text/html" and not html_body:
            html_body = value
    body = text_body.strip()
    if not body and html_body:
        body = BeautifulSoup(html_body, "html.parser").get_text("\n", strip=True)
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    return {
        "from": decode_mime_header(message.get("From")),
        "to": decode_mime_header(message.get("To")),
        "date": decode_mime_header(message.get("Date")),
        "subject": decode_mime_header(message.get("Subject")),
        "body": body,
    }


def _uid_ints(data: bytes | None) -> list[int]:
    if not data:
        return []
    return [int(x) for x in data.split() if x.isdigit()]


def sync_account(account: sqlite3.Row) -> None:
    account_id = account["id"]
    label = account["label"]
    conn: imaplib.IMAP4_SSL | None = None
    try:
        db.log("INFO", "imap_connect", f"Connecting to {label} ({account['email']})")
        conn = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=30)
        conn.login(account["email"], account["app_password"])
        status, _ = conn.select("INBOX", readonly=True)
        if status != "OK":
            raise RuntimeError("could not select INBOX")
        status, data = conn.uid("search", None, "ALL")
        if status != "OK":
            raise RuntimeError("UID search failed")
        uids = _uid_ints(data[0] if data else b"")
        current_max = max(uids, default=0)
        last_seen = account["last_seen_uid"]
        if last_seen is None:
            db.set_last_seen_uid(account_id, current_max)
            db.log("INFO", "imap_first_sync", f"{label}: baseline UID {current_max}; existing inbox left untouched")
            return
        new_uids = [uid for uid in uids if uid > int(last_seen)]
        for uid in sorted(new_uids):
            status, fetched = conn.uid("fetch", str(uid), "(BODY.PEEK[])")
            if status != "OK":
                db.log("ERROR", "imap_fetch_error", f"{label}: UID {uid} fetch failed")
                continue
            raw = next((item[1] for item in fetched if isinstance(item, tuple) and isinstance(item[1], bytes)), None)
            if raw:
                parsed = parse_email(raw)
                if db.save_email(account_id, uid, parsed):
                    db.log("INFO", "email_queued", f"{label}: {parsed.get('subject','(no subject)')[:160]}")
        if current_max > int(last_seen):
            db.set_last_seen_uid(account_id, current_max)
    except Exception as exc:  # noqa: BLE001 - polling must never take down the process
        db.log("ERROR", "imap_error", f"{label}: {type(exc).__name__}: {exc}")
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass


async def poll_loop() -> None:
    while True:
        try:
            accounts = db.accounts(enabled_only=True)
            await asyncio.gather(*(asyncio.to_thread(sync_account, account) for account in accounts))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            db.log("ERROR", "poller_error", f"{type(exc).__name__}: {exc}")
        interval = max(10, int(db.setting("poll_interval_seconds", str(DEFAULT_POLL_INTERVAL))))
        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

_allowed_hosts = [h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "localhost,localhost:*,127.0.0.1,127.0.0.1:*").split(",") if h.strip()]
_allowed_origins = [o.strip() for o in os.getenv("MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()]
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=_allowed_hosts,
    allowed_origins=_allowed_origins,
)


class SQLiteOAuthProvider:
    """Small OAuth 2.1 authorization server for a single-owner deployment.

    ChatGPT opens the consent URL in the browser once per connection. The
    resulting access and refresh tokens are stored in SQLite and verified by
    the MCP SDK on every request. This is intentionally separate from the
    static bearer token, which remains useful for direct integrations and
    health checks.
    """

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = db.oauth_client(client_id)
        if not row:
            return None
        try:
            return OAuthClientInformationFull.model_validate_json(row["metadata"])
        except Exception:
            return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise ValueError("OAuth client id is required")
        db.save_oauth_client(client_info)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        request_id = secrets.token_urlsafe(24)
        db.save_oauth_pending(request_id, client.client_id or "", params)
        return f"{PUBLIC_BASE_URL}/oauth/consent?request_id={quote(request_id)}"

    async def complete_authorization(self, request_id: str, approved: bool) -> str:
        row = db.oauth_pending(request_id)
        if not row:
            return f"{PUBLIC_BASE_URL}/oauth/consent?error=expired"
        db.delete_oauth_pending(request_id)
        redirect_uri = row["redirect_uri"]
        state = row["state"]
        if not approved:
            return construct_redirect_uri(redirect_uri, error="access_denied", state=state)
        code = secrets.token_urlsafe(32)
        db.save_oauth_code(
            AuthorizationCode(
                code=code,
                client_id=row["client_id"],
                scopes=json.loads(row["scopes"]),
                expires_at=time.time() + 300,
                code_challenge=row["code_challenge"],
                redirect_uri=redirect_uri,
                redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
                resource=row["resource"] or MCP_RESOURCE_URL,
                subject="owner",
            )
        )
        return construct_redirect_uri(redirect_uri, code=code, state=state)

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        row = db.oauth_code(authorization_code)
        if not row or row["client_id"] != client.client_id or float(row["expires_at"]) < time.time():
            return None
        return AuthorizationCode(
            code=row["code"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=float(row["expires_at"]),
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            resource=row["resource"] or MCP_RESOURCE_URL,
            subject=row["subject"],
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        db.delete_oauth_code(authorization_code.code)
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_in = 3600
        resource = authorization_code.resource or MCP_RESOURCE_URL
        db.save_oauth_token(access_token, "access", client.client_id or "", authorization_code.scopes, time.time() + expires_in, resource, authorization_code.subject)
        db.save_oauth_token(refresh_token, "refresh", client.client_id or "", authorization_code.scopes, None, resource, authorization_code.subject)
        return OAuthToken(
            access_token=access_token,
            expires_in=expires_in,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        row = db.oauth_token(refresh_token, "refresh")
        if not row or row["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=int(row["expires_at"]) if row["expires_at"] is not None else None,
            resource=row["resource"] or MCP_RESOURCE_URL,
            subject=row["subject"],
        )

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        db.revoke_oauth_token(refresh_token.token)
        access_token = secrets.token_urlsafe(32)
        replacement_refresh = secrets.token_urlsafe(32)
        expires_in = 3600
        resource = refresh_token.resource or MCP_RESOURCE_URL
        db.save_oauth_token(access_token, "access", client.client_id or "", scopes, time.time() + expires_in, resource, refresh_token.subject)
        db.save_oauth_token(replacement_refresh, "refresh", client.client_id or "", scopes, None, resource, refresh_token.subject)
        return OAuthToken(access_token=access_token, expires_in=expires_in, scope=" ".join(scopes), refresh_token=replacement_refresh)

    async def load_access_token(self, token: str) -> AccessToken | None:
        if MCP_BEARER_TOKEN and hmac.compare_digest(token, MCP_BEARER_TOKEN):
            return AccessToken(token=token, client_id="static", scopes=[MCP_SCOPE], resource=MCP_RESOURCE_URL)
        row = db.oauth_token(token, "access")
        if not row:
            return None
        return AccessToken(
            token=row["token"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=int(row["expires_at"]) if row["expires_at"] is not None else None,
            resource=row["resource"] or MCP_RESOURCE_URL,
            subject=row["subject"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        db.revoke_oauth_token(token.token)


class CombinedTokenVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if MCP_BEARER_TOKEN and hmac.compare_digest(token, MCP_BEARER_TOKEN):
            return AccessToken(token=token, client_id="static", scopes=[MCP_SCOPE], resource=MCP_RESOURCE_URL)
        return await oauth_provider.load_access_token(token)


oauth_provider = SQLiteOAuthProvider()
auth_settings = AuthSettings(
    issuer_url=MCP_ISSUER_URL,
    resource_server_url=MCP_RESOURCE_URL,
    validate_token_resource=True,
    required_scopes=[MCP_SCOPE],
    client_registration_options=ClientRegistrationOptions(
        enabled=True,
        valid_scopes=[MCP_SCOPE],
        default_scopes=[MCP_SCOPE],
    ),
)

mcp = FastMCP(
    APP_NAME,
    instructions="Gmail inbox triage queue. Use get_instructions before processing mail.",
    auth_server_provider=oauth_provider,
    auth=auth_settings,
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    transport_security=_transport_security,
)


def row_email(row: sqlite3.Row, truncate: int | None = None) -> dict[str, Any]:
    body = row["body"]
    if truncate:
        body = body[:truncate]
    return {
        "id": row["id"],
        "account": row["account_label"],
        "account_email": row["account_email"],
        "from": row["from_addr"],
        "to": row["to_addr"],
        "date": row["date"],
        "subject": row["subject"],
        "body": body,
        "status": row["status"],
        "created_at": row["created_at"],
        "account_instructions": row["account_instructions"],
        **({"processed_at": row["processed_at"], "note": row["note"]} if "processed_at" in row.keys() else {}),
    }


@mcp.tool()
def list_new_emails(account: str | None = None, limit: int = 20) -> dict[str, Any]:
    """Return queued unread-preserving emails. Account may be a label or email address."""
    db.log("INFO", "mcp_tool", f"list_new_emails account={account or '*'} limit={limit}")
    rows = db.new_emails(account, limit)
    return {
        "emails": [row_email(row, 3000) for row in rows],
        "count": len(rows),
        "global_instructions": db.setting("global_instructions", ""),
    }


@mcp.tool()
def get_email(id: str) -> dict[str, Any]:
    """Return one full queued or processed email by id."""
    db.log("INFO", "mcp_tool", f"get_email id={id}")
    row = db.email(id)
    if not row:
        return {"error": "Email not found"}
    return row_email(row)


@mcp.tool()
def mark_processed(ids: list[str], note: str | None = None) -> dict[str, Any]:
    """Mark emails processed so they are not returned by list_new_emails again."""
    db.log("INFO", "mcp_tool", f"mark_processed count={len(ids)}")
    updated = db.mark_processed(ids, note)
    return {"updated": updated, "ids": ids, "note": (note or "")[:2000]}


@mcp.tool()
def get_instructions() -> dict[str, Any]:
    """Return global triage instructions and per-account overrides."""
    db.log("INFO", "mcp_tool", "get_instructions")
    return {
        "global": db.setting("global_instructions", ""),
        "accounts": [
            {"account": row["label"], "email": row["email"], "instructions": row["instructions"]}
            for row in db.accounts()
        ],
        "poll_interval_seconds": int(db.setting("poll_interval_seconds", str(DEFAULT_POLL_INTERVAL))),
    }


class BearerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        auth = request.headers.get("authorization", "")
        expected = f"Bearer {MCP_BEARER_TOKEN}"
        if not MCP_BEARER_TOKEN or not hmac.compare_digest(auth, expected):
            return JSONResponse({"error": "Unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)


# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

def admin_cookie() -> str:
    return hmac.new(ADMIN_SESSION_SECRET.encode(), b"admin", hashlib.sha256).hexdigest()


def is_admin(request: Request) -> bool:
    return hmac.compare_digest(request.cookies.get("admin_session", ""), admin_cookie())


def login_page(error: str = "") -> str:
    return f"""<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>{APP_NAME}</title>
    <style>body{{font:16px system-ui;background:#f4f6f8;display:grid;place-items:center;min-height:100vh}}form{{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 30px #0001;min-width:300px}}input,button{{font:inherit;padding:.7rem;margin:.35rem 0;width:100%;box-sizing:border-box}}button{{background:#1f6feb;color:#fff;border:0;border-radius:6px}}.err{{color:#b42318}}</style></head>
    <body><form method='post' action='/login'><h1>Gmail Triage MCP</h1><p>Admin sign-in</p><input type='password' name='password' placeholder='Admin password' required autofocus>{f"<p class='err'>{html.escape(error)}</p>" if error else ''}<button>Sign in</button></form></body></html>"""


def dashboard_html(state: dict[str, Any]) -> str:
    return f"""<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>{APP_NAME}</title>
<style>body{{font:14px system-ui;margin:0;background:#f6f8fa;color:#172b4d}}header{{background:#172b4d;color:#fff;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center}}main{{max-width:1200px;margin:1.2rem auto;padding:0 1rem}}section{{background:#fff;padding:1rem;margin:1rem 0;border-radius:10px;box-shadow:0 2px 12px #0000000d}}h2{{margin-top:0}}input,textarea,button,select{{font:inherit;padding:.5rem;margin:.25rem 0;box-sizing:border-box}}input,textarea,select{{width:100%;border:1px solid #ccd3dc;border-radius:6px}}textarea{{min-height:90px}}button{{border:0;border-radius:6px;background:#1f6feb;color:white;cursor:pointer;padding:.55rem .8rem}}button.danger{{background:#b42318}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:.5rem;border-bottom:1px solid #eef1f4;vertical-align:top}}code{{word-break:break-all}}.muted{{color:#667085}}.pill{{display:inline-block;padding:.15rem .45rem;border-radius:20px;background:#e9eef5}}#logs,#queue{{max-height:380px;overflow:auto}}</style></head>
<body><header><strong>Gmail Inbox Triage MCP</strong><form method='post' action='/logout'><button>Log out</button></form></header><main>
<section><h2>Settings</h2><form method='post' action='/admin/settings'><label>Global triage instructions</label><textarea name='global_instructions'>{html.escape(state['global_instructions'])}</textarea><label>Poll interval (seconds)</label><input type='number' min='10' name='poll_interval_seconds' value='{state['poll_interval_seconds']}'><button>Save settings</button></form></section>
<section><h2>Add Gmail account</h2><form method='post' action='/admin/accounts'><div class='grid'><div><label>Email</label><input name='email' type='email' required></div><div><label>Label</label><input name='label' required></div><div><label>Gmail app password</label><input name='app_password' type='password' required autocomplete='new-password'></div></div><label>Per-account instructions (optional)</label><textarea name='instructions'></textarea><button>Add account</button></form></section>
<section><h2>Accounts</h2><div id='accounts'>{state['accounts_html']}</div></section>
<section><h2>Queue</h2><div class='muted'>New: {state['counts'].get('new',0)} · Processed: {state['counts'].get('processed',0)}</div><div id='queue'>{state['queue_html']}</div></section>
<section><h2>Activity log</h2><div id='logs'>{state['logs_html']}</div></section>
</main><script>async function refresh(){{const r=await fetch('/api/state');if(!r.ok)return;const s=await r.json();document.getElementById('queue').innerHTML=s.queue_html;document.getElementById('logs').innerHTML=s.logs_html;document.querySelector('#accounts').innerHTML=s.accounts_html;}}setInterval(refresh,5000);</script></body></html>"""


def safe_account_html(row: sqlite3.Row) -> str:
    return f"""<form method='post' action='/admin/accounts/{row['id']}' style='border-top:1px solid #eef1f4;padding:.8rem 0'><div class='grid'><div><label>Email</label><input name='email' type='email' value='{html.escape(row['email'])}' required></div><div><label>Label</label><input name='label' value='{html.escape(row['label'])}' required></div><div><label>New app password (leave blank to keep)</label><input name='app_password' type='password' autocomplete='new-password'></div></div><label>Instructions</label><textarea name='instructions'>{html.escape(row['instructions'])}</textarea><span class='muted'>Last seen UID: {row['last_seen_uid'] if row['last_seen_uid'] is not None else 'not synced'}</span><br><button>Save</button></form><form method='post' action='/admin/accounts/{row['id']}/delete' onsubmit='return confirm("Remove this account and its queued mail?")'><button class='danger'>Remove</button></form>"""


def render_queue(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return "<p class='muted'>No queued email records yet.</p>"
    out = ["<table><tr><th>Status</th><th>Account</th><th>Date</th><th>From</th><th>Subject</th><th>Note</th></tr>"]
    for row in rows:
        out.append(f"<tr><td><span class='pill'>{html.escape(row['status'])}</span></td><td>{html.escape(row['account_label'])}</td><td>{html.escape(row['date'])}</td><td>{html.escape(row['from_addr'])}</td><td>{html.escape(row['subject'])}</td><td>{html.escape(row['note'] or '')}</td></tr>")
    return "".join(out) + "</table>"


def render_logs(rows: list[sqlite3.Row]) -> str:
    if not rows:
        return "<p class='muted'>No activity yet.</p>"
    return "".join(f"<div><span class='muted'>{html.escape(row['created_at'])}</span> <b>{html.escape(row['level'])}</b> {html.escape(row['event'])}: {html.escape(row['detail'])}</div>" for row in rows)


def state_payload() -> dict[str, Any]:
    return {
        "global_instructions": db.setting("global_instructions", ""),
        "poll_interval_seconds": int(db.setting("poll_interval_seconds", str(DEFAULT_POLL_INTERVAL))),
        "counts": db.counts(),
        "accounts_html": "".join(safe_account_html(row) for row in db.accounts()) or "<p class='muted'>No accounts configured.</p>",
        "queue_html": render_queue(db.queue_rows()),
        "logs_html": render_logs(db.logs()),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    db.log("INFO", "app_start", "Application started")
    task = asyncio.create_task(poll_loop())
    async with mcp.session_manager.run():
        yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title=APP_NAME, lifespan=lifespan)
# The FastMCP app owns the /mcp route and the OAuth discovery/authorization
# endpoints. Mounting it at the root keeps the public endpoint exactly /mcp.
mcp_app = mcp.streamable_http_app()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not is_admin(request):
        return HTMLResponse(login_page())
    return HTMLResponse(dashboard_html(state_payload()))


@app.post("/login")
async def login(password: str = Form(...)):
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse(login_page("Invalid password"), status_code=401)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("admin_session", admin_cookie(), httponly=True, secure=os.getenv("COOKIE_SECURE", "true").lower() == "true", samesite="lax", max_age=86400 * 7)
    db.log("INFO", "admin_login", "Admin signed in")
    return response


@app.post("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("admin_session")
    return response


def admin_redirect(request: Request) -> RedirectResponse | None:
    return None if is_admin(request) else RedirectResponse("/", status_code=303)


@app.get("/api/state")
async def api_state(request: Request):
    if not is_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(state_payload())


@app.post("/admin/settings")
async def save_settings(request: Request, global_instructions: str = Form(""), poll_interval_seconds: int = Form(DEFAULT_POLL_INTERVAL)):
    redirect = admin_redirect(request)
    if redirect:
        return redirect
    db.set_setting("global_instructions", global_instructions[:10000])
    db.set_setting("poll_interval_seconds", str(max(10, min(poll_interval_seconds, 86400))))
    db.log("INFO", "settings_updated", "Triage settings updated")
    return RedirectResponse("/", status_code=303)


@app.post("/admin/accounts")
async def create_account(request: Request, email: str = Form(...), app_password: str = Form(...), label: str = Form(...), instructions: str = Form("")):
    redirect = admin_redirect(request)
    if redirect:
        return redirect
    try:
        db.add_account(email, app_password, label, instructions)
        db.log("INFO", "account_added", f"Account added: {label}")
    except sqlite3.IntegrityError:
        db.log("ERROR", "account_add_error", f"Account already exists: {email}")
    return RedirectResponse("/", status_code=303)


@app.post("/admin/accounts/{account_id}")
async def update_account(request: Request, account_id: str, email: str = Form(...), label: str = Form(...), instructions: str = Form(""), app_password: str = Form("")):
    redirect = admin_redirect(request)
    if redirect:
        return redirect
    try:
        db.update_account(account_id, email=email, label=label, instructions=instructions, app_password=app_password or None)
        db.log("INFO", "account_updated", f"Account updated: {label}")
    except sqlite3.IntegrityError:
        db.log("ERROR", "account_update_error", f"Account update conflict: {email}")
    return RedirectResponse("/", status_code=303)


@app.post("/admin/accounts/{account_id}/delete")
async def remove_account(request: Request, account_id: str):
    redirect = admin_redirect(request)
    if redirect:
        return redirect
    row = db.account(account_id)
    db.delete_account(account_id)
    if row:
        db.log("INFO", "account_removed", f"Account removed: {row['label']}")
    return RedirectResponse("/", status_code=303)


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata():
    """Advertise OAuth methods accepted by the built-in MCP authorization server.

    The SDK's default metadata predates ChatGPT's public-client preference and
    omits ``none``. Keeping this small response explicit lets ChatGPT use DCR
    with PKCE while the SDK continues to handle the protocol endpoints.
    """
    return JSONResponse(
        {
            "issuer": MCP_ISSUER_URL,
            "authorization_endpoint": f"{MCP_ISSUER_URL}/authorize",
            "token_endpoint": f"{MCP_ISSUER_URL}/token",
            "registration_endpoint": f"{MCP_ISSUER_URL}/register",
            "scopes_supported": [MCP_SCOPE],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "service_documentation": PUBLIC_BASE_URL,
        }
    )


@app.get("/oauth/consent", response_class=HTMLResponse)
async def oauth_consent(request_id: str | None = None, error: str | None = None):
    if error:
        return HTMLResponse("<h1>Authorization expired</h1><p>Please return to ChatGPT and reconnect.</p>", status_code=400)
    if not request_id or not db.oauth_pending(request_id):
        return HTMLResponse("<h1>Authorization request expired</h1><p>Please return to ChatGPT and reconnect.</p>", status_code=400)
    return HTMLResponse(
        """<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>
        <title>Authorize Gmail Inbox Triage</title><style>body{font:16px system-ui;display:grid;place-items:center;min-height:100vh;background:#f6f8fa}main{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 30px #0001;max-width:440px}button{font:inherit;padding:.7rem 1rem;border:0;border-radius:6px;margin:.4rem .2rem;cursor:pointer}.yes{background:#1f6feb;color:#fff}.no{background:#e5e7eb}</style></head>
        <body><main><h1>Authorize Gmail Inbox Triage</h1><p>ChatGPT is requesting access to read and process the queued Gmail messages in this service.</p>
        <form method='post' action='/oauth/consent'><input type='hidden' name='request_id' value='""" + html.escape(request_id) + """'><button class='yes' name='decision' value='approve'>Approve</button><button class='no' name='decision' value='deny'>Deny</button></form></main></body></html>"""
    )


@app.post("/oauth/consent")
async def oauth_consent_submit(request_id: str = Form(...), decision: str = Form("deny")):
    redirect_url = await oauth_provider.complete_authorization(request_id, decision == "approve")
    return RedirectResponse(redirect_url, status_code=303)


# Mount after the UI and consent routes so the dashboard, OAuth approval page,
# and metadata remain reachable without a bearer token. The MCP SDK's auth
# middleware protects /mcp and returns the OAuth discovery challenge.
app.mount("/", mcp_app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=PORT, reload=False)
