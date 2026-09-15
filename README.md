# Gmail Inbox Triage MCP

A small, single-process Python service that polls one or more Gmail inboxes over IMAP and exposes the queued mail through the official Model Context Protocol (MCP) Python SDK using Streamable HTTP at `/mcp`.

## What is included

- FastAPI admin panel at `/` with a single admin password.
- SQLite database for accounts, UID checkpoints, queue, notes, settings, and activity logs.
- Background poller in the same process as the UI and MCP endpoint.
- IMAP over TLS to `imap.gmail.com:993` using `BODY.PEEK[]`, so mail stays unread.
- First sync for a newly registered account records the current highest UID and imports nothing.
- Subsequent cycles import only UIDs greater than the saved checkpoint.
- MIME header decoding, `text/plain` preference, and HTML-to-text fallback.
- MCP tools: `list_new_emails`, `get_email`, `mark_processed`, and `get_instructions`.

## Local run

```bash
cd email_automation_mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set both secrets to long random values.
python -m app
```

Open `http://localhost:8000/`. The MCP endpoint is `http://localhost:8000/mcp`.

Generate secrets with:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Run checks:

```bash
pytest -q
```

## Gmail prerequisites

For every Gmail account you add:

1. Turn on 2-Step Verification for the Google account.
2. Create a Gmail App Password (Google Account → Security → App passwords).
3. Enter the 16-character app password in the admin form. The service stores it only for IMAP login and never returns it in the UI, MCP responses, or logs.
4. Confirm IMAP is enabled in Gmail settings if the account exposes that setting.

Use the full Gmail address and a descriptive label such as `Personal` or `Support`.

## MCP tools

- `list_new_emails(account?: string, limit?: int)` returns `id`, account label/email, sender, recipient, date, subject, a body truncated to 3,000 characters, status, and that account's instructions.
- `get_email(id)` returns the full stored email body and metadata.
- `mark_processed(ids: string[], note?: string)` marks records processed and stores an optional note. Processed records are never returned by `list_new_emails`.
- `get_instructions()` returns global triage instructions, per-account overrides, and the poll interval.

Direct MCP clients may authenticate to `/mcp` with the static bearer token:

```http
Authorization: Bearer YOUR_MCP_BEARER_TOKEN
```

ChatGPT custom MCP connections use OAuth 2.1. This app includes a small
SQLite-backed OAuth authorization server with PKCE and dynamic client
registration. On the first connection ChatGPT opens the app's consent page;
approve it once, then ChatGPT uses the issued access token. Set
`PUBLIC_BASE_URL` (and, when it differs, `MCP_ISSUER_URL` and
`MCP_RESOURCE_URL`) to the deployed HTTPS origin.

## Recommended deployment: Render

Render is the recommended cheap host because it runs the container as one long-lived process and can attach a persistent disk for SQLite. Create a **Web Service** from this repository; `render.yaml` is included as a blueprint.

1. Push this folder to a Git repository.
2. In Render, choose **New → Blueprint** and select the repository.
3. Set `MCP_BEARER_TOKEN`, `ADMIN_PASSWORD`, and `ADMIN_SESSION_SECRET` as secret environment variables.
4. Set `PUBLIC_BASE_URL` to the Render HTTPS URL, keep `MCP_ISSUER_URL` equal to it, and set `MCP_RESOURCE_URL` to `<URL>/mcp`.
5. Keep `DATABASE_PATH=/app/data/app.db` and use the included 1 GB disk. The disk requires Render's paid starter plan; the free plan runs but does not persist SQLite between deploys or restarts.
6. Deploy. Render's built-in TLS gives you an HTTPS URL such as `https://gmail-triage-mcp.onrender.com`.
7. Visit the URL, sign in, add Gmail accounts, and use the MCP URL (`https://.../mcp`).

Railway and Fly.io can run the same `Dockerfile`. Railway reads `railway.json`; for Fly, create a volume mounted at `/app/data`, set `DATABASE_PATH=/app/data/app.db`, and expose port 8000.

## Vercel project (included)

The repository includes `api/index.py` and `vercel.json`, so it can be imported as a Vercel project:

```bash
npm install -g vercel
vercel login
vercel --prod
```

Set `MCP_BEARER_TOKEN`, `ADMIN_PASSWORD`, `ADMIN_SESSION_SECRET`, `MCP_ALLOWED_HOSTS` (your Vercel hostname), and `COOKIE_SECURE=true` in the Vercel project settings, then redeploy. The resulting MCP URL is `https://YOUR_PROJECT.vercel.app/mcp`.

**Operational limitation:** Vercel Python Functions are request-scoped. They do not keep the background IMAP poller alive between requests, and a local SQLite file is not durable across instances. The Vercel adapter is useful for a project preview or MCP/UI smoke test; use Render/Railway/Fly with persistent storage for the required continuous polling behavior. If you need Vercel for the frontend, keep the long-running worker on Render and point ChatGPT at the worker's `/mcp` URL.

## Add it to ChatGPT as a custom connector

The exact menu wording can vary by ChatGPT version, but the flow is:

1. Turn on **Developer mode** in ChatGPT under **Settings → Security and login** if your account or workspace requires it.
2. Open **Settings → Connectors** (the UI may call this **Plugins**) and choose **Add custom connector**.
3. Name it `Gmail Inbox Triage` and enter the deployed MCP URL, including `/mcp`.
4. Choose the OAuth connection option. ChatGPT discovers the authorization and registration endpoints from the server metadata.
5. Complete the consent page in the browser. Do not enter a Gmail app password in ChatGPT; Gmail credentials stay in the admin panel.
6. Confirm that ChatGPT discovers `list_new_emails`, `get_email`, `mark_processed`, and `get_instructions`.

The static bearer token remains available for direct MCP clients and smoke tests. ChatGPT does not accept a customer-supplied API key for an MCP connection, so use the built-in OAuth flow.

Example scheduled-task prompt:

> Every 30 minutes, call `list_new_emails` (use a reasonable limit), call `get_instructions`, process each queued email according to the global instructions and the matching account instructions, then call `mark_processed` for every email with a short note summarizing what you did. Do not mark an email processed if you could not complete the requested triage.

## Security and operations

- Keep `.env` and the SQLite data directory private.
- Use a long random MCP bearer token and admin password; rotate them by updating environment variables and redeploying.
- The poller catches per-account authentication, network, and parsing errors, records them in the activity log, and continues with the other accounts.
- Activity logs contain connection state, queued subjects, errors, and MCP tool calls, but never app passwords.
