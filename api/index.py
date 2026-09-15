"""Vercel adapter. The same FastAPI app serves UI and /mcp.

Vercel Functions are request-scoped, so the IMAP background poller and local
SQLite file are not durable there. Use Render/Railway/Fly for production.
"""
from app import app
