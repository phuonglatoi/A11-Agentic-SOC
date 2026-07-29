from __future__ import annotations

import hmac
import time

from fastapi import Header, HTTPException, Query, Request, status


def _equal(provided: str | None, expected: str) -> bool:
    return bool(provided) and hmac.compare_digest(provided, expected)


def require_admin(request: Request, authorization: str | None = Header(default=None)) -> str:
    expected = request.app.state.settings.admin_token
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not _equal(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin bearer token is missing or invalid.",
        )
    return "soc-analyst"


def require_stream_ticket(
    request: Request,
    ticket: str | None = Query(default=None),
) -> str:
    expires_at = request.app.state.stream_tickets.get(ticket or "", 0)
    if expires_at < time.time():
        if ticket:
            request.app.state.stream_tickets.pop(ticket, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Stream ticket is missing, invalid, or expired.",
        )
    return "soc-dashboard"


def require_ingest(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> str:
    expected = request.app.state.settings.api_key
    provided = x_api_key
    if authorization and authorization.lower().startswith("splunk "):
        provided = authorization[7:].strip()
    if not _equal(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ingestion API key is missing or invalid.",
        )
    return "log-source"
