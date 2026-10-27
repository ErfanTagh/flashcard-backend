"""
Mongo persistence for the connector's OAuth (DCR clients, auth codes, tokens,
and the pending-login state that carries a user through the Auth0 round trip).

Access and refresh tokens are stored hashed; raw tokens are never logged. Rows
live in the same RecallCards database as everything else, in their own
connector_oauth_* collections, reached through main.py's existing connection.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from datetime import datetime
from typing import Any

from pymongo import MongoClient

ACCESS_TTL_SEC = 3600
REFRESH_TTL_SEC = 60 * 60 * 24 * 30
CODE_TTL_SEC = 300
LOGIN_STATE_TTL_SEC = 600

ACCESS_PREFIX = "mcp_at_"
REFRESH_PREFIX = "mcp_rt_"
CODE_PREFIX = "mcp_ac_"

_client = None
_db_handle = None


def _db():
    """The RecallCards database, over the connector's own connection.

    Same database the backend uses (service alias "mongodb" on the shared
    network), reached directly so the connector stays independent of the Flask
    app's code and Python version.
    """
    global _client, _db_handle
    if _db_handle is None:
        host = os.environ.get("MONGO_HOST", "mongodb")
        port = os.environ.get("MONGO_PORT", "27017")
        user = os.environ.get("MONGO_USERNAME", "")
        pw = os.environ.get("MONGO_PASSWORD", "")
        dbname = os.environ.get("MONGO_DATABASE", "flashcards")
        if user and pw:
            uri = f"mongodb://{user}:{pw}@{host}:{port}/{dbname}?authSource=admin"
        else:
            uri = f"mongodb://{host}:{port}/"
        _client = MongoClient(uri)
        _db_handle = _client[dbname]
    return _db_handle


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> float:
    return time.time()


# --- DCR clients ----------------------------------------------------------

def save_client(client: dict[str, Any]) -> None:
    client_id = client.get("client_id")
    if not client_id:
        raise ValueError("client_id required")
    doc = {**client, "updated_at": datetime.utcnow()}
    _db().connector_oauth_clients.replace_one({"client_id": client_id}, doc, upsert=True)


def get_client(client_id: str) -> dict[str, Any] | None:
    return _db().connector_oauth_clients.find_one({"client_id": client_id}, {"_id": 0})


# --- Pending login (authorize -> /connector/login -> Auth0 -> /done) ------

def save_login_state(payload: dict[str, Any]) -> str:
    state = secrets.token_urlsafe(24)
    _db().connector_oauth_login_states.insert_one(
        {
            "state": state,
            "payload": payload,
            "expires_at": _now() + LOGIN_STATE_TTL_SEC,
            "created_at": datetime.utcnow(),
        }
    )
    return state


def peek_login_state(state: str) -> dict[str, Any] | None:
    """Read the pending-login payload without consuming it (needed across the
    Auth0 round trip, where the verifier is read before the state is popped)."""
    row = _db().connector_oauth_login_states.find_one({"state": state})
    if not row or row.get("expires_at", 0) < _now():
        return None
    return row.get("payload")


def update_login_state(state: str, updates: dict[str, Any]) -> None:
    """Merge values (e.g. the PKCE verifier) into a pending login's payload."""
    _db().connector_oauth_login_states.update_one(
        {"state": state},
        {"$set": {f"payload.{k}": v for k, v in updates.items()}},
    )


def pop_login_state(state: str) -> dict[str, Any] | None:
    row = _db().connector_oauth_login_states.find_one_and_delete({"state": state})
    if not row or row.get("expires_at", 0) < _now():
        return None
    return row.get("payload")


# --- Authorization codes --------------------------------------------------

def save_authorization_code(code_doc: dict[str, Any]) -> str:
    code = CODE_PREFIX + secrets.token_urlsafe(32)
    _db().connector_oauth_codes.insert_one(
        {
            "code_sha256": _hash(code),
            "doc": code_doc,
            "expires_at": code_doc.get("expires_at", _now() + CODE_TTL_SEC),
            "created_at": datetime.utcnow(),
        }
    )
    return code


def get_authorization_code(code: str) -> dict[str, Any] | None:
    if not code or not code.startswith(CODE_PREFIX):
        return None
    row = _db().connector_oauth_codes.find_one({"code_sha256": _hash(code)})
    if not row:
        return None
    if row.get("expires_at", 0) < _now():
        _db().connector_oauth_codes.delete_one({"code_sha256": _hash(code)})
        return None
    return row.get("doc")


def delete_authorization_code(code: str) -> None:
    if code:
        _db().connector_oauth_codes.delete_one({"code_sha256": _hash(code)})


# --- Access + refresh tokens ---------------------------------------------

def issue_tokens(*, client_id: str, scopes: list[str], subject: str,
                 resource: str | None) -> tuple[str, str, int]:
    access = ACCESS_PREFIX + secrets.token_urlsafe(32)
    refresh = REFRESH_PREFIX + secrets.token_urlsafe(32)
    family = secrets.token_hex(16)
    common = {
        "client_id": client_id,
        "scopes": scopes,
        "subject": subject,
        "resource": resource,
        "family": family,
        "created_at": datetime.utcnow(),
    }
    _db().connector_oauth_tokens.insert_one(
        {**common, "kind": "access", "token_sha256": _hash(access),
         "expires_at": int(_now() + ACCESS_TTL_SEC)}
    )
    _db().connector_oauth_tokens.insert_one(
        {**common, "kind": "refresh", "token_sha256": _hash(refresh),
         "expires_at": int(_now() + REFRESH_TTL_SEC)}
    )
    return access, refresh, ACCESS_TTL_SEC


def load_access_token(token: str) -> dict[str, Any] | None:
    if not token or not token.startswith(ACCESS_PREFIX):
        return None
    row = _db().connector_oauth_tokens.find_one(
        {"token_sha256": _hash(token), "kind": "access"}, {"_id": 0})
    if not row or row.get("expires_at", 0) < _now():
        return None
    return row


def load_refresh_token(token: str) -> dict[str, Any] | None:
    if not token or not token.startswith(REFRESH_PREFIX):
        return None
    row = _db().connector_oauth_tokens.find_one(
        {"token_sha256": _hash(token), "kind": "refresh"}, {"_id": 0})
    if not row or row.get("expires_at", 0) < _now():
        return None
    return row


def revoke_by_token(token: str) -> None:
    if not token:
        return
    row = _db().connector_oauth_tokens.find_one({"token_sha256": _hash(token)})
    if not row:
        return
    family = row.get("family")
    if family:
        _db().connector_oauth_tokens.delete_many({"family": family})
    else:
        _db().connector_oauth_tokens.delete_one({"token_sha256": _hash(token)})


def rotate_refresh(old_refresh: str) -> tuple[str, str, int] | None:
    row = load_refresh_token(old_refresh)
    if not row:
        return None
    revoke_by_token(old_refresh)
    return issue_tokens(
        client_id=row["client_id"],
        scopes=list(row.get("scopes") or []),
        subject=str(row["subject"]),
        resource=row.get("resource"),
    )


# --- Auth0 sessions (the user's API token, kept to call the REST API) --------
#
# After the Auth0 login the connector holds an access token for the RecallCards
# API (audience "recallcards") and a refresh token to renew it. These are stored
# usable (not hashed) because they are replayed against Auth0 and the API, the
# way any confidential OAuth client keeps a refresh token. Keyed by email, which
# is the identity the MCP token carries.

def save_auth0_session(email: str, *, access_token: str, refresh_token: str | None,
                       expires_at: float) -> None:
    _db().connector_auth0_sessions.update_one(
        {"email": email},
        {"$set": {
            "email": email,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
            "updated_at": datetime.utcnow(),
        }},
        upsert=True,
    )


def get_auth0_session(email: str) -> dict[str, Any] | None:
    return _db().connector_auth0_sessions.find_one({"email": email}, {"_id": 0})


def update_auth0_access(email: str, *, access_token: str, expires_at: float) -> None:
    _db().connector_auth0_sessions.update_one(
        {"email": email},
        {"$set": {"access_token": access_token, "expires_at": expires_at,
                  "updated_at": datetime.utcnow()}},
    )
