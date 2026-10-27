"""
The connector's data layer: a thin client over the RecallCards REST API.

Every operation calls the same endpoints the website calls, with the signed-in
user's Auth0 access token, so the API does the authorization and scoping and the
connector never reimplements (or drifts from) the site's logic.

The Auth0 access token lasts about an hour; when it is close to expiry the stored
refresh token renews it. All calls here are synchronous (urllib) and are invoked
from the MCP server in a worker thread.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from connector import oauth_store as ost

API_URL = os.getenv("CONNECTOR_API_URL", "http://recallcards-backend:5000").rstrip("/")
PUBLIC_URL = os.getenv("CONNECTOR_PUBLIC_URL", "https://recallcards.net").rstrip("/")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
CLIENT_ID = os.getenv("CONNECTOR_AUTH0_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CONNECTOR_AUTH0_CLIENT_SECRET", "")


class ConnectorError(Exception):
    """A problem the user or Claude can act on (bad name, missing deck, expired
    session). Its message is shown; any other exception is hidden by the SDK."""


# --- the user's API token -------------------------------------------------

def _refresh_access(email: str, refresh_token: str) -> str | None:
    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }).encode("ascii")
    req = urllib.request.Request(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            tokens = json.loads(resp.read())
    except Exception:
        return None
    access = tokens.get("access_token")
    if not access:
        return None
    ost.update_auth0_access(email, access_token=access,
                            expires_at=time.time() + int(tokens.get("expires_in") or 3600))
    # Auth0 may rotate the refresh token.
    if tokens.get("refresh_token"):
        ost.save_auth0_session(email, access_token=access,
                               refresh_token=tokens["refresh_token"],
                               expires_at=time.time() + int(tokens.get("expires_in") or 3600))
    return access


def _access_token(email: str) -> str:
    session = ost.get_auth0_session(email)
    if not session:
        raise ConnectorError("Your session has ended. Reconnect RecallCards in Claude's connector settings.")
    if session.get("expires_at", 0) > time.time() + 30:
        return session["access_token"]
    refresh = session.get("refresh_token")
    if refresh:
        access = _refresh_access(email, refresh)
        if access:
            return access
    raise ConnectorError("Your session expired. Reconnect RecallCards in Claude's connector settings.")


# --- HTTP to the REST API -------------------------------------------------

def _call(email: str, method: str, path: str, *, params: dict | None = None,
          body: dict | None = None) -> Any:
    url = f"{API_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {_access_token(email)}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    except Exception as e:
        raise ConnectorError(f"Could not reach RecallCards ({e}).")

    parsed: Any = None
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None

    if status == 401:
        raise ConnectorError("RecallCards did not accept the session. Reconnect it in Claude.")
    msg = parsed.get("error") if isinstance(parsed, dict) else None
    # The API sometimes signals errors with HTTP codes and sometimes with a
    # status field in a 200 body; treat either as an error.
    body_status = parsed.get("status") if isinstance(parsed, dict) else None
    if status >= 400 or (isinstance(body_status, int) and body_status >= 400):
        raise ConnectorError(msg or f"RecallCards returned an error ({status}).")
    return parsed


# --- read -----------------------------------------------------------------

def list_collections(email: str) -> dict:
    """The user's decks: their own and the ones they follow, with the default."""
    data = _call(email, "GET", f"/api/collections/{urllib.parse.quote(email)}")
    return {
        "collections": data.get("collections", []),
        "default": data.get("default_collection"),
        "following": data.get("linked", []),
        "published": data.get("published", []),
    }


def get_cards(email: str, collection: str) -> list[dict]:
    """Every card in one deck: term, definition, and who wrote it when shared."""
    data = _call(email, "GET", "/api/cards", params={"collection": collection})
    return data.get("cards", []) if isinstance(data, dict) else []


def get_progress(email: str, collection: str) -> dict:
    """Study stats for one deck: totals, known, needs-review, accuracy."""
    return _call(email, "GET", "/api/progress", params={"collection": collection})


def list_public_decks(email: str) -> list[dict]:
    """Decks published to the public library that anyone can add."""
    data = _call(email, "GET", "/api/public/decks")
    return data.get("decks", data) if isinstance(data, dict) else data


# --- write: cards ---------------------------------------------------------

def add_card(email: str, collection: str, term: str, definition: str) -> dict:
    _call(email, "POST", "/api/sendwords",
          body={"word": term, "ans": definition, "collection": collection})
    return {"ok": True, "collection": collection, "term": term}


def edit_card(email: str, collection: str, term: str, new_term: str, definition: str) -> dict:
    _call(email, "POST", "/api/editword",
          body={"oldword": term, "word": new_term or term, "ans": definition,
                "collection": collection})
    return {"ok": True, "collection": collection, "term": new_term or term}


def delete_card(email: str, collection: str, term: str) -> dict:
    _call(email, "DELETE", f"/api/delword/{urllib.parse.quote(term)}",
          body={"collection": collection})
    return {"ok": True, "collection": collection, "removed": term}


def record_review(email: str, collection: str, term: str, outcome: str) -> dict:
    if outcome not in ("correct", "incorrect"):
        raise ConnectorError("outcome must be 'correct' or 'incorrect'.")
    return _call(email, "POST", "/api/review",
                 body={"word": term, "outcome": outcome, "collection": collection})


# --- write: collections ---------------------------------------------------

def create_collection(email: str, name: str) -> dict:
    _call(email, "POST", "/api/collections", body={"collection_name": name})
    return {"ok": True, "collection": name}


def rename_collection(email: str, old_name: str, new_name: str) -> dict:
    _call(email, "PUT", f"/api/collections/{urllib.parse.quote(old_name)}/rename",
          body={"new_collection_name": new_name})
    return {"ok": True, "from": old_name, "to": new_name}


def delete_collection(email: str, name: str) -> dict:
    _call(email, "DELETE", f"/api/collections/{urllib.parse.quote(name)}")
    return {"ok": True, "removed": name}


# --- sharing --------------------------------------------------------------

def share_deck(email: str, collection: str, allow_edit: bool = False) -> dict:
    data = _call(email, "POST", f"/api/collections/{urllib.parse.quote(collection)}/share",
                 body={"allow_edit": bool(allow_edit)})
    share_id = data.get("share_id") if isinstance(data, dict) else None
    return {
        "ok": True,
        "collection": collection,
        "allow_edit": bool(allow_edit),
        "share_id": share_id,
        "link": f"{PUBLIC_URL}/import/{share_id}" if share_id else None,
    }


def publish_deck(email: str, collection: str, public: bool = True) -> dict:
    _call(email, "POST", f"/api/collections/{urllib.parse.quote(collection)}/publish",
          body={"public": bool(public)})
    return {"ok": True, "collection": collection, "public": bool(public)}


def follow_deck(email: str, share_id: str) -> dict:
    return _call(email, "POST", f"/api/shares/{urllib.parse.quote(share_id)}/follow")
