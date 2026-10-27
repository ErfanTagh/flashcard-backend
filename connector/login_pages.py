"""
Connector login, via Auth0.

RecallCards has no password store of its own -- the website signs in through
Auth0 -- so the connector does the same. The flow:

  Claude -> provider.authorize() -> /connector/login?state=S
    /connector/login : make a PKCE pair, stash the verifier on login-state S,
                       send the browser to Auth0 /authorize (state=S), asking
                       for an access token for the RecallCards API (audience)
                       plus offline_access so the connector can renew it.
    Auth0 login ...
    /connector/oauth/done?code=C&state=S : exchange C at Auth0 for the tokens,
                       read the user's verified email from the id token, keep
                       the API access + refresh tokens for that email, then
                       complete_login(S, email) -> back to Claude.

The connector never reads or writes the database directly: every tool calls the
RecallCards REST API with that access token, which the API verifies and scopes
to the same email. The MCP token Claude holds carries only the email.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

import anyio
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

if TYPE_CHECKING:
    from connector.oauth_provider import RecallcardsOAuthProvider

PUBLIC_URL: str | None = None
SITE_URL: str | None = None
AUTH0_DOMAIN: str | None = None
AUTH0_AUDIENCE: str | None = None
CLIENT_ID: str | None = None
CLIENT_SECRET: str | None = None
_oauth: "RecallcardsOAuthProvider | None" = None
_ost = None  # the oauth_store module


def configure(*, public_url: str, site_url: str, oauth_provider, auth0_domain: str,
              auth0_audience: str, client_id: str, client_secret: str, ost) -> None:
    global PUBLIC_URL, SITE_URL, AUTH0_DOMAIN, AUTH0_AUDIENCE, CLIENT_ID, CLIENT_SECRET, _oauth, _ost
    PUBLIC_URL = public_url.rstrip("/")
    SITE_URL = site_url.rstrip("/")
    AUTH0_DOMAIN = auth0_domain
    AUTH0_AUDIENCE = auth0_audience
    CLIENT_ID = client_id
    CLIENT_SECRET = client_secret
    _oauth = oauth_provider
    _ost = ost


def _redirect_uri() -> str:
    return f"{PUBLIC_URL}/connector/oauth/done"


def _err(msg: str, status: int = 400) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><meta charset='utf-8'><div style='font-family:system-ui;"
        f"max-width:28rem;margin:4rem auto;text-align:center;color:#1c1917'>"
        f"<h2 style='color:#ec3d6e'>RecallCards</h2><p>{msg}</p>"
        f"<p style='color:#656d7c;font-size:.9rem'>Try connecting again from Claude.</p></div>",
        status_code=status,
    )


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    return verifier, challenge


async def login_page(request: Request) -> Response:
    """Entry from provider.authorize(): start the Auth0 round trip."""
    state = request.query_params.get("state") or ""
    if not state:
        return _err("Missing login state.")
    if not CLIENT_ID or not AUTH0_DOMAIN:
        return _err("The connector is not configured for sign-in yet.", status=500)

    payload = await anyio.to_thread.run_sync(_ost.peek_login_state, state)
    if not payload:
        return _err("This sign-in link has expired.")

    verifier, challenge = _pkce()
    await anyio.to_thread.run_sync(
        lambda: _ost.update_login_state(state, {"auth0_verifier": verifier})
    )

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": _redirect_uri(),
        # openid+email identify the user; offline_access returns a refresh token
        # so the connector can keep calling the API after the first hour.
        "scope": "openid profile email offline_access",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if AUTH0_AUDIENCE:
        # Ask for an access token the RecallCards API will accept.
        params["audience"] = AUTH0_AUDIENCE
    return RedirectResponse(
        url=f"https://{AUTH0_DOMAIN}/authorize?{urllib.parse.urlencode(params)}",
        status_code=302,
    )


def _exchange_code(code: str, verifier: str) -> dict | None:
    """Swap the Auth0 code for the token set. Runs in a worker thread."""
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": _redirect_uri(),
        "code_verifier": verifier,
    }).encode("ascii")
    req = urllib.request.Request(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _email_from_id_token(id_token: str | None) -> str | None:
    if not id_token or id_token.count(".") != 2:
        return None
    try:
        payload_b64 = id_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None
    return (claims.get("email") or "").strip().lower() or None


def _email_from_userinfo(access_token: str | None) -> str | None:
    if not access_token:
        return None
    req = urllib.request.Request(
        f"https://{AUTH0_DOMAIN}/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            profile = json.loads(resp.read())
    except Exception:
        return None
    return (profile.get("email") or "").strip().lower() or None


def _finish(code: str, verifier: str) -> str | None:
    """Exchange, resolve email, store the API tokens. Returns the email or None."""
    tokens = _exchange_code(code, verifier)
    if not tokens:
        return None
    email = _email_from_id_token(tokens.get("id_token")) or _email_from_userinfo(tokens.get("access_token"))
    if not email:
        return None
    access = tokens.get("access_token")
    if access:
        _ost.save_auth0_session(
            email,
            access_token=access,
            refresh_token=tokens.get("refresh_token"),
            expires_at=time.time() + int(tokens.get("expires_in") or 3600),
        )
    return email


async def oauth_done(request: Request) -> Response:
    """Auth0 redirects here with ?code & ?state (our login state)."""
    if request.query_params.get("error"):
        return _err(request.query_params.get("error_description") or "Sign-in was cancelled.")
    code = request.query_params.get("code") or ""
    state = request.query_params.get("state") or ""
    if not code or not state:
        return _err("Missing code or state from Auth0.")

    payload = await anyio.to_thread.run_sync(_ost.peek_login_state, state)
    if not payload:
        return _err("This sign-in has expired.")
    verifier = payload.get("auth0_verifier")
    if not verifier:
        return _err("Sign-in state is incomplete.")

    email = await anyio.to_thread.run_sync(_finish, code, verifier)
    if not email:
        return _err("Could not confirm your account with Auth0.", status=401)

    try:
        redirect_url = await _oauth.complete_login(state, email)
    except ValueError:
        return _err("This sign-in has expired.")
    return RedirectResponse(url=redirect_url, status_code=302)
