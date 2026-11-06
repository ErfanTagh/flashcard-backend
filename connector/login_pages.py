"""
Connector login, with a RecallCards account.

The flow:

  Claude -> provider.authorize() -> /connector/login?state=S
    GET  /connector/login : a sign-in form (email + password) carrying S
    POST /connector/login : the connector signs in to the RecallCards API
                            (POST /api/auth/login) on the user's behalf, keeps
                            the API access + refresh tokens for that email, then
                            complete_login(S, email) -> back to Claude.

The password goes from the form to the API and nowhere else; the connector
keeps only the API's tokens. It never reads or writes card data directly: every
tool calls the RecallCards REST API with that access token, which the API
verifies and scopes to the same email. The MCP token Claude holds carries only
the email.
"""
from __future__ import annotations

import html
import json
import time
import urllib.error
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
API_URL: str | None = None
_oauth: "RecallcardsOAuthProvider | None" = None
_ost = None  # the oauth_store module


def configure(*, public_url: str, site_url: str, api_url: str, oauth_provider, ost) -> None:
    global PUBLIC_URL, SITE_URL, API_URL, _oauth, _ost
    PUBLIC_URL = public_url.rstrip("/")
    SITE_URL = site_url.rstrip("/")
    API_URL = api_url.rstrip("/")
    _oauth = oauth_provider
    _ost = ost


_STYLE = """
body{margin:0;background:#f6f6f7;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#1c1917}
.card{max-width:24rem;margin:4rem auto;background:#fff;border-radius:14px;padding:2rem;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:1.25rem;margin:.25rem 0 1.25rem} .brand{color:#ec3d6e;font-weight:700}
label{display:block;font-size:.85rem;font-weight:600;margin:.9rem 0 .35rem}
input{box-sizing:border-box;width:100%;padding:.65rem .75rem;border:1px solid #d4d4d8;border-radius:8px;font-size:1rem}
button{margin-top:1.25rem;width:100%;padding:.75rem;border:0;border-radius:8px;background:#ec3d6e;color:#fff;font-weight:600;font-size:1rem;cursor:pointer}
.err{background:#fef2f2;color:#b91c1c;border-radius:8px;padding:.6rem .75rem;font-size:.9rem;margin-bottom:.5rem}
.links{margin-top:1.25rem;font-size:.85rem;color:#656d7c;text-align:center} .links a{color:#ec3d6e}
"""


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>Sign in to RecallCards</title><style>{_STYLE}</style></head>"
        f"<body><div class='card'>{body}</div></body></html>",
        status_code=status,
    )


def _err(msg: str, status: int = 400) -> HTMLResponse:
    return _page(
        f"<div class='brand'>RecallCards</div><p>{html.escape(msg)}</p>"
        "<p style='color:#656d7c;font-size:.9rem'>Try connecting again from Claude.</p>",
        status=status,
    )


def _form(state: str, email: str = "", error: str = "", status: int = 200) -> HTMLResponse:
    site = html.escape(SITE_URL or "")
    error_html = f"<div class='err'>{html.escape(error)}</div>" if error else ""
    return _page(
        "<div class='brand'>RecallCards</div>"
        "<h1>Sign in to connect Claude</h1>"
        f"{error_html}"
        "<form method='post' action='/connector/login'>"
        f"<input type='hidden' name='state' value='{html.escape(state)}'>"
        "<label for='email'>Email</label>"
        f"<input id='email' name='email' type='email' autocomplete='email' required value='{html.escape(email)}'>"
        "<label for='password'>Password</label>"
        "<input id='password' name='password' type='password' autocomplete='current-password' required>"
        "<button type='submit'>Sign in and connect</button>"
        "</form>"
        "<div class='links'>"
        f"<a href='{site}/signup' target='_blank' rel='noopener'>Create an account</a> · "
        f"<a href='{site}/forgot-password' target='_blank' rel='noopener'>Forgot password?</a>"
        "</div>",
        status=status,
    )


async def login_page(request: Request) -> Response:
    """Entry from provider.authorize(): show the sign-in form."""
    state = request.query_params.get("state") or ""
    if not state:
        return _err("Missing login state.")
    payload = await anyio.to_thread.run_sync(_ost.peek_login_state, state)
    if not payload:
        return _err("This sign-in link has expired.")
    return _form(state)


def _api_login(email: str, password: str) -> tuple[dict | None, str]:
    """Sign in to the API. Returns (token set, error message). Runs in a thread."""
    req = urllib.request.Request(
        f"{API_URL}/api/auth/login",
        data=json.dumps({"email": email, "password": password}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()), ""
    except urllib.error.HTTPError as e:
        try:
            message = json.loads(e.read()).get("error") or ""
        except Exception:
            message = ""
        return None, message or f"Sign-in failed (error {e.code})."
    except Exception:
        return None, "Could not reach RecallCards. Try again in a moment."


async def login_submit(request: Request) -> Response:
    """The form posts here: sign in to the API, then hand Claude its code."""
    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", "replace"))
    state = (form.get("state") or [""])[0]
    email = (form.get("email") or [""])[0].strip().lower()
    password = (form.get("password") or [""])[0]

    if not state:
        return _err("Missing login state.")
    payload = await anyio.to_thread.run_sync(_ost.peek_login_state, state)
    if not payload:
        return _err("This sign-in has expired.")
    if not email or not password:
        return _form(state, email, "Enter your email and password.", status=400)

    tokens, message = await anyio.to_thread.run_sync(_api_login, email, password)
    if not tokens or not tokens.get("access_token"):
        return _form(state, email, message or "Sign-in failed.", status=401)

    # The account the API vouched for, not the one typed into the form.
    email = ((tokens.get("user") or {}).get("email") or email).strip().lower()
    await anyio.to_thread.run_sync(lambda: _ost.save_api_session(
        email,
        access_token=tokens["access_token"],
        refresh_token=tokens.get("refresh_token"),
        expires_at=time.time() + int(tokens.get("expires_in") or 3600),
    ))

    try:
        redirect_url = await _oauth.complete_login(state, email)
    except ValueError:
        return _err("This sign-in has expired.")
    return RedirectResponse(url=redirect_url, status_code=303)
