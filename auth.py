"""Who is calling, established from a verified token rather than from a parameter.

Every data route used to take the caller's identity as an argument: `email=` in
a query string, or a field named `token` that in fact held the address. Nothing
verified it, so knowing an address was the same as owning the account. These
helpers replace that: the caller presents an Auth0 access token, the signature
is checked against Auth0's published keys, and the address comes out of the
verified token. A client-supplied address is then worth nothing.

The address is not in the access token by default. Auth0 puts the user id in
`sub`; `email` only appears if a custom claim adds it. Both paths are supported
-- a claim if one is configured, otherwise one `/userinfo` call per token,
cached for as long as the token is valid -- so this works whether or not the
Auth0 tenant has been given an action.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request

from functools import wraps

from flask import request
from jose import jwt

logger = logging.getLogger(__name__)

AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', 'dev-43bumhcy.us.auth0.com')
API_AUDIENCE = os.environ.get('AUTH0_AUDIENCE', 'recallcards')
ALGORITHMS = ['RS256']

# An Auth0 action can add the address to the access token under a namespaced
# claim. If one is configured there is no /userinfo round trip at all.
EMAIL_CLAIM = os.environ.get('AUTH0_EMAIL_CLAIM', 'https://recallcards.net/email')

HTTP_TIMEOUT = float(os.environ.get('AUTH0_HTTP_TIMEOUT', '5'))
JWKS_TTL = float(os.environ.get('AUTH0_JWKS_TTL', '3600'))
USERINFO_TTL = float(os.environ.get('AUTH0_USERINFO_TTL', '3600'))

# Local development only. With this set, an unauthenticated request may name
# its own user, which is exactly the hole this module exists to close -- so it
# is opt-in, off by default, and refused outright when FLASK_ENV says
# production.
DEV_AUTH_BYPASS = os.environ.get('RECALLCARDS_DEV_AUTH', '').strip().lower() in ('1', 'true', 'yes')


class AuthError(Exception):
    """Raised with the body and status Flask should return."""

    def __init__(self, error, status_code):
        super().__init__(error.get('description', ''))
        self.error = error
        self.status_code = status_code


def _unauthorized(code, description):
    return AuthError({'code': code, 'description': description}, 401)


# --- Auth0's signing keys -------------------------------------------------
#
# Fetched once and kept. The previous implementation fetched the key set on
# every single request, with no timeout: a request to this API could not be
# served faster than a round trip to Auth0, and an Auth0 slowdown became an
# outage here.

_jwks_lock = threading.Lock()
_jwks_cache: dict | None = None
_jwks_fetched_at = 0.0


def _fetch_jwks():
    url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
    with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as response:
        return json.loads(response.read())


def _jwks(force_refresh=False):
    global _jwks_cache, _jwks_fetched_at

    with _jwks_lock:
        fresh = _jwks_cache is not None and (time.monotonic() - _jwks_fetched_at) < JWKS_TTL
        if fresh and not force_refresh:
            return _jwks_cache

        try:
            _jwks_cache = _fetch_jwks()
            _jwks_fetched_at = time.monotonic()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # Serve a stale key set rather than locking every user out over a
            # blip: the keys rotate on the order of months.
            if _jwks_cache is not None:
                logger.warning('could not refresh Auth0 JWKS (%s), using cached keys', exc)
                return _jwks_cache
            raise _unauthorized('jwks_unavailable', 'Could not reach the identity provider.')

        return _jwks_cache


def _signing_key(token):
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise _unauthorized('invalid_header', 'The token could not be read.')

    kid = header.get('kid')
    if not kid:
        raise _unauthorized('invalid_header', 'The token names no signing key.')

    # An unknown kid most likely means the keys rotated since the last fetch,
    # so look again once before giving up.
    for force_refresh in (False, True):
        for key in _jwks(force_refresh).get('keys', []):
            if key.get('kid') == kid:
                return {k: key[k] for k in ('kty', 'kid', 'use', 'n', 'e') if k in key}

    raise _unauthorized('invalid_header', 'The token was signed by an unknown key.')


def verify_access_token(token):
    """Return the verified claims, or raise AuthError."""
    key = _signing_key(token)
    try:
        return jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f'https://{AUTH0_DOMAIN}/',
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized('token_expired', 'The token has expired.')
    except jwt.JWTClaimsError:
        raise _unauthorized('invalid_claims', 'The token is not for this API.')
    except Exception:
        raise _unauthorized('invalid_token', 'The token could not be verified.')


# --- The address behind a token -------------------------------------------

_userinfo_lock = threading.Lock()
_userinfo_cache: dict[str, tuple[str, float]] = {}


def _userinfo_email(token, claims):
    """Ask Auth0 for the address, once per token."""
    cache_key = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now = time.time()

    with _userinfo_lock:
        cached = _userinfo_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

    request_obj = urllib.request.Request(
        f'https://{AUTH0_DOMAIN}/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=HTTP_TIMEOUT) as response:
            profile = json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning('could not resolve the caller address via /userinfo: %s', exc)
        raise _unauthorized('email_unavailable', 'Could not establish who the token belongs to.')

    email = (profile.get('email') or '').strip().lower()
    if not email:
        raise _unauthorized('email_missing', 'The token carries no email address.')

    # Never outlive the token itself, and never cache for longer than the TTL.
    expiry = min(float(claims.get('exp', now + USERINFO_TTL)), now + USERINFO_TTL)
    with _userinfo_lock:
        _userinfo_cache[cache_key] = (email, expiry)
        if len(_userinfo_cache) > 2048:
            for stale_key in [k for k, (_, exp) in _userinfo_cache.items() if exp <= now]:
                _userinfo_cache.pop(stale_key, None)

    return email


def email_from_claims(claims, token):
    """The caller's address: a custom claim if the tenant sets one, else /userinfo."""
    for field in (EMAIL_CLAIM, 'email'):
        value = claims.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return _userinfo_email(token, claims)


def _bearer_token():
    header = request.headers.get('Authorization', '')
    if not header:
        return None

    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        raise _unauthorized('invalid_header', 'Expected an Authorization header of "Bearer <token>".')
    return parts[1]


def _dev_email():
    """The address a local developer is pretending to be, if that is switched on."""
    if not DEV_AUTH_BYPASS:
        return None
    if os.environ.get('FLASK_ENV', '').strip().lower() == 'production':
        logger.error('RECALLCARDS_DEV_AUTH is set in a production environment; ignoring it')
        return None

    stated = request.headers.get('X-Dev-User')
    if not stated:
        body = request.get_json(silent=True) or {}
        stated = body.get('token') or body.get('email') or request.args.get('email')
    stated = (stated or '').strip().lower()
    if stated:
        logger.warning('dev auth bypass: treating this request as %s', stated)
    return stated or None


def resolve_caller():
    """The verified address of the caller, or None when they present nothing."""
    token = _bearer_token()
    if token:
        return email_from_claims(verify_access_token(token), token)
    return _dev_email()


def requires_auth(view):
    """Reject anyone who cannot prove who they are; set `request.caller_email`."""

    @wraps(view)
    def decorated(*args, **kwargs):
        email = resolve_caller()
        if not email:
            raise _unauthorized('authorization_header_missing', 'An Authorization header is expected.')
        request.caller_email = email
        return view(*args, **kwargs)

    return decorated


def optional_auth(view):
    """For routes a signed-out visitor may read, such as a share link.

    `request.caller_email` is the verified address or None. A *broken* token is
    still an error -- quietly treating it as "signed out" would hide an expired
    session behind a page that looks like it worked.
    """

    @wraps(view)
    def decorated(*args, **kwargs):
        request.caller_email = resolve_caller()
        return view(*args, **kwargs)

    return decorated


def caller_email():
    """The caller's address, set by the decorators above."""
    return getattr(request, 'caller_email', None)
