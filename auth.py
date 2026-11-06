"""Who is calling, established from a verified token rather than from a parameter.

Every data route used to take the caller's identity as an argument: `email=` in
a query string, or a field named `token` that in fact held the address. Nothing
verified it, so knowing an address was the same as owning the account. These
helpers replace that: the caller presents an access token this API issued
itself (see accounts.py), the signature is checked, and the address comes out
of the verified token. A client-supplied address is then worth nothing.

Access tokens are short-lived HS256 JWTs signed with JWT_SECRET. They carry the
address in `sub`, so verifying one needs no database or network call. Sessions
outlive them through refresh tokens, which accounts.py stores and rotates.
"""
from __future__ import annotations

import logging
import os
import secrets
import time

from functools import wraps

from flask import request
from jose import jwt

logger = logging.getLogger(__name__)

ALGORITHM = 'HS256'
ISSUER = os.environ.get('AUTH_ISSUER', 'recallcards')
AUDIENCE = os.environ.get('AUTH_AUDIENCE', 'recallcards-api')
ACCESS_TOKEN_TTL = int(os.environ.get('ACCESS_TOKEN_TTL', str(60 * 60)))


def _is_production():
    return os.environ.get('FLASK_ENV', '').strip().lower() == 'production'


def _load_secret():
    secret = os.environ.get('JWT_SECRET', '').strip()
    if secret:
        if len(secret) < 32:
            raise RuntimeError('JWT_SECRET must be at least 32 characters.')
        return secret
    if _is_production():
        # Refuse to start rather than sign tokens with a key nobody chose.
        raise RuntimeError('JWT_SECRET must be set in production.')
    logger.warning('JWT_SECRET is not set; using a random key. Sessions end when the server restarts.')
    return secrets.token_urlsafe(48)


JWT_SECRET = _load_secret()

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


# --- Tokens ---------------------------------------------------------------

def issue_access_token(email, now=None):
    """A signed access token for a verified account. Returns (token, expires_in)."""
    now = int(now if now is not None else time.time())
    claims = {
        'sub': email,
        'email': email,
        'typ': 'access',
        'iss': ISSUER,
        'aud': AUDIENCE,
        'iat': now,
        'exp': now + ACCESS_TOKEN_TTL,
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=ALGORITHM), ACCESS_TOKEN_TTL


def verify_access_token(token):
    """Return the verified claims, or raise AuthError."""
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise _unauthorized('invalid_header', 'The token could not be read.')
    # Pinned below as well; checked here so the reason is clear.
    if header.get('alg') != ALGORITHM:
        raise _unauthorized('invalid_header', 'The token uses an unexpected algorithm.')

    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM], audience=AUDIENCE, issuer=ISSUER)
    except jwt.ExpiredSignatureError:
        raise _unauthorized('token_expired', 'The token has expired.')
    except jwt.JWTClaimsError:
        raise _unauthorized('invalid_claims', 'The token is not for this API.')
    except Exception:
        raise _unauthorized('invalid_token', 'The token could not be verified.')

    if claims.get('typ') != 'access':
        raise _unauthorized('invalid_token', 'This is not an access token.')
    return claims


def email_from_claims(claims):
    email = claims.get('sub')
    if not isinstance(email, str) or not email.strip():
        raise _unauthorized('email_missing', 'The token carries no email address.')
    return email.strip().lower()


# --- The caller -------------------------------------------------------------

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
    if _is_production():
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
        return email_from_claims(verify_access_token(token))
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
