"""Local accounts: sign up, confirm the email, sign in, stay signed in.

Replaces Auth0. Everything lives in the MongoDB the cards already use:

  users            one document per account
                   {email, password_hash, verified, name, created_at,
                    verify_token_hash, verify_expires,
                    reset_token_hash, reset_expires, password_changed_at}
  auth_sessions    one document per refresh token (hashed), with a TTL index

The flow:

  POST /api/auth/signup    -> account created unverified, link emailed
  POST /api/auth/verify    -> link's token checked, account activated, signed in
  POST /api/auth/login     -> email + password, only for activated accounts
  POST /api/auth/refresh   -> a refresh token for a new pair (rotated, single use)
  POST /api/auth/logout    -> the refresh token is revoked
  POST /api/auth/forgot-password, /reset-password -> reset by emailed link
  GET  /api/auth/me        -> who the access token belongs to

Cards are keyed by email, so someone who used the site under Auth0 signs up
again with the same address, confirms it, and finds their decks where they
left them. Confirming the address is what proves the decks are theirs.

Only hashes of the emailed and refresh tokens are stored: a copy of the
database is not a way into anyone's account.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import quote

from flask import Blueprint, jsonify, request
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from werkzeug.security import check_password_hash, generate_password_hash

import auth
import mailer

logger = logging.getLogger(__name__)

bp = Blueprint('accounts', __name__, url_prefix='/api/auth')

VERIFY_TTL_HOURS = int(os.environ.get('VERIFY_TOKEN_TTL_HOURS', '48'))
RESET_TTL_MINUTES = int(os.environ.get('RESET_TOKEN_TTL_MINUTES', '60'))
REFRESH_TTL_DAYS = int(os.environ.get('REFRESH_TOKEN_TTL_DAYS', '60'))
PASSWORD_MIN = 8
PASSWORD_MAX = 128
HASH_METHOD = 'pbkdf2:sha256:600000'

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

users = None
sessions = None

# Compared against when no account matches, so a missing account takes as
# long to refuse as a wrong password and the timing gives nothing away.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16), method=HASH_METHOD)


def init(db, background=True):
    """Point the module at the database and make sure its indexes exist.

    Index creation waits for the server, so by default it runs off the import
    path: the API starts even while MongoDB is still coming up."""
    global users, sessions
    users = db.users
    sessions = db.auth_sessions

    def ensure_indexes():
        try:
            users.create_index('email', unique=True)
            users.create_index('verify_token_hash', sparse=True)
            users.create_index('reset_token_hash', sparse=True)
            sessions.create_index('token_hash', unique=True)
            sessions.create_index('email')
            sessions.create_index('expires_at', expireAfterSeconds=0)
        except Exception as exc:  # the API still serves cards without them
            logger.error('could not create account indexes: %s', exc)

    if background:
        threading.Thread(target=ensure_indexes, name='account-indexes', daemon=True).start()
    else:
        ensure_indexes()


# --- Small helpers ----------------------------------------------------------

def _now():
    return datetime.utcnow()


def _error(status, message, code=None):
    body = {'status': status, 'error': message}
    if code:
        body['code'] = code
    response = jsonify(body)
    response.status_code = status
    return response


def _body():
    return request.get_json(silent=True) or {}


def _email(value):
    email = (value or '').strip().lower() if isinstance(value, str) else ''
    if not email or len(email) > 254 or not EMAIL_RE.match(email):
        return None
    return email


def _password_problem(password):
    if not isinstance(password, str) or len(password) < PASSWORD_MIN:
        return f'Use at least {PASSWORD_MIN} characters for your password.'
    if len(password) > PASSWORD_MAX:
        return f'Use at most {PASSWORD_MAX} characters for your password.'
    return None


def _hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _app_url():
    """Where the links in emails point. Never taken from the request in
    production: an attacker-chosen Origin would put a victim's token in a link
    to the attacker's site."""
    configured = os.environ.get('APP_URL', '').strip().rstrip('/')
    if configured:
        return configured
    if auth._is_production():
        return 'https://recallcards.net'
    return 'http://localhost:3001'


def _link(path, token):
    return f'{_app_url()}{path}?token={quote(token)}'


def _public_user(doc):
    return {
        'email': doc['email'],
        'name': doc.get('name') or None,
        'email_verified': bool(doc.get('verified')),
        'created_at': doc['created_at'].isoformat() + 'Z' if doc.get('created_at') else None,
    }


def _db_ready():
    return users is not None and sessions is not None


# --- Rate limiting ----------------------------------------------------------
#
# In memory, per process: the API runs as one process, and the point is to
# stop password guessing and email bombing, not to be exact.

class _Limiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits = defaultdict(deque)

    def allow(self, key, limit, window):
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            if len(self._hits) > 50000:  # forget idle keys
                for stale in [k for k, v in self._hits.items() if not v or v[-1] <= now - 3600]:
                    self._hits.pop(stale, None)
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = _Limiter()


def _client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.headers.get('X-Real-IP') or request.remote_addr or 'unknown'


def _limited(*rules):
    """rules: (key, limit, window_seconds). True if any is exceeded."""
    return not all(limiter.allow(key, limit, window) for key, limit, window in rules)


TOO_MANY = 'Too many attempts. Wait a few minutes and try again.'


# --- Sessions ---------------------------------------------------------------

def _issue_session(user_doc):
    email = user_doc['email']
    access, expires_in = auth.issue_access_token(email)
    refresh = secrets.token_urlsafe(48)
    now = _now()
    sessions.insert_one({
        'token_hash': _hash_token(refresh),
        'email': email,
        'created_at': now,
        'expires_at': now + timedelta(days=REFRESH_TTL_DAYS),
        'user_agent': (request.headers.get('User-Agent') or '')[:200],
    })
    return {
        'status': 200,
        'access_token': access,
        'token_type': 'Bearer',
        'expires_in': expires_in,
        'refresh_token': refresh,
        'refresh_expires_in': REFRESH_TTL_DAYS * 86400,
        'user': _public_user(user_doc),
    }


def _send_verification(user_doc):
    """Give the account a fresh link and email it. Raises mailer.MailError."""
    token = secrets.token_urlsafe(32)
    users.update_one({'_id': user_doc['_id']}, {'$set': {
        'verify_token_hash': _hash_token(token),
        'verify_expires': _now() + timedelta(hours=VERIFY_TTL_HOURS),
    }})
    mailer.send_verification(user_doc['email'], _link('/verify-email', token), VERIFY_TTL_HOURS)


CHECK_EMAIL = 'Check your inbox for a link to activate your account.'
MAIL_FAILED = 'We could not send the email just now. Try again in a minute.'


# --- Routes -----------------------------------------------------------------

@bp.route('/signup', methods=['POST'])
def signup():
    if not _db_ready():
        return _error(500, 'Database not connected')

    data = _body()
    email = _email(data.get('email'))
    if not email:
        return _error(400, 'Enter a valid email address.', 'invalid_email')
    problem = _password_problem(data.get('password'))
    if problem:
        return _error(400, problem, 'weak_password')
    name = (data.get('name') or '').strip()[:60] if isinstance(data.get('name'), str) else ''

    ip = _client_ip()
    if _limited((f'signup:ip:{ip}', 10, 3600), (f'signup:email:{email}', 3, 3600)):
        return _error(429, TOO_MANY, 'rate_limited')

    existing = users.find_one({'email': email})

    # The same answer whatever the address's state, so signup cannot be used
    # to find out who has an account. The email itself says what happened.
    if existing and existing.get('verified'):
        try:
            mailer.send_already_registered(email, f'{_app_url()}/login', f'{_app_url()}/forgot-password')
        except mailer.MailError as exc:
            logger.error('already-registered mail to %s failed: %s', email, exc)
        return jsonify({'status': 200, 'message': CHECK_EMAIL})

    if existing:
        # Pending and unconfirmed: resend, but keep the password the first
        # signup chose. Replacing it would let anyone who knows the address set
        # the password of an account its owner is about to activate. An owner
        # who forgot what they typed uses "forgot password", which also
        # activates the account.
        user_doc = existing
    else:
        user_doc = {
            'email': email,
            'password_hash': generate_password_hash(data['password'], method=HASH_METHOD),
            'verified': False,
            'name': name or None,
            'created_at': _now(),
        }
        try:
            user_doc['_id'] = users.insert_one(user_doc).inserted_id
        except DuplicateKeyError:  # a double submit raced us
            user_doc = users.find_one({'email': email})

    try:
        _send_verification(user_doc)
    except mailer.MailError as exc:
        logger.error('verification mail to %s failed: %s', email, exc)
        return _error(502, MAIL_FAILED, 'mail_failed')
    return jsonify({'status': 200, 'message': CHECK_EMAIL})


@bp.route('/verify', methods=['POST'])
def verify():
    if not _db_ready():
        return _error(500, 'Database not connected')
    if _limited((f'verify:ip:{_client_ip()}', 30, 600)):
        return _error(429, TOO_MANY, 'rate_limited')

    token = _body().get('token')
    if not isinstance(token, str) or not token:
        return _error(400, 'This link is missing its code.', 'invalid_token')

    user_doc = users.find_one_and_update(
        {'verify_token_hash': _hash_token(token), 'verify_expires': {'$gt': _now()}},
        {'$set': {'verified': True, 'verified_at': _now()},
         '$unset': {'verify_token_hash': '', 'verify_expires': ''}},
        return_document=ReturnDocument.AFTER,
    )
    if not user_doc:
        return _error(400, 'This link has expired or was already used.', 'invalid_token')
    logger.info('account activated: %s', user_doc['email'])
    return jsonify(_issue_session(user_doc))


@bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    if not _db_ready():
        return _error(500, 'Database not connected')

    email = _email(_body().get('email'))
    if not email:
        return _error(400, 'Enter a valid email address.', 'invalid_email')
    if _limited((f'resend:ip:{_client_ip()}', 10, 3600), (f'resend:email:{email}', 3, 3600)):
        return _error(429, TOO_MANY, 'rate_limited')

    user_doc = users.find_one({'email': email})
    if user_doc and not user_doc.get('verified'):
        try:
            _send_verification(user_doc)
        except mailer.MailError as exc:
            logger.error('verification resend to %s failed: %s', email, exc)
            return _error(502, MAIL_FAILED, 'mail_failed')
    return jsonify({'status': 200, 'message': 'If that account is waiting to be activated, a new link is on its way.'})


@bp.route('/login', methods=['POST'])
def login():
    if not _db_ready():
        return _error(500, 'Database not connected')

    data = _body()
    email = _email(data.get('email'))
    password = data.get('password') if isinstance(data.get('password'), str) else ''
    if not email or not password:
        return _error(400, 'Enter your email and password.', 'missing_credentials')

    ip = _client_ip()
    if _limited((f'login:ip:{ip}', 60, 900), (f'login:email:{email}', 10, 900)):
        return _error(429, TOO_MANY, 'rate_limited')

    user_doc = users.find_one({'email': email})
    stored = (user_doc or {}).get('password_hash') or _DUMMY_HASH
    if not check_password_hash(stored, password[:PASSWORD_MAX]) or not user_doc:
        return _error(401, 'Incorrect email or password.', 'invalid_credentials')
    if not user_doc.get('verified'):
        return _error(403, 'Confirm your email first. We sent you a link when you signed up.',
                      'email_not_verified')
    return jsonify(_issue_session(user_doc))


@bp.route('/refresh', methods=['POST'])
def refresh():
    if not _db_ready():
        return _error(500, 'Database not connected')

    token = _body().get('refresh_token')
    if not isinstance(token, str) or not token:
        return _error(401, 'Sign in again.', 'invalid_refresh')

    # Single use: taking the session out is what makes rotation atomic, so a
    # stolen refresh token stops working the next time its owner refreshes.
    old = sessions.find_one_and_delete({'token_hash': _hash_token(token), 'expires_at': {'$gt': _now()}})
    if not old:
        return _error(401, 'Your session has ended. Sign in again.', 'invalid_refresh')

    user_doc = users.find_one({'email': old['email']})
    if not user_doc or not user_doc.get('verified'):
        return _error(401, 'Your session has ended. Sign in again.', 'invalid_refresh')
    return jsonify(_issue_session(user_doc))


@bp.route('/logout', methods=['POST'])
def logout():
    if not _db_ready():
        return _error(500, 'Database not connected')
    token = _body().get('refresh_token')
    if isinstance(token, str) and token:
        sessions.delete_one({'token_hash': _hash_token(token)})
    return jsonify({'status': 200})


@bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    if not _db_ready():
        return _error(500, 'Database not connected')

    email = _email(_body().get('email'))
    if not email:
        return _error(400, 'Enter a valid email address.', 'invalid_email')
    if _limited((f'forgot:ip:{_client_ip()}', 10, 3600), (f'forgot:email:{email}', 3, 3600)):
        return _error(429, TOO_MANY, 'rate_limited')

    user_doc = users.find_one({'email': email})
    if user_doc:
        token = secrets.token_urlsafe(32)
        users.update_one({'_id': user_doc['_id']}, {'$set': {
            'reset_token_hash': _hash_token(token),
            'reset_expires': _now() + timedelta(minutes=RESET_TTL_MINUTES),
        }})
        try:
            mailer.send_password_reset(email, _link('/reset-password', token), RESET_TTL_MINUTES)
        except mailer.MailError as exc:
            logger.error('reset mail to %s failed: %s', email, exc)
            return _error(502, MAIL_FAILED, 'mail_failed')
    return jsonify({'status': 200, 'message': 'If there is an account for that address, a reset link is on its way.'})


@bp.route('/reset-password', methods=['POST'])
def reset_password():
    if not _db_ready():
        return _error(500, 'Database not connected')
    if _limited((f'reset:ip:{_client_ip()}', 30, 600)):
        return _error(429, TOO_MANY, 'rate_limited')

    data = _body()
    token = data.get('token')
    if not isinstance(token, str) or not token:
        return _error(400, 'This link is missing its code.', 'invalid_token')
    problem = _password_problem(data.get('password'))
    if problem:
        return _error(400, problem, 'weak_password')

    user_doc = users.find_one_and_update(
        {'reset_token_hash': _hash_token(token), 'reset_expires': {'$gt': _now()}},
        {'$set': {
            'password_hash': generate_password_hash(data['password'], method=HASH_METHOD),
            'password_changed_at': _now(),
            # Following an emailed link proves the address as well as signing up does.
            'verified': True,
        },
         '$unset': {'reset_token_hash': '', 'reset_expires': '',
                    'verify_token_hash': '', 'verify_expires': ''}},
        return_document=ReturnDocument.AFTER,
    )
    if not user_doc:
        return _error(400, 'This link has expired or was already used.', 'invalid_token')

    # A new password signs out every other device.
    sessions.delete_many({'email': user_doc['email']})
    return jsonify(_issue_session(user_doc))


@bp.route('/me', methods=['GET'])
@auth.requires_auth
def me():
    if not _db_ready():
        return _error(500, 'Database not connected')
    user_doc = users.find_one({'email': auth.caller_email()})
    if not user_doc:
        return _error(401, 'Your account no longer exists.', 'unknown_user')
    return jsonify({'status': 200, 'user': _public_user(user_doc)})
