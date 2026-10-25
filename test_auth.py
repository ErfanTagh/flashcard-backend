"""Tests for auth.py: what counts as proof of identity, and what does not.

Run with: python -m pytest test_auth.py   (or: python test_auth.py)

A real RSA key is generated here and a real token signed with it, so the
signature check is exercised rather than mocked. Only the two network calls --
Auth0's key set and /userinfo -- are stubbed.
"""
import base64
import importlib
import json
import os
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from jose.utils import long_to_base64

DOMAIN = 'test-tenant.auth0.com'
AUDIENCE = 'recallcards'
EMAIL_CLAIM = 'https://recallcards.net/email'

os.environ['AUTH0_DOMAIN'] = DOMAIN
os.environ['AUTH0_AUDIENCE'] = AUDIENCE
os.environ['AUTH0_EMAIL_CLAIM'] = EMAIL_CLAIM
os.environ.pop('RECALLCARDS_DEV_AUTH', None)

import auth  # noqa: E402  (imported after the environment is set)
from flask import Flask  # noqa: E402


def _rsa_jwk(private_key, kid):
    numbers = private_key.public_key().public_numbers()
    return {
        'kty': 'RSA',
        'kid': kid,
        'use': 'sig',
        'alg': 'RS256',
        'n': long_to_base64(numbers.n).decode('ascii'),
        'e': long_to_base64(numbers.e).decode('ascii'),
    }


PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = 'test-key-1'


def _pem(key):
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('ascii')


def make_token(key=PRIVATE_KEY, kid=KID, audience=AUDIENCE, issuer=None,
               expires_in=3600, claims=None):
    now = int(time.time())
    payload = {
        'sub': 'auth0|abc123',
        'aud': audience,
        'iss': issuer or f'https://{DOMAIN}/',
        'iat': now,
        'exp': now + expires_in,
    }
    payload.update(claims or {})
    return jwt.encode(payload, _pem(key), algorithm='RS256', headers={'kid': kid})


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        importlib.reload(auth)
        self.app = Flask(__name__)
        self.jwks_fetches = 0
        self.userinfo_calls = 0

        def fake_fetch_jwks():
            self.jwks_fetches += 1
            return {'keys': [_rsa_jwk(PRIVATE_KEY, KID)]}

        auth._fetch_jwks = fake_fetch_jwks

    def _resolve(self, headers=None, json_body=None, query=''):
        with self.app.test_request_context(
            f'/api/thing{query}', headers=headers or {}, json=json_body
        ):
            return auth.resolve_caller()

    def _bearer(self, token):
        return {'Authorization': f'Bearer {token}'}

    # --- the happy path ---

    def test_email_from_custom_claim(self):
        token = make_token(claims={EMAIL_CLAIM: 'Erfan@Example.com'})
        self.assertEqual(self._resolve(self._bearer(token)), 'erfan@example.com')
        self.assertEqual(self.userinfo_calls, 0, 'a claim should avoid the /userinfo call')

    def test_email_from_standard_claim(self):
        token = make_token(claims={'email': 'plain@example.com'})
        self.assertEqual(self._resolve(self._bearer(token)), 'plain@example.com')

    def test_email_from_userinfo_when_no_claim(self):
        def fake_userinfo(token, claims):
            self.userinfo_calls += 1
            return 'viauserinfo@example.com'

        auth._userinfo_email = fake_userinfo
        token = make_token()
        self.assertEqual(self._resolve(self._bearer(token)), 'viauserinfo@example.com')
        self.assertEqual(self.userinfo_calls, 1)

    # --- what must be refused ---

    def test_no_header_is_not_a_caller(self):
        self.assertIsNone(self._resolve())

    def test_email_parameter_alone_proves_nothing(self):
        """The whole point: naming an address must not identify you."""
        self.assertIsNone(self._resolve(query='?email=victim@example.com'))
        self.assertIsNone(self._resolve(json_body={'token': 'victim@example.com'}))

    def test_token_signed_by_another_key_is_refused(self):
        token = make_token(key=OTHER_KEY, claims={EMAIL_CLAIM: 'attacker@example.com'})
        with self.assertRaises(auth.AuthError) as caught:
            self._resolve(self._bearer(token))
        self.assertEqual(caught.exception.status_code, 401)

    def test_tampered_payload_is_refused(self):
        token = make_token(claims={EMAIL_CLAIM: 'real@example.com'})
        header_b64, payload_b64, signature = token.split('.')
        forged = json.loads(base64.urlsafe_b64decode(payload_b64 + '==='))
        forged[EMAIL_CLAIM] = 'victim@example.com'
        swapped = base64.urlsafe_b64encode(
            json.dumps(forged).encode('utf-8')
        ).decode('ascii').rstrip('=')
        with self.assertRaises(auth.AuthError):
            self._resolve(self._bearer(f'{header_b64}.{swapped}.{signature}'))

    def test_expired_token_is_refused(self):
        token = make_token(expires_in=-10, claims={EMAIL_CLAIM: 'late@example.com'})
        with self.assertRaises(auth.AuthError) as caught:
            self._resolve(self._bearer(token))
        self.assertEqual(caught.exception.error['code'], 'token_expired')

    def test_token_for_another_audience_is_refused(self):
        token = make_token(audience='some-other-api', claims={EMAIL_CLAIM: 'x@example.com'})
        with self.assertRaises(auth.AuthError) as caught:
            self._resolve(self._bearer(token))
        self.assertEqual(caught.exception.error['code'], 'invalid_claims')

    def test_token_from_another_issuer_is_refused(self):
        token = make_token(issuer='https://evil.example.com/',
                           claims={EMAIL_CLAIM: 'x@example.com'})
        with self.assertRaises(auth.AuthError):
            self._resolve(self._bearer(token))

    def test_unsigned_token_is_refused(self):
        """alg=none must never be accepted."""
        now = int(time.time())
        payload = {'sub': 'a', 'aud': AUDIENCE, 'iss': f'https://{DOMAIN}/',
                   'exp': now + 600, EMAIL_CLAIM: 'none@example.com'}
        encode = lambda d: base64.urlsafe_b64encode(
            json.dumps(d).encode()).decode().rstrip('=')
        unsigned = f"{encode({'alg': 'none', 'kid': KID})}.{encode(payload)}."
        with self.assertRaises(auth.AuthError):
            self._resolve(self._bearer(unsigned))

    def test_malformed_header_is_refused(self):
        for header in ({'Authorization': 'Bearer'},
                       {'Authorization': 'Basic abc'},
                       {'Authorization': 'Bearer a b'}):
            with self.subTest(header=header), self.assertRaises(auth.AuthError):
                self._resolve(header)

    def test_garbage_token_is_refused(self):
        with self.assertRaises(auth.AuthError):
            self._resolve(self._bearer('not-a-jwt'))

    # --- the key set is not refetched per request ---

    def test_jwks_is_cached(self):
        token = make_token(claims={EMAIL_CLAIM: 'a@example.com'})
        for _ in range(5):
            self._resolve(self._bearer(token))
        self.assertEqual(self.jwks_fetches, 1, 'the key set should be fetched once, not per request')

    def test_unknown_kid_triggers_one_refresh(self):
        token = make_token(kid='rotated-key')
        with self.assertRaises(auth.AuthError):
            self._resolve(self._bearer(token))
        self.assertEqual(self.jwks_fetches, 2, 'an unknown kid should refresh the keys exactly once')

    def test_stale_keys_are_served_when_auth0_is_unreachable(self):
        token = make_token(claims={EMAIL_CLAIM: 'a@example.com'})
        self._resolve(self._bearer(token))  # warm the cache

        def exploding_fetch():
            self.jwks_fetches += 1
            raise OSError('auth0 unreachable')

        auth._fetch_jwks = exploding_fetch
        auth._jwks_fetched_at = 0  # force the TTL to look expired
        self.assertEqual(self._resolve(self._bearer(token)), 'a@example.com')

    def test_no_keys_and_no_cache_is_a_clean_401(self):
        def exploding_fetch():
            raise OSError('auth0 unreachable')

        auth._fetch_jwks = exploding_fetch
        token = make_token(claims={EMAIL_CLAIM: 'a@example.com'})
        with self.assertRaises(auth.AuthError) as caught:
            self._resolve(self._bearer(token))
        self.assertEqual(caught.exception.error['code'], 'jwks_unavailable')

    # --- the development bypass ---

    def test_dev_bypass_is_off_unless_asked_for(self):
        self.assertFalse(auth.DEV_AUTH_BYPASS)
        self.assertIsNone(self._resolve(query='?email=someone@example.com'))

    def test_dev_bypass_names_a_user_when_switched_on(self):
        os.environ['RECALLCARDS_DEV_AUTH'] = '1'
        try:
            importlib.reload(auth)
            self.assertTrue(auth.DEV_AUTH_BYPASS)
            with self.app.test_request_context('/api/thing?email=Dev@Example.com'):
                self.assertEqual(auth.resolve_caller(), 'dev@example.com')
        finally:
            os.environ.pop('RECALLCARDS_DEV_AUTH', None)
            importlib.reload(auth)

    def test_dev_bypass_refuses_to_work_in_production(self):
        os.environ['RECALLCARDS_DEV_AUTH'] = '1'
        os.environ['FLASK_ENV'] = 'production'
        try:
            importlib.reload(auth)
            with self.app.test_request_context('/api/thing?email=someone@example.com'):
                self.assertIsNone(auth.resolve_caller())
        finally:
            os.environ.pop('RECALLCARDS_DEV_AUTH', None)
            os.environ.pop('FLASK_ENV', None)
            importlib.reload(auth)

    # --- the decorators ---

    def test_requires_auth_rejects_and_passes_through(self):
        app = Flask(__name__)

        @app.route('/guarded')
        @auth.requires_auth
        def guarded():
            return {'you_are': auth.caller_email()}

        app.register_error_handler(
            auth.AuthError, lambda e: (json.dumps(e.error), e.status_code)
        )
        client = app.test_client()
        self.assertEqual(client.get('/guarded').status_code, 401)

        token = make_token(claims={EMAIL_CLAIM: 'erfan@example.com'})
        response = client.get('/guarded', headers=self._bearer(token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['you_are'], 'erfan@example.com')

    def test_optional_auth_allows_anonymous_but_rejects_a_bad_token(self):
        app = Flask(__name__)

        @app.route('/public')
        @auth.optional_auth
        def public():
            return {'you_are': auth.caller_email()}

        app.register_error_handler(
            auth.AuthError, lambda e: (json.dumps(e.error), e.status_code)
        )
        client = app.test_client()

        anonymous = client.get('/public')
        self.assertEqual(anonymous.status_code, 200)
        self.assertIsNone(anonymous.get_json()['you_are'])

        self.assertEqual(client.get('/public', headers=self._bearer('junk')).status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
