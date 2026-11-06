"""Tests for auth.py: what counts as proof of identity, and what does not.

Run with: python -m unittest test_auth

Real tokens are signed with the real key, so the signature check is exercised
rather than mocked.
"""
import os
import time
import unittest

os.environ['JWT_SECRET'] = 'test-secret-' + 'x' * 40
os.environ.pop('RECALLCARDS_DEV_AUTH', None)
os.environ.pop('FLASK_ENV', None)

import auth  # noqa: E402  (imported after the environment is set)
from flask import Flask  # noqa: E402
from jose import jwt  # noqa: E402

EMAIL = 'someone@example.com'


def forge(claims=None, secret=None, algorithm='HS256'):
    now = int(time.time())
    base = {'sub': EMAIL, 'email': EMAIL, 'typ': 'access', 'iss': auth.ISSUER,
            'aud': auth.AUDIENCE, 'iat': now, 'exp': now + 600}
    base.update(claims or {})
    base = {k: v for k, v in base.items() if v is not None}
    return jwt.encode(base, secret or auth.JWT_SECRET, algorithm=algorithm)


class VerifyTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def caller(self, headers=None, **kwargs):
        with self.app.test_request_context('/', headers=headers or {}, **kwargs):
            return auth.resolve_caller()

    def assertRefused(self, token, code=None):
        with self.assertRaises(auth.AuthError) as ctx:
            self.caller({'Authorization': f'Bearer {token}'})
        self.assertEqual(ctx.exception.status_code, 401)
        if code:
            self.assertEqual(ctx.exception.error['code'], code)

    def test_issued_token_identifies_its_owner(self):
        token, ttl = auth.issue_access_token(EMAIL)
        self.assertEqual(self.caller({'Authorization': f'Bearer {token}'}), EMAIL)
        self.assertEqual(ttl, auth.ACCESS_TOKEN_TTL)

    def test_address_is_normalised(self):
        token = forge({'sub': ' Someone@Example.COM '})
        self.assertEqual(self.caller({'Authorization': f'Bearer {token}'}), EMAIL)

    def test_no_header_is_not_a_caller(self):
        self.assertIsNone(self.caller())

    def test_email_parameter_alone_proves_nothing(self):
        self.assertIsNone(self.caller(query_string={'email': EMAIL}))
        self.assertIsNone(self.caller(json={'token': EMAIL, 'email': EMAIL}))

    def test_token_signed_with_another_key_is_refused(self):
        self.assertRefused(forge(secret='another-secret-' + 'y' * 40), 'invalid_token')

    def test_tampered_payload_is_refused(self):
        token = forge()
        header, payload, signature = token.split('.')
        other = forge({'sub': 'victim@example.com'}).split('.')[1]
        self.assertRefused(f'{header}.{other}.{signature[::-1]}')
        self.assertRefused(f'{header}.{other}.{signature}')

    def test_expired_token_is_refused(self):
        self.assertRefused(forge({'exp': int(time.time()) - 10}), 'token_expired')

    def test_token_for_another_audience_is_refused(self):
        self.assertRefused(forge({'aud': 'something-else'}), 'invalid_claims')

    def test_token_from_another_issuer_is_refused(self):
        self.assertRefused(forge({'iss': 'https://evil.example/'}), 'invalid_claims')

    def test_token_of_another_type_is_refused(self):
        self.assertRefused(forge({'typ': 'refresh'}), 'invalid_token')
        self.assertRefused(forge({'typ': None}), 'invalid_token')

    def test_unsigned_token_is_refused(self):
        import base64
        import json

        def b64(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b'=').decode()

        now = int(time.time())
        token = b64({'alg': 'none', 'typ': 'JWT'}) + '.' + b64({
            'sub': EMAIL, 'typ': 'access', 'iss': auth.ISSUER, 'aud': auth.AUDIENCE,
            'iat': now, 'exp': now + 600}) + '.'
        self.assertRefused(token)

    def test_other_algorithm_is_refused(self):
        self.assertRefused(forge(algorithm='HS512'), 'invalid_header')

    def test_token_without_subject_is_refused(self):
        self.assertRefused(forge({'sub': None}))

    def test_malformed_header_is_refused(self):
        with self.assertRaises(auth.AuthError):
            self.caller({'Authorization': 'Token abc'})
        with self.assertRaises(auth.AuthError):
            self.caller({'Authorization': 'Bearer'})

    def test_garbage_token_is_refused(self):
        self.assertRefused('not.a.token', 'invalid_header')

    def test_dev_bypass_is_off_unless_asked_for(self):
        self.assertFalse(auth.DEV_AUTH_BYPASS)
        self.assertIsNone(self.caller({'X-Dev-User': EMAIL}))

    def test_dev_bypass_names_a_user_when_switched_on(self):
        auth.DEV_AUTH_BYPASS = True
        try:
            self.assertEqual(self.caller({'X-Dev-User': EMAIL}), EMAIL)
        finally:
            auth.DEV_AUTH_BYPASS = False

    def test_dev_bypass_refuses_to_work_in_production(self):
        auth.DEV_AUTH_BYPASS = True
        os.environ['FLASK_ENV'] = 'production'
        try:
            self.assertIsNone(self.caller({'X-Dev-User': EMAIL}))
        finally:
            auth.DEV_AUTH_BYPASS = False
            os.environ.pop('FLASK_ENV', None)

    def test_production_refuses_to_start_without_a_secret(self):
        saved = os.environ.pop('JWT_SECRET')
        os.environ['FLASK_ENV'] = 'production'
        try:
            with self.assertRaises(RuntimeError):
                auth._load_secret()
            os.environ['JWT_SECRET'] = 'short'
            with self.assertRaises(RuntimeError):
                auth._load_secret()
        finally:
            os.environ['JWT_SECRET'] = saved
            os.environ.pop('FLASK_ENV', None)


class DecoratorTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

        @self.app.errorhandler(auth.AuthError)
        def handle(ex):
            return ex.error, ex.status_code

        @self.app.route('/private')
        @auth.requires_auth
        def private():
            return {'email': auth.caller_email()}

        @self.app.route('/public')
        @auth.optional_auth
        def public():
            return {'email': auth.caller_email()}

        self.client = self.app.test_client()
        self.token, _ = auth.issue_access_token(EMAIL)

    def test_requires_auth_rejects_and_passes_through(self):
        self.assertEqual(self.client.get('/private').status_code, 401)
        response = self.client.get('/private', headers={'Authorization': f'Bearer {self.token}'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['email'], EMAIL)

    def test_optional_auth_allows_anonymous_but_rejects_a_bad_token(self):
        self.assertEqual(self.client.get('/public').get_json()['email'], None)
        self.assertEqual(self.client.get('/public', headers={'Authorization': 'Bearer junk'}).status_code, 401)
        response = self.client.get('/public', headers={'Authorization': f'Bearer {self.token}'})
        self.assertEqual(response.get_json()['email'], EMAIL)


if __name__ == '__main__':
    unittest.main(verbosity=2)
