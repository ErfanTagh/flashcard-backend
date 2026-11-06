"""The account lifecycle, end to end: sign up, get the email, follow the link,
sign in, refresh, sign out, reset a password.

Needs mongomock. Mail is captured instead of sent.
Run with: python -m unittest test_accounts
"""
import os
import re
import unittest
from datetime import datetime, timedelta

os.environ['JWT_SECRET'] = 'test-secret-' + 'x' * 40
os.environ['APP_URL'] = 'https://app.test'
os.environ.pop('RECALLCARDS_DEV_AUTH', None)
os.environ.setdefault('MONGO_HOST', 'localhost')

import mongomock  # noqa: E402

import accounts  # noqa: E402
import mailer  # noqa: E402
import main  # noqa: E402

EMAIL = 'new.person@example.com'
PASSWORD = 'correct horse battery'


class AccountsTestCase(unittest.TestCase):
    def setUp(self):
        db = mongomock.MongoClient().flashcards
        accounts.init(db, background=False)
        main.flashcards_collection = db.flashcards
        main.shares_collection = db.shares
        accounts.limiter.reset()
        self.sent = []
        self.fail_mail = False

        def fake_send(to, subject, text, html):
            if self.fail_mail:
                raise mailer.MailError('down')
            self.sent.append({'to': to, 'subject': subject, 'text': text})

        self._real_send = mailer.send
        mailer.send = fake_send
        self.client = main.app.test_client()

    def tearDown(self):
        mailer.send = self._real_send

    # helpers
    def post(self, path, body):
        return self.client.post(f'/api/auth/{path}', json=body)

    def link_token(self, path):
        message = self.sent[-1]
        match = re.search(re.escape(f'https://app.test{path}?token=') + r'(\S+)', message['text'])
        self.assertIsNotNone(match, message['text'])
        return match.group(1)

    def signup(self, email=EMAIL, password=PASSWORD, **extra):
        return self.post('signup', {'email': email, 'password': password, **extra})

    def activate(self, email=EMAIL):
        self.signup(email)
        return self.post('verify', {'token': self.link_token('/verify-email')})

    # signup + verification
    def test_signup_sends_a_link_and_the_link_activates_the_account(self):
        response = self.signup(name='New Person')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]['to'], EMAIL)

        user = accounts.users.find_one({'email': EMAIL})
        self.assertFalse(user['verified'])
        self.assertNotIn(PASSWORD, str(user))
        token = self.link_token('/verify-email')
        self.assertNotIn(token, str(user), 'the emailed token must be stored hashed')

        response = self.post('verify', {'token': token})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual({k: body['user'][k] for k in ('email', 'name', 'email_verified')},
                         {'email': EMAIL, 'name': 'New Person', 'email_verified': True})
        self.assertTrue(accounts.users.find_one({'email': EMAIL})['verified'])

        me = self.client.get('/api/auth/me', headers={'Authorization': f"Bearer {body['access_token']}"})
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.get_json()['user']['email'], EMAIL)

    def test_link_works_once(self):
        self.signup()
        token = self.link_token('/verify-email')
        self.assertEqual(self.post('verify', {'token': token}).status_code, 200)
        self.assertEqual(self.post('verify', {'token': token}).status_code, 400)

    def test_expired_link_is_refused(self):
        self.signup()
        token = self.link_token('/verify-email')
        accounts.users.update_one({'email': EMAIL}, {'$set': {'verify_expires': datetime.utcnow() - timedelta(seconds=1)}})
        self.assertEqual(self.post('verify', {'token': token}).status_code, 400)

    def test_made_up_link_is_refused(self):
        self.signup()
        self.assertEqual(self.post('verify', {'token': 'made-up'}).status_code, 400)
        self.assertEqual(self.post('verify', {}).status_code, 400)

    def test_cannot_sign_in_before_activating(self):
        self.signup()
        response = self.post('login', {'email': EMAIL, 'password': PASSWORD})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()['code'], 'email_not_verified')

    def test_resend_replaces_the_link(self):
        self.signup()
        first = self.link_token('/verify-email')
        self.assertEqual(self.post('resend-verification', {'email': EMAIL}).status_code, 200)
        second = self.link_token('/verify-email')
        self.assertNotEqual(first, second)
        self.assertEqual(self.post('verify', {'token': first}).status_code, 400)
        self.assertEqual(self.post('verify', {'token': second}).status_code, 200)

    def test_signing_up_again_does_not_replace_a_pending_password(self):
        self.signup(password=PASSWORD)
        self.signup(password='attacker password 1')
        self.post('verify', {'token': self.link_token('/verify-email')})
        self.assertEqual(self.post('login', {'email': EMAIL, 'password': 'attacker password 1'}).status_code, 401)
        self.assertEqual(self.post('login', {'email': EMAIL, 'password': PASSWORD}).status_code, 200)

    def test_signup_on_an_existing_account_does_not_reveal_it(self):
        self.activate()
        response = self.signup(password='something else 1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('already has an account', self.sent[-1]['text'])

    def test_signup_validates_input(self):
        self.assertEqual(self.signup(email='not-an-email').status_code, 400)
        self.assertEqual(self.signup(password='short').status_code, 400)
        self.assertEqual(self.signup(password=None).status_code, 400)
        self.assertEqual(self.sent, [])

    def test_address_is_case_insensitive(self):
        self.signup(email='New.Person@Example.com')
        self.post('verify', {'token': self.link_token('/verify-email')})
        self.assertEqual(self.post('login', {'email': EMAIL.upper(), 'password': PASSWORD}).status_code, 200)

    def test_failed_mail_is_reported(self):
        self.fail_mail = True
        response = self.signup()
        self.assertEqual(response.status_code, 502)
        self.fail_mail = False
        self.assertEqual(self.post('resend-verification', {'email': EMAIL}).status_code, 200)
        self.assertEqual(len(self.sent), 1)

    # sign in
    def test_wrong_password_and_unknown_account_look_the_same(self):
        self.activate()
        wrong = self.post('login', {'email': EMAIL, 'password': 'wrong password'})
        unknown = self.post('login', {'email': 'nobody@example.com', 'password': PASSWORD})
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(wrong.get_json(), unknown.get_json())

    def test_login_is_rate_limited(self):
        self.activate()
        codes = [self.post('login', {'email': EMAIL, 'password': 'wrong'}).status_code for _ in range(12)]
        self.assertIn(429, codes)
        self.assertEqual(self.post('login', {'email': EMAIL, 'password': PASSWORD}).status_code, 429)

    def test_access_token_reaches_the_card_api(self):
        main.flashcards_collection.insert_one({'user_email': EMAIL, 'collections': {'Old deck': {}}})
        token = self.activate().get_json()['access_token']
        response = self.client.get('/api/collections/ignored', headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('Old deck', response.get_data(as_text=True),
                      'an Auth0-era account must find its decks after signing up with the same address')

    # sessions
    def test_refresh_rotates_and_is_single_use(self):
        first = self.activate().get_json()
        second = self.post('refresh', {'refresh_token': first['refresh_token']})
        self.assertEqual(second.status_code, 200)
        self.assertNotEqual(second.get_json()['refresh_token'], first['refresh_token'])
        self.assertEqual(self.post('refresh', {'refresh_token': first['refresh_token']}).status_code, 401)
        self.assertEqual(self.post('refresh', {'refresh_token': 'junk'}).status_code, 401)

    def test_logout_revokes_the_refresh_token(self):
        session = self.activate().get_json()
        self.assertEqual(self.post('logout', {'refresh_token': session['refresh_token']}).status_code, 200)
        self.assertEqual(self.post('refresh', {'refresh_token': session['refresh_token']}).status_code, 401)

    def test_refresh_token_is_stored_hashed(self):
        session = self.activate().get_json()
        self.assertNotIn(session['refresh_token'], str(list(accounts.sessions.find())))

    def test_me_requires_a_token(self):
        self.assertEqual(self.client.get('/api/auth/me').status_code, 401)

    # password reset
    def test_reset_password_changes_it_and_ends_other_sessions(self):
        old_session = self.activate().get_json()
        self.assertEqual(self.post('forgot-password', {'email': EMAIL}).status_code, 200)
        token = self.link_token('/reset-password')

        self.assertEqual(self.post('reset-password', {'token': token, 'password': 'short'}).status_code, 400)
        response = self.post('reset-password', {'token': token, 'password': 'a brand new password'})
        self.assertEqual(response.status_code, 200)

        self.assertEqual(self.post('refresh', {'refresh_token': old_session['refresh_token']}).status_code, 401)
        self.assertEqual(self.post('login', {'email': EMAIL, 'password': PASSWORD}).status_code, 401)
        self.assertEqual(self.post('login', {'email': EMAIL, 'password': 'a brand new password'}).status_code, 200)
        self.assertEqual(self.post('reset-password', {'token': token, 'password': 'another new one'}).status_code, 400)

    def test_reset_activates_a_pending_account(self):
        self.signup()
        self.post('forgot-password', {'email': EMAIL})
        token = self.link_token('/reset-password')
        self.assertEqual(self.post('reset-password', {'token': token, 'password': 'remembered now'}).status_code, 200)
        self.assertEqual(self.post('login', {'email': EMAIL, 'password': 'remembered now'}).status_code, 200)

    def test_forgot_password_does_not_reveal_accounts(self):
        response = self.post('forgot-password', {'email': 'nobody@example.com'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sent, [])


    # where to go after activating
    def test_activation_link_carries_a_safe_return_path(self):
        self.signup(next='/import/abc123')
        self.assertIn('/verify-email?token=', self.sent[-1]['text'])
        self.assertIn('&next=/import/abc123', self.sent[-1]['text'])

    def test_unsafe_return_paths_are_dropped(self):
        for bad in ('https://evil.example/x', '//evil.example', '/\\evil.example', 'import/x', '/x\n/y'):
            self.sent.clear()
            accounts.limiter.reset()
            accounts.users.delete_many({})
            self.signup(next=bad)
            self.assertNotIn('next=', self.sent[-1]['text'], bad)


class GoogleSignInTestCase(unittest.TestCase):
    CLIENT_ID = 'test-client.apps.googleusercontent.com'

    def setUp(self):
        os.environ['GOOGLE_CLIENT_ID'] = self.CLIENT_ID
        os.environ['GOOGLE_CLIENT_SECRET'] = 'test-secret'
        db = mongomock.MongoClient().flashcards
        accounts.init(db, background=False)
        main.flashcards_collection = db.flashcards
        main.shares_collection = db.shares
        accounts.limiter.reset()
        self.claims = {'iss': 'https://accounts.google.com', 'aud': self.CLIENT_ID,
                       'exp': 4102444800, 'sub': 'google-123', 'email': 'G.User@Example.com',
                       'email_verified': True, 'given_name': 'Gina'}
        self.exchanged = []

        def fake_exchange(code, verifier):
            self.exchanged.append((code, verifier))
            import base64, json as _json
            body = base64.urlsafe_b64encode(_json.dumps(self.claims).encode()).decode().rstrip('=')
            return {'id_token': f'header.{body}.signature'}

        self._real_exchange = accounts._exchange_google_code
        accounts._exchange_google_code = fake_exchange
        self.client = main.app.test_client()

    def tearDown(self):
        accounts._exchange_google_code = self._real_exchange
        os.environ.pop('GOOGLE_CLIENT_ID', None)
        os.environ.pop('GOOGLE_CLIENT_SECRET', None)

    def start(self, next_path='/import/abc'):
        response = self.client.get('/api/auth/google/start', query_string={'next': next_path})
        self.assertEqual(response.status_code, 302)
        location = response.headers['Location']
        self.assertTrue(location.startswith('https://accounts.google.com/'))
        from urllib.parse import urlparse, parse_qs
        params = {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}
        self.assertEqual(params['code_challenge_method'], 'S256')
        return params['state']

    def finish(self, state, cookie_state=None):
        self.client.set_cookie('localhost', accounts.OAUTH_COOKIE, cookie_state or state, path='/api/auth/google')
        return self.client.get('/api/auth/google/callback', query_string={'code': 'g-code', 'state': state})

    def site_params(self, response):
        from urllib.parse import urlparse, parse_qs
        url = urlparse(response.headers['Location'])
        return url.path, {k: v[0] for k, v in parse_qs(url.query).items()}

    def test_providers_reports_google(self):
        self.assertTrue(self.client.get('/api/auth/providers').get_json()['google'])
        os.environ.pop('GOOGLE_CLIENT_ID')
        self.assertFalse(self.client.get('/api/auth/providers').get_json()['google'])

    def test_new_user_is_created_active_and_signed_in(self):
        path, params = self.site_params(self.finish(self.start()))
        self.assertEqual(path, '/auth/callback')
        self.assertEqual(params['next'], '/import/abc')
        session = self.client.post('/api/auth/google/exchange', json={'code': params['code']})
        self.assertEqual(session.status_code, 200)
        self.assertEqual(session.get_json()['user']['email'], 'g.user@example.com')
        user = accounts.users.find_one({'email': 'g.user@example.com'})
        self.assertTrue(user['verified'])
        self.assertEqual(user['name'], 'Gina')
        self.assertIsNone(user['password_hash'])
        # The code works once.
        self.assertEqual(self.client.post('/api/auth/google/exchange', json={'code': params['code']}).status_code, 400)
        # A Google-only account cannot be signed into with a password.
        self.assertEqual(self.client.post('/api/auth/login', json={'email': 'g.user@example.com', 'password': 'anything at all'}).status_code, 401)

    def test_existing_password_account_is_signed_in_and_activated(self):
        accounts.users.insert_one({'email': 'g.user@example.com', 'password_hash': 'x', 'verified': False,
                                   'created_at': accounts._now(), 'verify_token_hash': 'h'})
        _, params = self.site_params(self.finish(self.start()))
        self.assertEqual(self.client.post('/api/auth/google/exchange', json={'code': params['code']}).status_code, 200)
        user = accounts.users.find_one({'email': 'g.user@example.com'})
        self.assertTrue(user['verified'])
        self.assertEqual(user['google_sub'], 'google-123')
        self.assertNotIn('verify_token_hash', user)

    def test_state_from_another_browser_is_refused(self):
        state = self.start()
        path, params = self.site_params(self.finish(state, cookie_state='someone-elses-state'))
        self.assertEqual((path, params.get('error')), ('/login', 'google'))
        self.assertEqual(self.exchanged, [])

    def test_state_is_single_use(self):
        state = self.start()
        self.finish(state)
        path, params = self.site_params(self.finish(state))
        self.assertEqual((path, params.get('error')), ('/login', 'google'))

    def test_unverified_google_email_is_refused(self):
        self.claims['email_verified'] = False
        path, params = self.site_params(self.finish(self.start()))
        self.assertEqual((path, params.get('error')), ('/login', 'google'))
        self.assertIsNone(accounts.users.find_one({'email': 'g.user@example.com'}))

    def test_token_for_another_app_is_refused(self):
        self.claims['aud'] = 'some-other-app'
        path, params = self.site_params(self.finish(self.start()))
        self.assertEqual((path, params.get('error')), ('/login', 'google'))

    def test_address_linked_to_another_google_account_is_refused(self):
        accounts.users.insert_one({'email': 'g.user@example.com', 'password_hash': None, 'verified': True,
                                   'google_sub': 'google-999', 'created_at': accounts._now()})
        path, params = self.site_params(self.finish(self.start()))
        self.assertEqual((path, params.get('error')), ('/login', 'google'))

    def test_cancel_on_google_goes_back_to_login(self):
        response = self.client.get('/api/auth/google/callback', query_string={'error': 'access_denied'})
        self.assertEqual(self.site_params(response), ('/login', {'error': 'google_cancelled'}))

    def test_unsafe_next_is_not_carried(self):
        _, params = self.site_params(self.finish(self.start(next_path='https://evil.example')))
        self.assertNotIn('next', params)

    def test_start_without_configuration_says_so(self):
        os.environ.pop('GOOGLE_CLIENT_ID')
        response = self.client.get('/api/auth/google/start')
        self.assertEqual(self.site_params(response), ('/login', {'error': 'google_unavailable'}))

class MailerTestCase(unittest.TestCase):
    def test_no_transport_refuses_in_production(self):
        saved = {k: os.environ.pop(k, None) for k in ('MAILGUN_API_KEY', 'MAILGUN_DOMAIN', 'SMTP_HOST')}
        os.environ['FLASK_ENV'] = 'production'
        try:
            self.assertEqual(mailer.transport(), 'log')
            with self.assertRaises(mailer.MailError):
                mailer.send('a@example.com', 's', 't', '<p>t</p>')
        finally:
            os.environ.pop('FLASK_ENV', None)
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_mailgun_is_chosen_when_configured(self):
        os.environ['MAILGUN_API_KEY'] = 'key'
        os.environ['MAILGUN_DOMAIN'] = 'mg.example.com'
        try:
            self.assertEqual(mailer.transport(), 'mailgun')
        finally:
            os.environ.pop('MAILGUN_API_KEY')
            os.environ.pop('MAILGUN_DOMAIN')


if __name__ == '__main__':
    unittest.main(verbosity=2)
