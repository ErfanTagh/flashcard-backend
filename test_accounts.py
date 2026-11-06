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
