"""Every route is checked for who may call it, by walking the app's own URL map.

A route added later is covered without touching this file: it either appears in
PUBLIC below with a reason, or it must answer 401 to an anonymous caller.

No database is needed. The collections are set to None, so a request that gets
past the auth decorator fails with "Database not connected" (500). That is the
signal that authentication passed: 401 means it was refused, anything else means
it was let through.

Run with: python test_api_auth.py
"""
import os
import unittest

os.environ['JWT_SECRET'] = 'test-secret-' + 'x' * 40
os.environ.pop('RECALLCARDS_DEV_AUTH', None)
# Keep PyMongo from trying to reach a server during import.
os.environ.setdefault('MONGO_HOST', 'localhost')

import auth  # noqa: E402
import main  # noqa: E402

VICTIM = 'victim@example.com'
CALLER = 'caller@example.com'


def token_for(email):
    return auth.issue_access_token(email)[0]


# Registered at import, before any test module sends the shared app its first
# request: Flask refuses new routes after that.
SEEN = {}


def _record():
    SEEN['email'] = auth.caller_email()
    return {'status': 200}


main.app.add_url_rule('/api/_probe', 'probe_caller', auth.requires_auth(_record), methods=['POST'])


# Readable without signing in, each for a stated reason.
PUBLIC = {
    'get_share': 'a share link shows what it is (name, owner, count, cover) before anyone joins; the cards are for members',
    'get_image': "a share link's cover picture loads for a signed-out visitor; nothing else does",
    'list_public_decks': 'Explore is open to visitors: publishing a deck makes it readable by anyone',
    'handle_auth_error': 'an error handler, not a route',
    # Signing in is how a caller gets a token, so it cannot require one.
    'accounts.signup': 'creating an account',
    'accounts.verify': 'following the emailed activation link',
    'accounts.resend_verification': 'asking for a new activation link',
    'accounts.login': 'signing in',
    'accounts.refresh': 'swapping a refresh token for a new access token',
    'accounts.logout': 'revoking a refresh token',
    'accounts.forgot_password': 'asking for a password reset link',
    'accounts.reset_password': 'following the emailed reset link',
}

# Of those, the ones that never read a bearer token at all.
SIGN_IN = {name for name in PUBLIC if name.startswith('accounts.')}

# Placeholder values for path parameters.
PATH_VALUES = {
    'token': VICTIM, 'word': 'apple', 'collection_name': 'Default',
    'old_collection_name': 'Default', 'image_id': '0' * 24,
    'share_id': 'sharetoken', 'path': 'x', 'filename': 'x',
}


def iter_routes():
    """(endpoint, method, concrete path) for every API route the app serves."""
    for rule in main.app.url_map.iter_rules():
        if not str(rule).startswith('/api/'):
            continue
        path = str(rule)
        for name in rule.arguments:
            path = path.replace(f'<{name}>', str(PATH_VALUES.get(name, 'x')))
        for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
            yield rule.endpoint, method, path


class ApiAuthTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Past the decorator, every route should fail on the database rather
        # than reach for a real one.
        main.flashcards_collection = None
        main.shares_collection = None
        main.images = None
        import accounts
        accounts.users = None
        accounts.sessions = None

        cls.seen = SEEN
        cls.client = main.app.test_client()

    def _call(self, method, path, headers=None, body=None):
        return self.client.open(
            path, method=method, headers=headers or {},
            json=body if method in ('POST', 'PUT', 'PATCH', 'DELETE') else None,
        )

    def test_every_guarded_route_refuses_an_anonymous_caller(self):
        checked = 0
        for endpoint, method, path in iter_routes():
            if endpoint in PUBLIC:
                continue
            with self.subTest(endpoint=endpoint, method=method, path=path):
                response = self._call(method, path)
                self.assertEqual(
                    response.status_code, 401,
                    f'{method} {path} ({endpoint}) answered {response.status_code} '
                    f'to a caller with no credentials; it must be 401',
                )
            checked += 1
        self.assertGreater(checked, 25, 'the route walk found suspiciously few routes')

    def test_naming_a_victim_is_not_authentication(self):
        """The hole this change closes: an address in the request proves nothing."""
        for endpoint, method, path in iter_routes():
            if endpoint in PUBLIC:
                continue
            with self.subTest(endpoint=endpoint, method=method):
                by_query = self._call(method, f'{path}?email={VICTIM}&collection=Default')
                self.assertEqual(by_query.status_code, 401, f'{method} {path}: email= was accepted')

                by_body = self._call(method, path, body={
                    'token': VICTIM, 'email': VICTIM, 'word': 'apple', 'ans': 'x',
                    'oldword': 'apple', 'answer': 'x', 'collection_name': 'Default',
                })
                self.assertEqual(by_body.status_code, 401, f'{method} {path}: token in the body was accepted')

    def test_a_bogus_bearer_token_is_not_authentication(self):
        for endpoint, method, path in iter_routes():
            if endpoint in PUBLIC:
                continue
            with self.subTest(endpoint=endpoint, method=method):
                response = self._call(method, path, headers={'Authorization': 'Bearer made-up'})
                self.assertEqual(response.status_code, 401)

    def test_a_real_token_gets_past_authentication(self):
        """A verified caller must reach the handler, which then has no database."""
        headers = {'Authorization': f'Bearer {token_for(CALLER)}'}
        reached = 0
        for endpoint, method, path in iter_routes():
            if endpoint in PUBLIC:
                continue
            with self.subTest(endpoint=endpoint, method=method):
                response = self._call(method, path, headers=headers, body={
                    'word': 'apple', 'ans': 'x', 'oldword': 'apple', 'answer': 'x',
                    'collection_name': 'Default',
                })
                self.assertNotEqual(
                    response.status_code, 401,
                    f'{method} {path} ({endpoint}) refused a valid token',
                )
            reached += 1
        self.assertGreater(reached, 25)

    def test_public_routes_stay_readable_signed_out(self):
        for endpoint, method, path in iter_routes():
            if endpoint not in PUBLIC or endpoint == 'handle_auth_error':
                continue
            with self.subTest(endpoint=endpoint, method=method):
                response = self._call(method, path)
                self.assertNotEqual(
                    response.status_code, 401,
                    f'{method} {path} ({endpoint}) should be readable signed out: '
                    f'{PUBLIC[endpoint]}',
                )

    def test_public_routes_still_reject_a_broken_token(self):
        """An expired session must not be mistaken for a signed-out visitor."""
        for endpoint, method, path in iter_routes():
            if endpoint not in PUBLIC or endpoint == 'handle_auth_error' or endpoint in SIGN_IN:
                continue
            with self.subTest(endpoint=endpoint, method=method):
                response = self._call(method, path, headers={'Authorization': 'Bearer junk'})
                self.assertEqual(response.status_code, 401)

    def test_the_caller_is_the_token_not_the_request(self):
        """Even with a victim's address all over the request, the caller is the token."""
        response = self.client.post(
            '/api/_probe?email=' + VICTIM,
            headers={'Authorization': f'Bearer {token_for(CALLER)}'},
            json={'token': VICTIM, 'email': VICTIM},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.seen['email'], CALLER)


if __name__ == '__main__':
    unittest.main(verbosity=2)
