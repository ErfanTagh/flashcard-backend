"""Can one account reach another account's cards? With real data, end to end.

test_api_auth.py proves that a request without a verified token is refused.
This proves the thing that refusal is for: with two real accounts and real
cards in a database, what one signed-in user can see and change is their own
data only -- whatever address they put in the request.

Needs mongomock: pip install mongomock
Run with: python test_isolation.py
"""
import os
import unittest

import mongomock
os.environ['JWT_SECRET'] = 'test-secret-' + 'x' * 40
os.environ.pop('RECALLCARDS_DEV_AUTH', None)
# Keep PyMongo from trying to reach a server during import.
os.environ.setdefault('MONGO_HOST', 'localhost')

import auth  # noqa: E402
import main  # noqa: E402

ALICE = 'alice@example.com'
BOB = 'bob@example.com'


def token_for(email):
    return auth.issue_access_token(email)[0]


class IsolationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = main.app.test_client()

    def setUp(self):
        db = mongomock.MongoClient().flashcards
        main.flashcards_collection = db.flashcards
        main.shares_collection = db.shares

        # Two accounts, each with a card of their own.
        for email, term, definition in (
            (ALICE, 'apfel', 'apple'),
            (BOB, 'geheim', 'bob private answer'),
        ):
            main.flashcards_collection.insert_one({
                'user_email': email,
                'collections': {'Default': {term: {
                    'definition': definition, 'image': None, 'reviews': [],
                    'created_by': email, 'created_at': None,
                    'edited_by': None, 'edited_at': None,
                }}},
                'default_collection': 'Default',
            })

    def as_user(self, email):
        return {'Authorization': f'Bearer {token_for(email)}'}

    def cards_of(self, email):
        """Whatever is actually stored for this account."""
        doc = main.flashcards_collection.find_one({'user_email': email})
        return doc['collections']['Default']

    # --- reading ---

    def test_alice_sees_only_her_own_cards(self):
        body = self.client.get('/api/cards?collection=Default',
                               headers=self.as_user(ALICE)).get_json()
        text = str(body)
        self.assertIn('apfel', text)
        self.assertNotIn('bob private answer', text)

    def test_naming_bob_does_not_return_bobs_cards(self):
        """Alice asks for Bob's data by address, and gets her own."""
        body = self.client.get(f'/api/cards?collection=Default&email={BOB}',
                               headers=self.as_user(ALICE)).get_json()
        text = str(body)
        self.assertNotIn('bob private answer', text)
        self.assertIn('apfel', text)

    def test_the_path_form_also_ignores_the_address(self):
        """/api/collections/<address> no longer means "this person's decks"."""
        response = self.client.get(f'/api/collections/{BOB}', headers=self.as_user(ALICE))
        self.assertEqual(response.status_code, 200)
        # Alice has a Default deck of her own; the response is hers either way,
        # so the test that matters is that Bob's card never appears.
        self.assertNotIn('bob private answer', str(response.get_json()))

    # --- writing ---

    def test_alice_cannot_write_into_bobs_deck(self):
        self.client.post('/api/sendwords',
                         headers=self.as_user(ALICE),
                         json={'token': BOB, 'email': BOB, 'word': 'injected',
                               'ans': 'by alice', 'collection': 'Default'})
        self.assertNotIn('injected', self.cards_of(BOB))
        self.assertIn('injected', self.cards_of(ALICE),
                      'the card should have landed in her own deck')

    def test_alice_cannot_delete_bobs_card(self):
        self.client.delete('/api/delword/geheim',
                           headers=self.as_user(ALICE),
                           json={'token': BOB, 'collection': 'Default'})
        self.assertIn('geheim', self.cards_of(BOB), "Bob's card was deleted by Alice")

    def test_alice_cannot_edit_bobs_card(self):
        self.client.post('/api/editword',
                         headers=self.as_user(ALICE),
                         json={'token': BOB, 'oldword': 'geheim', 'word': 'geheim',
                               'ans': 'overwritten', 'collection': 'Default'})
        self.assertEqual(self.cards_of(BOB)['geheim']['definition'], 'bob private answer')

    def test_alice_cannot_delete_bobs_deck(self):
        self.client.delete('/api/collections/Default',
                           headers=self.as_user(ALICE),
                           json={'token': BOB})
        bob = main.flashcards_collection.find_one({'user_email': BOB})
        self.assertIn('Default', bob['collections'], "Bob's deck was deleted by Alice")

    def test_alice_cannot_publish_bobs_deck(self):
        self.client.post('/api/collections/Default/publish',
                         headers=self.as_user(ALICE),
                         json={'token': BOB, 'public': True})
        published = list(main.shares_collection.find({'owner_email': BOB}))
        self.assertEqual(published, [], "Bob's deck was published by Alice")

    def test_alice_cannot_share_bobs_deck(self):
        self.client.post('/api/collections/Default/share',
                         headers=self.as_user(ALICE),
                         json={'token': BOB})
        shares = list(main.shares_collection.find({'owner_email': BOB}))
        self.assertEqual(shares, [], "a share link for Bob's deck was created by Alice")

    def test_alice_cannot_revoke_bobs_share(self):
        main.shares_collection.insert_one({
            'share_id': 'bobshare', 'owner_email': BOB,
            'collection_name': 'Default', 'can_edit': False,
        })
        self.client.delete('/api/collections/Default/share',
                           headers=self.as_user(ALICE),
                           json={'token': BOB})
        self.assertIsNotNone(
            main.shares_collection.find_one({'share_id': 'bobshare'}),
            "Bob's share was revoked by Alice")

    def test_review_is_recorded_against_the_caller(self):
        self.client.post('/api/review',
                         headers=self.as_user(ALICE),
                         json={'token': BOB, 'word': 'geheim', 'outcome': 'known',
                               'collection': 'Default'})
        self.assertEqual(self.cards_of(BOB)['geheim']['reviews'], [],
                         "a review was written onto Bob's card")

    # --- and the whole thing still works for its owner ---

    def test_bob_can_still_do_all_of_this_to_his_own_deck(self):
        headers = self.as_user(BOB)

        added = self.client.post('/api/sendwords', headers=headers,
                                 json={'word': 'neu', 'ans': 'new',
                                       'collection': 'Default'})
        self.assertIn(added.status_code, (200, 201), added.get_data(as_text=True))
        self.assertIn('neu', self.cards_of(BOB))

        self.client.post('/api/editword', headers=headers,
                         json={'oldword': 'neu', 'word': 'neu', 'ans': 'changed',
                               'collection': 'Default'})
        self.assertEqual(self.cards_of(BOB)['neu']['definition'], 'changed')

        self.client.delete('/api/delword/neu', headers=headers,
                           json={'collection': 'Default'})
        self.assertNotIn('neu', self.cards_of(BOB))

        self.assertIn('geheim', str(
            self.client.get('/api/cards?collection=Default', headers=headers).get_json()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
