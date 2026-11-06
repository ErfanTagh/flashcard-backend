"""What a share link shows to someone without an account.

A signed-out visitor sees a summary -- name, owner, card count, cover -- and
none of the cards, unless the deck is published to Explore: then they can read
(only read) its cards and pictures.

Needs mongomock. Run with: python -m unittest test_share_preview
"""
import os
import unittest

os.environ['JWT_SECRET'] = 'test-secret-' + 'x' * 40
os.environ.pop('RECALLCARDS_DEV_AUTH', None)
os.environ.setdefault('MONGO_HOST', 'localhost')

import gridfs  # noqa: E402
import mongomock  # noqa: E402
import mongomock.gridfs  # noqa: E402

import auth  # noqa: E402
import main  # noqa: E402

mongomock.gridfs.enable_gridfs_integration()

OWNER = 'owner@example.com'
VIEWER = 'viewer@example.com'
SHARE_ID = 'abcDEF123456'


class SharePreviewTestCase(unittest.TestCase):
    def setUp(self):
        db = mongomock.MongoClient().flashcards
        main.flashcards_collection = db.flashcards
        main.shares_collection = db.shares
        main.images = gridfs.GridFS(db)

        self.cover_id = str(main.images.put(b'cover-bytes', content_type='image/png',
                                            metadata={'user_email': OWNER}))
        self.card_image_id = str(main.images.put(b'card-bytes', content_type='image/png',
                                                 metadata={'user_email': OWNER}))
        main.flashcards_collection.insert_one({
            'user_email': OWNER,
            'display_name': 'Olga',
            'collections': {'German': {
                'die Stelle': {**main._default_card('position'), 'image': self.card_image_id},
                'leiten': main._default_card('to lead'),
            }},
            'collection_meta': {'German': {'cover_image': self.cover_id}},
        })
        main.shares_collection.insert_one({
            'share_id': SHARE_ID, 'owner_email': OWNER, 'collection_name': 'German',
            'allow_edit': False, 'public': False,
        })
        self.client = main.app.test_client()

    def auth(self, email):
        return {'Authorization': f'Bearer {auth.issue_access_token(email)[0]}'}

    def test_signed_out_gets_the_summary_without_cards(self):
        response = self.client.get(f'/api/shares/{SHARE_ID}')
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body['collection'], 'German')
        self.assertEqual(body['owner_name'], 'Olga')
        self.assertEqual(body['card_count'], 2)
        self.assertEqual(body['cover'], self.cover_id)
        self.assertEqual(body['cards'], [])
        self.assertNotIn('to lead', response.get_data(as_text=True))

    def test_signed_in_gets_the_cards(self):
        body = self.client.get(f'/api/shares/{SHARE_ID}', headers=self.auth(VIEWER)).get_json()
        self.assertEqual({c['term'] for c in body['cards']}, {'die Stelle', 'leiten'})

    def test_a_broken_token_is_still_refused(self):
        response = self.client.get(f'/api/shares/{SHARE_ID}', headers={'Authorization': 'Bearer junk'})
        self.assertEqual(response.status_code, 401)

    def test_unknown_link_is_404(self):
        self.assertEqual(self.client.get('/api/shares/nope').status_code, 404)

    def test_signed_out_may_load_only_the_cover(self):
        cover = self.client.get(f'/api/images/{self.cover_id}?share={SHARE_ID}')
        self.assertEqual(cover.status_code, 200)
        self.assertEqual(cover.data, b'cover-bytes')
        card = self.client.get(f'/api/images/{self.card_image_id}?share={SHARE_ID}')
        self.assertEqual(card.status_code, 404)
        self.assertEqual(self.client.get(f'/api/images/{self.cover_id}').status_code, 404)
        self.assertEqual(self.client.get(f'/api/images/{self.cover_id}?share=nope').status_code, 404)

    def test_signed_in_follower_view_may_load_card_pictures(self):
        card = self.client.get(f'/api/images/{self.card_image_id}?share={SHARE_ID}', headers=self.auth(VIEWER))
        self.assertEqual(card.status_code, 200)

    # Published to Explore: readable by anyone, read-only.
    def publish(self):
        main.shares_collection.update_one({'share_id': SHARE_ID}, {'$set': {'public': True}})

    def test_published_deck_shows_its_cards_signed_out(self):
        self.publish()
        body = self.client.get(f'/api/shares/{SHARE_ID}').get_json()
        self.assertTrue(body['public'])
        self.assertEqual({c['term'] for c in body['cards']}, {'die Stelle', 'leiten'})
        self.assertNotIn('seen', body['cards'][0])  # the owner's progress is never shared

    def test_unpublished_link_still_hides_cards(self):
        body = self.client.get(f'/api/shares/{SHARE_ID}').get_json()
        self.assertFalse(body['public'])
        self.assertEqual(body['cards'], [])

    def test_published_deck_card_pictures_load_signed_out(self):
        self.publish()
        card = self.client.get(f'/api/images/{self.card_image_id}?share={SHARE_ID}')
        self.assertEqual(card.status_code, 200)
        self.assertEqual(card.data, b'card-bytes')

    def test_other_pictures_stay_private_even_for_a_published_deck(self):
        self.publish()
        stranger = str(main.images.put(b'other', content_type='image/png', metadata={'user_email': OWNER}))
        self.assertEqual(self.client.get(f'/api/images/{stranger}?share={SHARE_ID}').status_code, 404)

    def test_public_library_lists_published_decks_signed_out(self):
        main.flashcards_collection.update_one({'user_email': OWNER}, {'$set': {
            'collections.German.extra': main._default_card('third card')}})
        self.publish()
        response = self.client.get('/api/public/decks')
        self.assertEqual(response.status_code, 200)
        self.assertEqual([d['collection'] for d in response.get_json()['decks']], ['German'])

    def test_signed_out_cannot_follow_or_edit(self):
        self.publish()
        self.assertEqual(self.client.post(f'/api/shares/{SHARE_ID}/follow', json={}).status_code, 401)
        self.assertEqual(self.client.post(f'/api/shares/{SHARE_ID}/cards', json={'word': 'x', 'ans': 'y'}).status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
