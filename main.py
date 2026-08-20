import os
import json
from flask import Flask, Response, request, jsonify
from werkzeug.exceptions import HTTPException
from bson.objectid import ObjectId
from bson.errors import InvalidId
import gridfs
from datetime import datetime
import random
import secrets
from flask_cors import cross_origin
from pymongo import MongoClient
from functools import wraps
from six.moves.urllib.request import urlopen
from jose import jwt

app = Flask(__name__)

# MongoDB connection
mongo_host = os.environ.get('MONGO_HOST', 'localhost')
mongo_port = os.environ.get('MONGO_PORT', '27017')
mongo_database = os.environ.get('MONGO_DATABASE', 'flashcards')
mongo_username = os.environ.get('MONGO_USERNAME', '')
mongo_password = os.environ.get('MONGO_PASSWORD', '')

# Build connection string
if mongo_username and mongo_password:
    mongo_uri = f'mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/{mongo_database}?authSource=admin'
else:
    mongo_uri = f'mongodb://{mongo_host}:{mongo_port}/'

try:
    client = MongoClient(mongo_uri)
    db = client[mongo_database]
    flashcards_collection = db.flashcards
    # Card images live in GridFS rather than inside the user document: every
    # card of every collection sits in that one document, so embedding image
    # bytes would make /api/cards drag megabytes down the wire on each call,
    # and would run into the 16MB document ceiling soon after.
    images = gridfs.GridFS(db)
    # One document per shared collection; see the sharing section below.
    shares_collection = db.shares
    print(f"Connected to MongoDB at {mongo_host}:{mongo_port}")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    flashcards_collection = None
    images = None
    shares_collection = None

AUTH0_DOMAIN = 'dev-43bumhcy.us.auth0.com'
API_AUDIENCE = 'recallcards'
ALGORITHMS = ["RS256"]

# Cards were originally stored as a bare definition string, with "needs review"
# encoded by appending this sentinel to that string. They are now stored as
# documents; the sentinel is still understood on read, and still emitted by the
# legacy endpoints so older clients keep working.
REVIEW_KEY = "FFFLASHBACKCARDS"


def _default_card(definition):
    return {
        "definition": definition,
        # GridFS id of a picture shown with the definition, or None. A card may
        # have text, a picture, or both.
        "image": None,
        "seen": 0,
        "correct": 0,
        "incorrect": 0,
        "needs_review": False,
        "last_reviewed": None,
    }


def _normalise_card(value):
    """Coerce whatever is stored for a card into the structured shape."""
    if isinstance(value, dict):
        card = _default_card(value.get("definition", ""))
        for key in card:
            if key in value:
                card[key] = value[key]
        return card

    definition = value if isinstance(value, str) else ""
    needs_review = definition.endswith(REVIEW_KEY)
    if needs_review:
        definition = definition[: -len(REVIEW_KEY)]

    card = _default_card(definition)
    card["needs_review"] = needs_review
    return card


def _legacy_value(card):
    """The definition-plus-sentinel string that older clients expect."""
    return card["definition"] + (REVIEW_KEY if card["needs_review"] else "")


# Deck covers
#
# `collections` maps a name straight to its cards, and everything in this file
# relies on that shape, so per-deck settings live in a parallel map rather than
# being nested inside it. Adding a key here cannot disturb how cards are read.


def _display_name_of(user_doc):
    """The name to show other people, or None if we were never told one."""
    return ((user_doc or {}).get('display_name') or '').strip() or None


def _collection_meta(user_doc):
    return (user_doc or {}).get('collection_meta') or {}


def _cover_of(user_doc, collection_name):
    return _collection_meta(user_doc).get(collection_name, {}).get('cover_image')


def _covers_map(user_doc, collection_names):
    meta = _collection_meta(user_doc)
    return {name: meta.get(name, {}).get('cover_image') for name in collection_names}


def _card_payload(term, card):
    return {"term": term, **card}


# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# /server.py

# Format error response and append status code
def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                             "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must start with"
                             " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must be"
                             " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_auth(f):
    """Determines if the Access Token is valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                     "incorrect claims,"
                                     "please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                     "Unable to parse authentication"
                                     " token."}, 401)

            request.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)

    return decorated


@app.route('/api/words', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def allwords():
    if flashcards_collection is None:
        return Response(json.dumps({}), mimetype='application/json')

    # Scoped to a single user. This used to iterate the whole collection and
    # return every account's cards to any caller.
    email = request.args.get('email')
    if not email:
        return jsonify({"status": 400, "error": "email query parameter is required"}), 400

    user_doc = flashcards_collection.find_one({'user_email': email})
    if not user_doc:
        return Response(json.dumps({}), mimetype='application/json')

    collections = migrate_user_to_collections(user_doc)
    legacy = {
        name: {term: _legacy_value(card) for term, card in cards.items()}
        for name, cards in collections.items()
    }
    return Response(json.dumps({email: legacy}), mimetype='application/json')


@app.route('/api/words/rand/<token>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def getwordrand(token):
    if flashcards_collection is None:
        return json.dumps(["You Don't Have Anything to Memorize ", "Please Add Cards!"])
    
    # Get collection from query parameter, default to 'Default'
    collection_name = request.args.get('collection', 'Default')
    # Get index from query parameter (0-based)
    index = request.args.get('index', None)
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return json.dumps(["You Don't Have Anything to Memorize ", "Please Add Cards!"])
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    # Get cards from the specified collection
    if collection_name not in collections or len(collections[collection_name]) == 0:
        return json.dumps(["You Don't Have Anything to Memorize ", "Please Add Cards!"])
    
    cards = collections[collection_name]
    # Convert to list to maintain insertion order (Python 3.7+ dicts maintain order)
    cards_list = [(term, _legacy_value(card)) for term, card in cards.items()]

    position = 0
    if index is not None:
        try:
            index = int(index)
            if 0 <= index < len(cards_list):
                position = index
        except ValueError:
            pass

    return json.dumps(list(cards_list[position]))


@app.route('/api/sendwords', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def send_word():
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"})
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'word' not in data or 'ans' not in data:
        return jsonify({"status": 400, "error": "Missing required fields"})
    
    token = data['token']
    word = data['word']
    ans = data['ans']
    image_id = data.get('image') or None
    collection_name = data.get('collection', 'Default')  # Default collection if not specified

    # A card needs something on the back, but that something may be a picture.
    if not str(ans).strip() and not image_id:
        return jsonify({"status": 400, "error": "A definition or an image is required"})

    user_doc = flashcards_collection.find_one({'user_email': token})

    if not user_doc:
        # Create new user document with collections structure
        new_card = _default_card(ans)
        new_card['image'] = image_id
        collections = {collection_name: {word: new_card}}
        flashcards_collection.insert_one({
            'user_email': token,
            'collections': collections,
            'default_collection': collection_name,
            'created_at': datetime.utcnow()
        })
    else:
        # Migrate if needed
        collections = migrate_user_to_collections(user_doc)

        # Initialize collection if it doesn't exist
        if collection_name not in collections:
            collections[collection_name] = {}

        # Add or update the word, keeping any review history it already has
        existing = collections[collection_name].get(word)
        card = _normalise_card(existing) if existing else _default_card(ans)
        card['definition'] = ans
        if 'image' in data:
            # Replacing or clearing a picture orphans the old one in GridFS
            # unless it is deleted here.
            if card.get('image') and card['image'] != image_id:
                _delete_image(card['image'])
            card['image'] = image_id
        collections[collection_name][word] = card
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
        )
    
    return {"status": 200}


@app.route('/api/token', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def send_token():
    return {"status": 200}


@app.route('/api/delword/<word>', methods=['DELETE'])
@cross_origin(headers=["Content-Type", "Authorization"])
def del_word(word):
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"})
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"})
    
    token = data['token']
    collection_name = data.get('collection', 'Default')
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return jsonify({"status": 404, "error": "User not found"})
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    # Initialize collection if it doesn't exist
    if collection_name not in collections:
        return jsonify({"status": 404, "error": "Collection not found"})
    
    cards = collections[collection_name]
    if word in cards:
        _delete_image(_normalise_card(cards[word]).get('image'))
        del cards[word]
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
        )
        return jsonify({"status": 200})
    else:
        return jsonify({"status": 404, "error": "Word not found"})


@app.route('/api/editword', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def edit_word():
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"})
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'oldword' not in data or 'word' not in data or 'ans' not in data:
        return jsonify({"status": 400, "error": "Missing required fields"})
    
    token = data['token']
    oldWord = data['oldword']
    word = data['word']
    ans = data['ans']
    collection_name = data.get('collection', 'Default')
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return jsonify({"status": 404, "error": "User not found"})
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    # Initialize collection if it doesn't exist
    if collection_name not in collections:
        collections[collection_name] = {}
    
    cards = collections[collection_name]

    source = word if word in cards else oldWord
    if source not in cards:
        return jsonify({"status": 404, "error": "Word not found"})

    incoming = _normalise_card(ans)
    card = _normalise_card(cards[source])
    card['definition'] = incoming['definition']

    # Only touched when the caller says so, so a client that knows nothing
    # about images cannot wipe one by editing the text.
    if 'image' in data:
        new_image = data.get('image') or None
        if card.get('image') and card['image'] != new_image:
            _delete_image(card['image'])
        card['image'] = new_image

    # Review state is only changed when the caller actually asks. Editing the
    # text of a card must not silently clear the flag on it.
    if 'needs_review' in data:
        card['needs_review'] = bool(data['needs_review'])
    elif incoming['needs_review']:
        # Older clients flag a card by appending the sentinel to the definition.
        card['needs_review'] = True

    if source != word:
        del cards[source]
    cards[word] = card

    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
    )
    return jsonify({"status": 200})


# Collections API endpoints
def migrate_user_to_collections(user_doc):
    """Bring a user document up to the current shape.

    Handles both migrations: the old top-level 'cards' dict into 'collections',
    and bare definition strings into structured card documents. Rewrites the
    document only when something actually changed.
    """
    had_legacy_cards = 'cards' in user_doc and 'collections' not in user_doc

    if had_legacy_cards:
        collections = {'Default': user_doc['cards']}
    elif 'collections' in user_doc:
        collections = user_doc['collections']
    else:
        collections = {'Default': {}}

    normalised = {
        name: {term: _normalise_card(value) for term, value in cards.items()}
        for name, cards in collections.items()
    }

    if normalised != collections or had_legacy_cards or 'default_collection' not in user_doc:
        update = {'$set': {
            'collections': normalised,
            'default_collection': user_doc.get('default_collection', 'Default'),
        }}
        if had_legacy_cards:
            update['$unset'] = {'cards': ''}

        flashcards_collection.update_one(
            {'user_email': user_doc['user_email']}, update, upsert=True
        )

    user_doc['collections'] = normalised
    user_doc.pop('cards', None)
    return normalised


@app.route('/api/collections/<token>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def get_collections(token):
    """Get all collections for a user"""
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        # Return empty structure for new users
        return Response(json.dumps({'collections': ['Default'], 'default_collection': 'Default'}), mimetype='application/json')
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    # Refresh user_doc to get updated structure
    user_doc = flashcards_collection.find_one({'user_email': token})
    
    collection_names = list(collections.keys())
    # An account can exist with no collections now that signing in records a
    # profile before any cards are added. Every client assumes at least one
    # deck, so present the same starting point a brand-new user gets.
    if not collection_names:
        collection_names = ['Default']
    default_collection = user_doc.get('default_collection', 'Default') if user_doc else 'Default'
    
    return Response(json.dumps({
        'collections': collection_names,
        'default_collection': default_collection,
        'covers': _covers_map(user_doc, collection_names),
    }), mimetype='application/json')


@app.route('/api/collections', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def create_collection():
    """Create a new collection"""
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'collection_name' not in data:
        return {"status": 400, "error": "Missing required fields"}
    
    token = data['token']
    collection_name = data['collection_name'].strip()
    
    if not collection_name:
        return {"status": 400, "error": "Collection name cannot be empty"}
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    
    if not user_doc:
        # Create new user with the collection
        collections = {collection_name: {}}
        flashcards_collection.insert_one({
            'user_email': token,
            'collections': collections,
            'default_collection': collection_name,
            'created_at': datetime.utcnow()
        })
    else:
        # Migrate if needed
        collections = migrate_user_to_collections(user_doc)
        
        if collection_name in collections:
            return {"status": 400, "error": "Collection already exists"}
        
        collections[collection_name] = {}
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
        )
    
    return {"status": 200}


@app.route('/api/collections/<collection_name>', methods=['DELETE'])
@cross_origin(headers=["Content-Type", "Authorization"])
def delete_collection(collection_name):
    """Delete a collection"""
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return {"status": 400, "error": "Missing token in request body"}
    
    token = data['token']
    
    if collection_name == 'Default':
        return {"status": 400, "error": "Cannot delete Default collection"}
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return {"status": 404, "error": "User not found"}
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    if collection_name not in collections:
        return {"status": 404, "error": "Collection not found"}
    
    # Delete the collection, the pictures its cards referred to, and any share
    # link pointing at it -- the link would otherwise 404 forever.
    for image_id in _card_image_ids(collections[collection_name]):
        _delete_image(image_id)
    if shares_collection is not None:
        shares_collection.delete_many({'owner_email': token, 'collection_name': collection_name})

    meta = dict(_collection_meta(user_doc))
    _delete_image(meta.get(collection_name, {}).get('cover_image'))
    meta.pop(collection_name, None)

    del collections[collection_name]
    
    # If it was the default collection, set Default as default
    default_collection = user_doc.get('default_collection', 'Default')
    if default_collection == collection_name:
        default_collection = 'Default'
    
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collections': collections, 'default_collection': default_collection,
                  'collection_meta': meta, 'updated_at': datetime.utcnow()}}
    )

    return {"status": 200}


@app.route('/api/collections/default', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def set_default_collection():
    """Set the default collection"""
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'collection_name' not in data:
        return {"status": 400, "error": "Missing required fields"}
    
    token = data['token']
    collection_name = data['collection_name']
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return {"status": 404, "error": "User not found"}
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    if collection_name not in collections:
        return {"status": 404, "error": "Collection not found"}
    
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'default_collection': collection_name, 'updated_at': datetime.utcnow()}}
    )
    
    return {"status": 200}


@app.route('/api/collections/<old_collection_name>/rename', methods=['PUT'])
@cross_origin(headers=["Content-Type", "Authorization"])
def rename_collection(old_collection_name):
    """Rename a collection"""
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'new_collection_name' not in data:
        return {"status": 400, "error": "Missing required fields"}
    
    token = data['token']
    new_collection_name = data['new_collection_name'].strip()
    
    if not new_collection_name:
        return {"status": 400, "error": "Collection name cannot be empty"}
    
    if old_collection_name == 'Default':
        return {"status": 400, "error": "Cannot rename Default collection"}
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return {"status": 404, "error": "User not found"}
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    if old_collection_name not in collections:
        return {"status": 404, "error": "Collection not found"}
    
    if new_collection_name in collections:
        return {"status": 400, "error": "A collection with that name already exists"}
    
    # Rename the collection
    collections[new_collection_name] = collections[old_collection_name]
    del collections[old_collection_name]
    
    # Update default_collection if it was the renamed collection
    default_collection = user_doc.get('default_collection', 'Default')
    if default_collection == old_collection_name:
        default_collection = new_collection_name

    # Per-deck settings are keyed by name too, so the cover moves with it.
    meta = dict(_collection_meta(user_doc))
    if old_collection_name in meta:
        meta[new_collection_name] = meta.pop(old_collection_name)

    # A share link points at a collection by name, so it has to follow the
    # rename or it would resolve to nothing.
    if shares_collection is not None:
        shares_collection.update_many(
            {'owner_email': token, 'collection_name': old_collection_name},
            {'$set': {'collection_name': new_collection_name}},
        )
    
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collections': collections, 'default_collection': default_collection,
                  'collection_meta': meta, 'updated_at': datetime.utcnow()}}
    )

    return {"status": 200}


@app.route('/api/collections/<token>/stats', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def get_collection_stats(token):
    """Get statistics for all collections (card counts)"""
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return Response(json.dumps({'stats': {}}), mimetype='application/json')
    
    # Migrate if needed
    collections = migrate_user_to_collections(user_doc)
    
    stats = {}
    for collection_name, cards in collections.items():
        stats[collection_name] = len(cards)
    
    return Response(json.dumps({'stats': stats}), mimetype='application/json')


@app.route('/api/cards', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def get_cards():
    """Every card in a collection, with its review history."""
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    email = request.args.get('email')
    if not email:
        return jsonify({"status": 400, "error": "email query parameter is required"}), 400

    collection_name = request.args.get('collection', 'Default')

    user_doc = flashcards_collection.find_one({'user_email': email})
    if not user_doc:
        return Response(json.dumps({'cards': []}), mimetype='application/json')

    collections = migrate_user_to_collections(user_doc)
    cards = collections.get(collection_name, {})

    payload = [_card_payload(term, card) for term, card in cards.items()]
    return Response(json.dumps({'cards': payload}), mimetype='application/json')


@app.route('/api/review', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def record_review():
    """Record the outcome of studying one card."""
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"})

    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'word' not in data or 'outcome' not in data:
        return jsonify({"status": 400, "error": "Missing required fields"})

    outcome = data['outcome']
    if outcome not in ('correct', 'incorrect'):
        return jsonify({"status": 400, "error": "outcome must be 'correct' or 'incorrect'"})

    token = data['token']
    word = data['word']
    collection_name = data.get('collection', 'Default')

    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return jsonify({"status": 404, "error": "User not found"})

    collections = migrate_user_to_collections(user_doc)
    cards = collections.get(collection_name)
    if cards is None:
        return jsonify({"status": 404, "error": "Collection not found"})
    if word not in cards:
        return jsonify({"status": 404, "error": "Word not found"})

    card = _normalise_card(cards[word])
    card['seen'] += 1
    card['last_reviewed'] = datetime.utcnow().isoformat()
    if outcome == 'correct':
        card['correct'] += 1
        card['needs_review'] = False
    else:
        card['incorrect'] += 1
        card['needs_review'] = True

    cards[word] = card
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
    )

    return Response(
        json.dumps({'status': 200, 'card': _card_payload(word, card)}),
        mimetype='application/json',
    )


@app.route('/api/progress', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def get_progress():
    """Real study statistics, derived from recorded review outcomes."""
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    email = request.args.get('email')
    if not email:
        return jsonify({"status": 400, "error": "email query parameter is required"}), 400

    collection_name = request.args.get('collection', 'Default')

    empty = {'total': 0, 'studied': 0, 'unseen': 0, 'needs_review': 0,
             'known': 0, 'attempts': 0, 'accuracy': 0, 'last_reviewed': None}

    user_doc = flashcards_collection.find_one({'user_email': email})
    if not user_doc:
        return Response(json.dumps(empty), mimetype='application/json')

    collections = migrate_user_to_collections(user_doc)
    cards = list(collections.get(collection_name, {}).values())
    if not cards:
        return Response(json.dumps(empty), mimetype='application/json')

    studied = sum(1 for c in cards if c['seen'] > 0)
    needs_review = sum(1 for c in cards if c['needs_review'])
    # "Known" means answered at least once and not currently flagged. A card you
    # have never opened is neither known nor unknown.
    known = sum(1 for c in cards if c['seen'] > 0 and not c['needs_review'])
    correct = sum(c['correct'] for c in cards)
    attempts = correct + sum(c['incorrect'] for c in cards)
    timestamps = [c['last_reviewed'] for c in cards if c['last_reviewed']]

    return Response(json.dumps({
        'total': len(cards),
        'studied': studied,
        'unseen': len(cards) - studied,
        'needs_review': needs_review,
        'known': known,
        'attempts': attempts,
        'accuracy': round(correct / attempts * 100) if attempts else 0,
        'last_reviewed': max(timestamps) if timestamps else None,
    }), mimetype='application/json')


# Card images

MAX_IMAGE_BYTES = 5 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {
    "image/jpeg", "image/png", "image/gif",
    "image/webp", "image/heic", "image/heif",
}

# Flask rejects a larger body before the view runs, which turns a huge upload
# into a cheap 413 instead of buffering it.
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES + (256 * 1024)


def _delete_image(image_id):
    """Remove a stored image, ignoring one that has already gone."""
    if images is None or not image_id:
        return
    try:
        images.delete(ObjectId(image_id))
    except (InvalidId, TypeError, gridfs.errors.NoFile):
        pass


def _copy_image_for(image_id, new_owner_email):
    """Duplicate a stored picture under another account.

    Importing a shared collection copies the bytes rather than pointing at the
    owner's file, so the recipient keeps their cards intact if the owner later
    deletes theirs, and image access stays scoped to one account.
    """
    if images is None or not image_id:
        return None
    try:
        original = images.get(ObjectId(image_id))
    except (InvalidId, TypeError, gridfs.errors.NoFile):
        return None

    copied = images.put(
        original.read(),
        contentType=original.content_type,
        filename=original.filename,
        metadata={"user_email": new_owner_email, "uploaded_at": datetime.utcnow().isoformat()},
    )
    return str(copied)


def _card_image_ids(cards):
    """Every image referenced by a dict of cards."""
    for value in cards.values():
        image_id = _normalise_card(value).get("image")
        if image_id:
            yield image_id


@app.errorhandler(413)
def handle_too_large(error):
    return jsonify({
        "status": 413,
        "error": f"Image is too large. The limit is {MAX_IMAGE_BYTES // (1024 * 1024)}MB.",
    }), 413


@app.route('/api/images', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def upload_image():
    """Store a picture and return the id a card refers to it by."""
    if images is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    upload = request.files.get('file')
    token = request.form.get('token')
    if not upload or not token:
        return jsonify({"status": 400, "error": "A file and a token are required"}), 400

    content_type = (upload.mimetype or "").lower()
    if content_type not in ALLOWED_IMAGE_TYPES:
        return jsonify({
            "status": 400,
            "error": "Unsupported image type. Use JPEG, PNG, GIF, WEBP or HEIC.",
        }), 400

    data = upload.read()
    if not data:
        return jsonify({"status": 400, "error": "The file is empty"}), 400
    if len(data) > MAX_IMAGE_BYTES:
        return jsonify({
            "status": 413,
            "error": f"Image is too large. The limit is {MAX_IMAGE_BYTES // (1024 * 1024)}MB.",
        }), 413

    image_id = images.put(
        data,
        contentType=content_type,
        filename=upload.filename or "card-image",
        metadata={"user_email": token, "uploaded_at": datetime.utcnow().isoformat()},
    )
    return Response(json.dumps({"status": 200, "image_id": str(image_id)}),
                    mimetype='application/json')


@app.route('/api/images/<image_id>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def get_image(image_id):
    """Serve a stored picture.

    Scoped to the owner, matching how the rest of this API treats an email
    address as the key to an account's data.
    """
    if images is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    email = request.args.get('email')
    share_id = request.args.get('share')
    if not email and not share_id:
        return jsonify({"status": 400, "error": "email or share query parameter is required"}), 400

    try:
        stored = images.get(ObjectId(image_id))
    except (InvalidId, TypeError, gridfs.errors.NoFile):
        return jsonify({"status": 404, "error": "Image not found"}), 404

    owner = (stored.metadata or {}).get("user_email")

    # Someone previewing a share is not the owner, so authorise them through
    # the link instead: the picture must belong to whoever shared it.
    if share_id:
        share = (shares_collection.find_one({'share_id': share_id})
                 if shares_collection is not None else None)
        if not share or (owner and owner != share['owner_email']):
            return jsonify({"status": 404, "error": "Image not found"}), 404
    elif owner and owner != email:
        return jsonify({"status": 404, "error": "Image not found"}), 404

    response = Response(stored.read(), mimetype=stored.content_type or "application/octet-stream")
    # The bytes behind an id never change, so this can be cached hard.
    response.headers["Cache-Control"] = "private, max-age=31536000, immutable"
    return response


# Importing a deck from JSON
#
# Written to be forgiving about shape, because the point is to paste in what a
# language model produced and have it work. Models reliably get the idea and
# unreliably get the spelling: "front"/"back" instead of "term"/"definition", a
# bare list with no wrapper, a stray blank entry. All of that is accepted. What
# is not accepted is anything that would produce a broken card, and the caller
# is told exactly which entry failed and why.

MAX_IMPORT_CARDS = 500
MAX_TERM_LENGTH = 200
MAX_DEFINITION_LENGTH = 2000

# Aliases seen in practice from models asked for flashcards.
TERM_KEYS = ("term", "front", "question", "word", "prompt")
DEFINITION_KEYS = ("definition", "back", "answer", "meaning", "response")


def _unique_collection_name(collections, requested):
    """A name that does not collide with one the user already has."""
    name = (requested or "").strip() or "Imported"
    if name not in collections:
        return name
    suffix = 2
    while f"{name} ({suffix})" in collections:
        suffix += 1
    return f"{name} ({suffix})"


def _first_key(entry, keys):
    for key in keys:
        if key in entry and entry[key] is not None:
            return entry[key]
    return None


def parse_deck_json(payload):
    """Turn a parsed JSON document into (name, cards, warnings).

    Raises ValueError with a message meant to be shown to the person who
    pasted it.
    """
    name = ""
    if isinstance(payload, dict):
        raw_cards = payload.get("cards")
        if raw_cards is None:
            raw_cards = _first_key(payload, ("flashcards", "items", "deck"))
        name = str(payload.get("name") or payload.get("deck_name") or "").strip()
    elif isinstance(payload, list):
        # A bare list of cards is a common shape; the name comes from the form.
        raw_cards = payload
    else:
        raise ValueError("The JSON should be an object with a \"cards\" list, or a list of cards.")

    if not isinstance(raw_cards, list):
        raise ValueError("\"cards\" should be a list.")
    if not raw_cards:
        raise ValueError("There are no cards in that JSON.")
    if len(raw_cards) > MAX_IMPORT_CARDS:
        raise ValueError(f"That is {len(raw_cards)} cards; the limit is {MAX_IMPORT_CARDS}.")

    cards = {}
    warnings = []
    for index, entry in enumerate(raw_cards, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Card {index} is not an object with a term and a definition.")

        term = _first_key(entry, TERM_KEYS)
        definition = _first_key(entry, DEFINITION_KEYS)

        if term is None:
            raise ValueError(f"Card {index} has no \"term\".")
        if definition is None:
            raise ValueError(f"Card {index} has no \"definition\".")
        if isinstance(term, (dict, list)) or isinstance(definition, (dict, list)):
            raise ValueError(f"Card {index} should use plain text, not nested objects.")

        term = str(term).strip()
        definition = str(definition).strip()

        if not term:
            raise ValueError(f"Card {index} has an empty term.")
        if not definition:
            raise ValueError(f"Card {index} (\"{term[:40]}\") has an empty definition.")
        if len(term) > MAX_TERM_LENGTH:
            raise ValueError(f"Card {index} has a term longer than {MAX_TERM_LENGTH} characters.")
        if len(definition) > MAX_DEFINITION_LENGTH:
            raise ValueError(
                f"Card {index} (\"{term[:40]}\") has a definition longer than "
                f"{MAX_DEFINITION_LENGTH} characters."
            )

        # Cards are keyed by term, so a repeat would silently replace the first.
        if term in cards:
            warnings.append(f"\"{term}\" appears more than once; the last one was kept.")
        cards[term] = definition

    return name, cards, warnings


@app.route('/api/collections/import', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def import_deck_json():
    """Create a deck from a JSON document."""
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"}), 400

    token = data['token']
    payload = data.get('deck')
    if payload is None:
        return jsonify({"status": 400, "error": "Missing deck in request body"}), 400

    try:
        parsed_name, cards, warnings = parse_deck_json(payload)
    except ValueError as error:
        return jsonify({"status": 400, "error": str(error)}), 400

    user_doc = flashcards_collection.find_one({'user_email': token})
    collections = migrate_user_to_collections(user_doc) if user_doc else {}

    requested = (data.get('name') or parsed_name or "Imported").strip()
    name = _unique_collection_name(collections, requested)

    collections[name] = {term: _default_card(definition) for term, definition in cards.items()}

    if user_doc:
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}},
        )
    else:
        flashcards_collection.insert_one({
            'user_email': token,
            'collections': collections,
            'default_collection': name,
            'created_at': datetime.utcnow(),
        })

    return Response(json.dumps({
        'status': 200,
        'collection': name,
        'imported': len(cards),
        'warnings': warnings,
    }), mimetype='application/json')


@app.route('/api/profile', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def save_profile():
    """Record who an email address belongs to.

    The identity provider is the only thing that knows a person's name -- for a
    Google login Auth0 fills in given_name and family_name itself -- and it only
    tells the client. So the client hands it here once after signing in, and
    every feature that needs to show a name reads it from the account instead of
    being passed one.

    Nothing else changes: the email remains the key, and a caller that skips
    this simply has no name attached.
    """
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"}), 400

    token = data['token']
    name = (data.get('name') or '').strip()[:60]

    update = {'updated_at': datetime.utcnow()}
    if name:
        update['display_name'] = name

    # Upsert: someone can sign in before they own any cards.
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': update, '$setOnInsert': {'collections': {}, 'created_at': datetime.utcnow()}},
        upsert=True,
    )
    return jsonify({"status": 200, "display_name": name or None})


@app.route('/api/collections/<collection_name>/cover', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def set_collection_cover(collection_name):
    """Set or clear a deck's cover picture.

    Takes an id from /api/images, so uploading and attaching stay separate the
    way they do for cards.
    """
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"}), 400

    token = data['token']
    image_id = data.get('image') or None

    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return jsonify({"status": 404, "error": "User not found"}), 404

    collections = migrate_user_to_collections(user_doc)
    if collection_name not in collections:
        return jsonify({"status": 404, "error": "Collection not found"}), 404

    meta = dict(_collection_meta(user_doc))
    previous = meta.get(collection_name, {}).get('cover_image')
    if previous and previous != image_id:
        _delete_image(previous)

    entry = dict(meta.get(collection_name, {}))
    if image_id:
        entry['cover_image'] = image_id
    else:
        entry.pop('cover_image', None)
    meta[collection_name] = entry

    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collection_meta': meta, 'updated_at': datetime.utcnow()}},
    )
    return jsonify({"status": 200, "cover": image_id})


# Sharing collections
#
# A share is a random, unguessable id that stands for "this user's collection
# called X". Anyone holding the link can look at it and copy it; there is no
# per-recipient permission, which is the model people expect from a share link
# and the only one that works without accounts for the recipients.
#
# The link reads through to the owner's live collection rather than freezing a
# snapshot, so edits reach anyone who opens it later. Importing takes a copy at
# that moment: the recipient gets their own cards, their own pictures and a
# clean review history, and nothing the owner does afterwards can reach into
# their account.


def _share_url_path(share_id):
    return f"/import/{share_id}"


def _share_payload(share):
    return {
        "share_id": share["share_id"],
        "collection": share["collection_name"],
        "allow_edit": bool(share.get("allow_edit")),
        "path": _share_url_path(share["share_id"]),
    }


@app.route('/api/collections/<collection_name>/share', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def share_collection(collection_name):
    """Create a share link for a collection, or return the one it already has."""
    if flashcards_collection is None or shares_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"}), 400

    token = data['token']
    # Accepted for clients that send it inline, but the account's own name wins:
    # see /api/profile.
    display_name = (data.get('display_name') or '').strip()[:60] or None

    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return jsonify({"status": 404, "error": "User not found"}), 404

    collections = migrate_user_to_collections(user_doc)
    if collection_name not in collections:
        return jsonify({"status": 404, "error": "Collection not found"}), 404

    # Idempotent: sharing twice hands back the same link rather than making a
    # second one that also works forever.
    existing = shares_collection.find_one({
        'owner_email': token, 'collection_name': collection_name,
    })
    if existing:
        changes = {}
        if display_name and existing.get('owner_name') != display_name:
            changes['owner_name'] = display_name
        # Only the owner reaches this endpoint, so this is the one place
        # collaboration can be switched on or off.
        if 'allow_edit' in data:
            changes['allow_edit'] = bool(data['allow_edit'])
        if changes:
            shares_collection.update_one({'_id': existing['_id']}, {'$set': changes})
            existing.update(changes)
        return Response(json.dumps({"status": 200, **_share_payload(existing)}),
                        mimetype='application/json')

    share = {
        'share_id': secrets.token_urlsafe(9),
        'owner_email': token,
        'owner_name': display_name,
        'collection_name': collection_name,
        # Off unless asked for: a link that only hands out copies cannot damage
        # the original, and that is the safe default for a link that will be
        # forwarded further than intended.
        'allow_edit': bool(data.get('allow_edit')),
        'created_at': datetime.utcnow(),
    }
    shares_collection.insert_one(share)
    return Response(json.dumps({"status": 200, **_share_payload(share)}),
                    mimetype='application/json')


@app.route('/api/collections/<collection_name>/share', methods=['DELETE'])
@cross_origin(headers=["Content-Type", "Authorization"])
def unshare_collection(collection_name):
    """Revoke a share link. Copies already taken are unaffected."""
    if shares_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"}), 400

    result = shares_collection.delete_one({
        'owner_email': data['token'], 'collection_name': collection_name,
    })
    if result.deleted_count == 0:
        return jsonify({"status": 404, "error": "That collection is not shared"}), 404
    return jsonify({"status": 200})


@app.route('/api/shares/<share_id>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
def get_share(share_id):
    """What is behind a share link. Deliberately open: holding the link is the
    permission, and a recipient has to see what they are importing first."""
    if flashcards_collection is None or shares_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    share = shares_collection.find_one({'share_id': share_id})
    if not share:
        return jsonify({"status": 404, "error": "This link is no longer available"}), 404

    owner_doc = flashcards_collection.find_one({'user_email': share['owner_email']})
    if not owner_doc:
        return jsonify({"status": 404, "error": "This link is no longer available"}), 404

    collections = migrate_user_to_collections(owner_doc)
    cards = collections.get(share['collection_name'])
    if cards is None:
        # The owner renamed or deleted it after sharing.
        return jsonify({"status": 404, "error": "This link is no longer available"}), 404

    # Review history is the owner's, not part of what is being shared.
    payload = []
    for term, value in cards.items():
        card = _normalise_card(value)
        payload.append({
            'term': term,
            'definition': card['definition'],
            'image': card['image'],
        })

    # A viewer that says who it is gets told whether the deck is already theirs,
    # so the page can offer something other than a button that cannot work.
    viewer = request.args.get('email')

    return Response(json.dumps({
        'status': 200,
        'share_id': share_id,
        'collection': share['collection_name'],
        'is_owner': bool(viewer) and viewer == share['owner_email'],
        'allow_edit': bool(share.get('allow_edit')),
        # Read from the account so a changed name shows up on links already
        # out in the world; the copy on the share is only a fallback for links
        # made before profiles were recorded.
        'owner_name': _display_name_of(owner_doc) or share.get('owner_name'),
        'cover': _cover_of(owner_doc, share['collection_name']),
        'card_count': len(payload),
        'cards': payload,
    }), mimetype='application/json')


MAX_SHARED_DECK_CARDS = 1000


def _open_shared_deck(share_id, token):
    """Resolve a share that grants editing, for a caller who supplies a token.

    Returns (owner_doc, collections, cards, error_response). Only one of the
    first three and the last is meaningful.
    """
    if flashcards_collection is None or shares_collection is None:
        return None, None, None, (jsonify({"status": 500, "error": "Database not connected"}), 500)
    if not token:
        return None, None, None, (jsonify({"status": 400, "error": "Missing token in request body"}), 400)

    share = shares_collection.find_one({'share_id': share_id})
    if not share:
        return None, None, None, (jsonify({"status": 404, "error": "This link is no longer available"}), 404)

    # Editing through a link is off unless the owner turned it on. The owner
    # themselves always reaches their own deck through the normal endpoints.
    if not share.get('allow_edit') and share['owner_email'] != token:
        return None, None, None, (jsonify({
            "status": 403,
            "error": "This deck is shared read-only. Ask the owner to allow editing.",
        }), 403)

    owner_doc = flashcards_collection.find_one({'user_email': share['owner_email']})
    if not owner_doc:
        return None, None, None, (jsonify({"status": 404, "error": "This link is no longer available"}), 404)

    collections = migrate_user_to_collections(owner_doc)
    cards = collections.get(share['collection_name'])
    if cards is None:
        return None, None, None, (jsonify({"status": 404, "error": "This link is no longer available"}), 404)

    return share, collections, cards, None


def _save_shared_deck(share, collections):
    flashcards_collection.update_one(
        {'user_email': share['owner_email']},
        {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}},
    )


@app.route('/api/shares/<share_id>/cards', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def add_card_to_shared_deck(share_id):
    """Add a card to a deck shared for editing.

    Writes into the owner's deck, so everyone holding the link sees it. There
    is deliberately no delete counterpart: a link travels further than the
    group it was meant for, and losing a deck days before an exam is not
    something an undo-less app should make possible. Removing a card stays with
    the owner.
    """
    data = request.get_json(silent=True) or {}
    share, collections, cards, error = _open_shared_deck(share_id, data.get('token'))
    if error:
        return error

    term = (data.get('word') or '').strip()
    definition = (data.get('ans') or '').strip()
    image_id = data.get('image') or None
    if not term:
        return jsonify({"status": 400, "error": "A term is required"}), 400
    if not definition and not image_id:
        return jsonify({"status": 400, "error": "A definition or an image is required"}), 400
    if term not in cards and len(cards) >= MAX_SHARED_DECK_CARDS:
        return jsonify({
            "status": 400,
            "error": f"This deck has reached {MAX_SHARED_DECK_CARDS} cards.",
        }), 400

    existing = cards.get(term)
    card = _normalise_card(existing) if existing else _default_card(definition)
    card['definition'] = definition
    if image_id:
        card['image'] = image_id
    cards[term] = card

    _save_shared_deck(share, collections)
    return jsonify({"status": 200, "collection": share['collection_name']})


@app.route('/api/shares/<share_id>/cards/edit', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def edit_card_in_shared_deck(share_id):
    """Change a card in a deck shared for editing, including renaming its term."""
    data = request.get_json(silent=True) or {}
    share, collections, cards, error = _open_shared_deck(share_id, data.get('token'))
    if error:
        return error

    old_term = (data.get('oldword') or '').strip()
    term = (data.get('word') or '').strip()
    definition = (data.get('ans') or '').strip()
    if not old_term or not term:
        return jsonify({"status": 400, "error": "Missing required fields"}), 400
    if old_term not in cards:
        return jsonify({"status": 404, "error": "That card is no longer in the deck"}), 404
    if not definition and not (data.get('image') or cards.get(old_term, {}).get('image')):
        return jsonify({"status": 400, "error": "A definition or an image is required"}), 400

    card = _normalise_card(cards[old_term])
    card['definition'] = definition
    if 'image' in data:
        card['image'] = data.get('image') or None

    # Renaming onto an existing card would silently swallow it.
    if term != old_term and term in cards:
        return jsonify({"status": 400, "error": f'The deck already has a card called "{term}"'}), 400

    if term != old_term:
        del cards[old_term]
    cards[term] = card

    _save_shared_deck(share, collections)
    return jsonify({"status": 200, "collection": share['collection_name']})


@app.route('/api/shares/<share_id>/import', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def import_share(share_id):
    """Copy a shared collection into the caller's account."""
    if flashcards_collection is None or shares_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data:
        return jsonify({"status": 400, "error": "Missing token in request body"}), 400

    token = data['token']
    share = shares_collection.find_one({'share_id': share_id})
    if not share:
        return jsonify({"status": 404, "error": "This link is no longer available"}), 404

    owner_doc = flashcards_collection.find_one({'user_email': share['owner_email']})
    source = migrate_user_to_collections(owner_doc).get(share['collection_name']) if owner_doc else None
    if source is None:
        return jsonify({"status": 404, "error": "This link is no longer available"}), 404
    if not source:
        return jsonify({"status": 400, "error": "That collection is empty"}), 400

    # Importing your own link would copy a deck alongside itself, which is
    # never what opening it means -- people open their own share links to check
    # they work. Refused here rather than in a client, so no client can do it.
    if share['owner_email'] == token:
        return jsonify({
            "status": 400,
            "error": "This is your own deck. It is already in your collections.",
        }), 400

    user_doc = flashcards_collection.find_one({'user_email': token})
    collections = migrate_user_to_collections(user_doc) if user_doc else {}

    # Never overwrite what the recipient already has.
    requested = (data.get('collection_name') or share['collection_name']).strip()
    name = _unique_collection_name(collections, requested or share['collection_name'])

    imported = {}
    for term, value in source.items():
        card = _normalise_card(value)
        # Fresh cards: the recipient has not studied any of this yet.
        copy = _default_card(card['definition'])
        copy['image'] = _copy_image_for(card['image'], token)
        imported[term] = copy

    collections[name] = imported

    # The cover is copied like any other picture, so the recipient's deck keeps
    # looking right even if the owner later deletes theirs.
    meta = dict(_collection_meta(user_doc))
    copied_cover = _copy_image_for(_cover_of(owner_doc, share['collection_name']), token)
    if copied_cover:
        meta[name] = {**meta.get(name, {}), 'cover_image': copied_cover}

    if user_doc:
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'collection_meta': meta,
                      'updated_at': datetime.utcnow()}},
        )
    else:
        flashcards_collection.insert_one({
            'user_email': token,
            'collections': collections,
            'collection_meta': meta,
            'default_collection': name,
            'created_at': datetime.utcnow(),
        })

    return Response(json.dumps({
        'status': 200,
        'collection': name,
        'imported': len(imported),
    }), mimetype='application/json')


# Quiz grading
#
# Lives here rather than in each client so that a quiz means the same thing
# everywhere. The outcome of a grading decision is written to a card's review
# history, so two clients grading differently would make the same accuracy
# figure mean two different things.
#
# Requiring the answer to equal the definition is right for "Danke -> Thanks"
# and useless for a forty-word definition, where nobody reproduces the wording
# and being told "wrong" teaches nothing. So answers are scored, and the client
# is expected to let the reader overrule the result.

CORRECT_THRESHOLD = 0.9
CLOSE_THRESHOLD = 0.55
LEADING_ARTICLES = ("a", "an", "the")


def _normalise_answer(text):
    """Lowercase, drop punctuation, collapse whitespace, ignore a leading article."""
    cleaned = "".join(c if c.isalnum() or c.isspace() else " " for c in text.lower())
    words = cleaned.split()
    if words and words[0] in LEADING_ARTICLES:
        words = words[1:]
    return " ".join(words)


def _typo_allowance(length):
    """How many character edits still count as the right answer."""
    if length < 5:
        return 0    # "need" and "seed" are different words
    if length < 12:
        return 1
    return 2


def _edit_distance(a, b):
    """Optimal string alignment: Levenshtein plus transposition.

    Plain Levenshtein charges two edits for swapping adjacent letters, so
    "thnaks" would score as far from "thanks" as an unrelated word. Transposing
    is the commonest typing mistake there is; it costs one.
    """
    if not a:
        return len(b)
    if not b:
        return len(a)

    rows = len(a) + 1
    cols = len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _word_overlap(a, b):
    """F1 over the two word multisets.

    Precision and recall together, so neither padding an answer nor writing
    half of it scores well.
    """
    left = a.split()
    right = b.split()
    if not left or not right:
        return 0.0

    remaining = {}
    for word in right:
        remaining[word] = remaining.get(word, 0) + 1

    shared = 0
    for word in left:
        if remaining.get(word, 0) > 0:
            remaining[word] -= 1
            shared += 1
    if shared == 0:
        return 0.0

    precision = shared / len(left)
    recall = shared / len(right)
    return 2 * precision * recall / (precision + recall)


def _character_similarity(a, b):
    """1 - (edit distance / longer length), skipped for long text where the
    comparison is quadratic and word overlap is the better signal anyway."""
    longest = max(len(a), len(b))
    if longest == 0 or longest > 120:
        return 0.0
    return 1 - _edit_distance(a, b) / longest


def grade_answer(answer, definition):
    """Score a typed answer. Returns (grade, similarity)."""
    a = _normalise_answer(answer or "")
    b = _normalise_answer(definition or "")

    if not a or not b:
        return "incorrect", 0.0
    if a == b:
        return "correct", 1.0

    longest = max(len(a), len(b))
    if longest <= 120:
        distance = _edit_distance(a, b)
        if distance <= _typo_allowance(longest):
            return "correct", 1 - distance / longest

    score = max(_word_overlap(a, b), _character_similarity(a, b))
    if score >= CORRECT_THRESHOLD:
        return "correct", score
    if score >= CLOSE_THRESHOLD:
        return "close", score
    return "incorrect", score


@app.route('/api/quiz/grade', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def grade_quiz_answer():
    """Grade a typed answer against a stored card.

    Grading only - the outcome is recorded through /api/review as usual, so a
    reader who overrules the grade changes the single recorded answer instead
    of adding a second one.
    """
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"}), 500

    data = request.get_json(silent=True)
    if not data or 'token' not in data or 'word' not in data or 'answer' not in data:
        return jsonify({"status": 400, "error": "Missing required fields"}), 400

    token = data['token']
    word = data['word']
    collection_name = data.get('collection', 'Default')

    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc:
        return jsonify({"status": 404, "error": "User not found"}), 404

    collections = migrate_user_to_collections(user_doc)
    cards = collections.get(collection_name)
    if cards is None:
        return jsonify({"status": 404, "error": "Collection not found"}), 404
    if word not in cards:
        return jsonify({"status": 404, "error": "Word not found"}), 404

    card = _normalise_card(cards[word])
    if not card['definition'].strip():
        # Picture-only card: there is no text to compare against, so there is
        # nothing this endpoint can honestly say about the answer.
        return jsonify({"status": 400, "error": "This card has no text to grade against"}), 400

    grade, similarity = grade_answer(data['answer'], card['definition'])

    return Response(json.dumps({
        'status': 200,
        'grade': grade,
        'similarity': round(similarity, 4),
        'expected': card['definition'],
    }), mimetype='application/json')


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    # Without this, Flask's own 404/405/415 responses were being swallowed and
    # re-reported as 500s, hiding the real cause from callers.
    if isinstance(error, HTTPException):
        return error

    app.logger.error(f"An unexpected error occurred: {error}", exc_info=True)
    response = jsonify({"status": 500, "error": "An unexpected error occurred."})
    response.status_code = 500
    return response


if __name__ == '__main__':
    # for deployment
    # to make it work for both production and development
    port = int(os.environ.get("PORT", 5000))
    # Debug mode exposes the Werkzeug console; opt in explicitly for local work
    # rather than shipping it on by default.
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host='0.0.0.0', port=port)
