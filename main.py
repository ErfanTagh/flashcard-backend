import os
import json
from flask import Flask, Response, request, jsonify
from werkzeug.exceptions import HTTPException
from bson.objectid import ObjectId
from bson.errors import InvalidId
import gridfs
from datetime import datetime
import random
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
    print(f"Connected to MongoDB at {mongo_host}:{mongo_port}")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    flashcards_collection = None
    images = None

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
    default_collection = user_doc.get('default_collection', 'Default') if user_doc else 'Default'
    
    return Response(json.dumps({
        'collections': collection_names,
        'default_collection': default_collection
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
    
    # Delete the collection, and the pictures its cards referred to
    for image_id in _card_image_ids(collections[collection_name]):
        _delete_image(image_id)
    del collections[collection_name]
    
    # If it was the default collection, set Default as default
    default_collection = user_doc.get('default_collection', 'Default')
    if default_collection == collection_name:
        default_collection = 'Default'
    
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collections': collections, 'default_collection': default_collection, 'updated_at': datetime.utcnow()}}
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
    
    flashcards_collection.update_one(
        {'user_email': token},
        {'$set': {'collections': collections, 'default_collection': default_collection, 'updated_at': datetime.utcnow()}}
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
    if not email:
        return jsonify({"status": 400, "error": "email query parameter is required"}), 400

    try:
        stored = images.get(ObjectId(image_id))
    except (InvalidId, TypeError, gridfs.errors.NoFile):
        return jsonify({"status": 404, "error": "Image not found"}), 404

    owner = (stored.metadata or {}).get("user_email")
    if owner and owner != email:
        return jsonify({"status": 404, "error": "Image not found"}), 404

    response = Response(stored.read(), mimetype=stored.content_type or "application/octet-stream")
    # The bytes behind an id never change, so this can be cached hard.
    response.headers["Cache-Control"] = "private, max-age=31536000, immutable"
    return response


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
