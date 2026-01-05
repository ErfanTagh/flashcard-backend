import os
import json
from flask import Flask, Response, request, jsonify
from bson.objectid import ObjectId
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
    print(f"Connected to MongoDB at {mongo_host}:{mongo_port}")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    flashcards_collection = None

AUTH0_DOMAIN = 'dev-43bumhcy.us.auth0.com'
API_AUDIENCE = 'recallcards'
ALGORITHMS = ["RS256"]


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
    
    all_cards = {}
    for document in flashcards_collection.find():
        if 'user_email' in document:
            # Migrate if needed
            collections = migrate_user_to_collections(document)
            all_cards[document['user_email']] = collections
    
    return Response(json.dumps(all_cards), mimetype='application/json')


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
    cards_list = list(cards.items())
    
    if index is not None:
        try:
            index = int(index)
            if 0 <= index < len(cards_list):
                res = cards_list[index]
                return json.dumps(res)
            else:
                # Index out of range, return first card
                res = cards_list[0]
                return json.dumps(res)
        except ValueError:
            # Invalid index, return first card
            res = cards_list[0]
            return json.dumps(res)
    else:
        # No index specified, return first card
        res = cards_list[0]
        return json.dumps(res)


@app.route('/api/sendwords', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
def send_word():
    if flashcards_collection is None:
        return jsonify({"status": 500, "error": "Database not connected"})
    
    data = request.json
    if not data or 'token' not in data or 'word' not in data or 'ans' not in data:
        return jsonify({"status": 400, "error": "Missing required fields"})
    
    token = data['token']
    word = data['word']
    ans = data['ans']
    collection_name = data.get('collection', 'Default')  # Default collection if not specified
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    
    if not user_doc:
        # Create new user document with collections structure
        collections = {collection_name: {word: ans}}
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
        
        # Add or update the word
        collections[collection_name][word] = ans
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
    
    data = request.json
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
    
    data = request.json
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
    
    if word in cards:
        # Update existing word (including review status updates)
        cards[word] = ans
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
        )
        return jsonify({"status": 200})
    elif oldWord in cards:
        # Rename word (update term name)
        cards[word] = ans
        del cards[oldWord]
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'collections': collections, 'updated_at': datetime.utcnow()}}
        )
        return jsonify({"status": 200})
    
    return jsonify({"status": 404, "error": "Word not found"})


# Collections API endpoints
def migrate_user_to_collections(user_doc):
    """Migrate old 'cards' structure to 'collections' structure"""
    if 'cards' in user_doc and 'collections' not in user_doc:
        collections = {'Default': user_doc['cards']}
        flashcards_collection.update_one(
            {'user_email': user_doc['user_email']},
            {'$set': {'collections': collections, 'default_collection': 'Default'},
             '$unset': {'cards': ''}}
        )
        # Refresh the document
        user_doc['collections'] = collections
        user_doc.pop('cards', None)
        return collections
    elif 'collections' in user_doc:
        return user_doc['collections']
    else:
        # No cards or collections, create empty Default collection
        collections = {'Default': {}}
        flashcards_collection.update_one(
            {'user_email': user_doc['user_email']},
            {'$set': {'collections': collections, 'default_collection': 'Default'}},
            upsert=True
        )
        return collections


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
    
    data = request.json
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
    
    data = request.json
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
    
    # Delete the collection
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
    
    data = request.json
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
    
    data = request.json
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


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    app.logger.error(f"An unexpected error occurred: {error}", exc_info=True)
    response = jsonify({"status": 500, "error": "An unexpected error occurred."})
    response.status_code = 500
    return response


if __name__ == '__main__':
    # for deployment
    # to make it work for both production and development
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
