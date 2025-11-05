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
def allwords():
    if flashcards_collection is None:
        return Response(json.dumps({}), mimetype='application/json')
    
    all_cards = {}
    for document in flashcards_collection.find():
        if 'user_email' in document and 'cards' in document:
            all_cards[document['user_email']] = document['cards']
    
    return Response(json.dumps(all_cards), mimetype='application/json')


@app.route('/api/words/rand/<token>', methods=['GET'])
def getwordrand(token):
    if flashcards_collection is None:
        return json.dumps(["You Don't Have Anything to Memorize ", "Please Add Cards!"])
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc or 'cards' not in user_doc or len(user_doc['cards']) == 0:
        return json.dumps(["You Don't Have Anything to Memorize ", "Please Add Cards!"])
    
    cards = user_doc['cards']
    res = random.choice(list(cards.items()))
    return json.dumps(res)


@app.route('/api/sendwords', methods=['POST'])
def send_word():
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.json
    if not data or 'token' not in data or 'word' not in data or 'ans' not in data:
        return {"status": 400, "error": "Missing required fields"}
    
    token = data['token']
    word = data['word']
    ans = data['ans']
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    
    if not user_doc:
        # Create new user document
        flashcards_collection.insert_one({
            'user_email': token,
            'cards': {word: ans},
            'created_at': datetime.utcnow()
        })
    else:
        # Update existing user document
        cards = user_doc.get('cards', {})
        if word not in cards:
            cards[word] = ans
            flashcards_collection.update_one(
                {'user_email': token},
                {'$set': {'cards': cards, 'updated_at': datetime.utcnow()}}
            )
        else:
            # Word already exists, update it
            cards[word] = ans
            flashcards_collection.update_one(
                {'user_email': token},
                {'$set': {'cards': cards, 'updated_at': datetime.utcnow()}}
            )
    
    return {"status": 200}


@app.route('/api/token', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def send_token():
    return {"status": 200}


@app.route('/api/delword/<word>', methods=['DELETE'])
def del_word(word):
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.json
    if not data or 'token' not in data:
        return {"status": 400, "error": "Missing token in request body"}
    
    token = data['token']
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if user_doc and 'cards' in user_doc:
        cards = user_doc['cards']
        if word in cards:
            del cards[word]
            flashcards_collection.update_one(
                {'user_email': token},
                {'$set': {'cards': cards, 'updated_at': datetime.utcnow()}}
            )
            return {"status": 200}
        else:
            return {"status": 404, "error": "Word not found"}
    
    return {"status": 404, "error": "User not found"}


@app.route('/api/editword', methods=['POST'])
def edit_word():
    if flashcards_collection is None:
        return {"status": 500, "error": "Database not connected"}
    
    data = request.json
    if not data or 'token' not in data or 'oldword' not in data or 'word' not in data or 'ans' not in data:
        return {"status": 400, "error": "Missing required fields"}
    
    token = data['token']
    oldWord = data['oldword']
    word = data['word']
    ans = data['ans']
    
    user_doc = flashcards_collection.find_one({'user_email': token})
    if not user_doc or 'cards' not in user_doc:
        return {"status": 404, "error": "User not found"}
    
    cards = user_doc['cards']
    
    if word in cards:
        # Update existing word (including review status updates)
        cards[word] = ans
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'cards': cards, 'updated_at': datetime.utcnow()}}
        )
        return {"status": 200}
    elif oldWord in cards:
        # Rename word (update term name)
        cards[word] = ans
        del cards[oldWord]
        flashcards_collection.update_one(
            {'user_email': token},
            {'$set': {'cards': cards, 'updated_at': datetime.utcnow()}}
        )
        return {"status": 200}
    
    return {"status": 404, "error": "Word not found"}


if __name__ == '__main__':
    # for deployment
    # to make it work for both production and development
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
