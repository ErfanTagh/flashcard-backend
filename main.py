import os
import redis
import json
from flask import Flask, Response, request
import json
from bson.objectid import ObjectId
import json
from datetime import datetime
import random
from flask_cors import cross_origin

app = Flask(__name__)




redis = redis.Redis(
    host='localhost',
    port='6379', password="3414", charset="utf-8", decode_responses=True)

key = "hashexample"
entry = redis.hgetall("hashexample")

import json
from six.moves.urllib.request import urlopen
from functools import wraps

from flask import Flask, request, jsonify, _request_ctx_stack
from jose import jwt

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

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)

    return decorated


@app.route('/words', methods=['GET'])
def allwords():
    return Response(json.dumps(redis.hgetall(key)), mimetype='application/json')


@app.route('/words/rand/<token>', methods=['GET'])
def getwordrand(token):
    key = token
    print("token" + key)
    dataaa = redis.hgetall(key)
    if len(dataaa) == 0:

        return json.dumps(["You Don't Have Anything to Memorize ", "Please Add Cards!"])

    else:
        res = random.choice(list(dataaa.items()))

        return json.dumps(res)


@app.route('/sendwords', methods=['POST'])
def send_word():
    data = request.json
    token = data['token']
    key = token

    entry = redis.hgetall(token)

    word = data['word']
    ans = data['ans']

    if word not in entry.keys():
        entry[word] = ans

        redis.hset(key, mapping=entry)

    return {"status": 200}


@app.route('/token', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def send_token():
    return {"status": 200}


@app.route('/delword/<word>', methods=['DELETE'])
def del_word(word):
    data = request.json
    print(data)
    token = data['token']
    key = token
    entry = redis.hgetall(token)

    if word in entry.keys():
        redis.hdel(key, word)
        del entry[word]

    return {"status": 200}


@app.route('/editword', methods=['POST'])
def edit_word():
    data = request.json

    token = data['token']
    key = token
    entry = redis.hgetall(token)

    oldWord = data['oldword']
    word = data['word']
    ans = data['ans']

    print(ans + " top ans")

    if word in entry.keys():
        print(ans + " first if")
        entry[word] = ans
        redis.hset(key, mapping=entry)
        return {"status": 200}

    elif oldWord in entry.keys():
        print(ans + " second if")
        redis.hdel(key, oldWord)
        del entry[oldWord]
        entry[word] = ans
        redis.hset(key, mapping=entry)
        return {"status": 200}
    return {"status": 404}


if __name__ == '__main__':
    # for deployment
    # to make it work for both production and development
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
