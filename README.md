# flashcard-backend

The fact that we can develop a whole back-end project, including a database, in a single Python file is pretty amazing!\
A main.py file contains all the rest-API endpoints and database queries that interact with the site's front-end (https://github.com/ErfanTagh/flashcard-frontend).\
Users' flashcard values and answers are stored in a Redis database.

```
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

```
It takes the users email as a parameter and returns a random value from the user's stored values.
Using the following function, the front sends the new value-answer to the backend as a POST request:

```
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

```

This file implements Rest-Api functions to delete and edit key-values.














