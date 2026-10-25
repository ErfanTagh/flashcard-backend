# The API now checks who is calling

Until this change, `requires_auth` was applied to exactly one route,
`/api/token`. The other 30 identified the caller from an `email` query
parameter, or from a field named `token` that in fact held the address, and
verified nothing. Knowing an address was the same as owning the account:

```
GET  /api/words?email=someone@example.com          -> that person's cards
DELETE /api/collections/Default {"token": "..."}    -> that person's deck, gone
```

Confirmed against production before the fix: those routes answered `200` with
no credentials, and `200` with a deliberately invalid `Bearer` token, because
the header was never read.

## What changed

`auth.py` holds the verification. Identity comes out of a verified Auth0 access
token and nothing else; an address in the request is ignored.

- `requires_auth` — 27 routes. No valid token, no access.
- `optional_auth` — 3 routes a signed-out visitor is meant to read: a share
  link (`GET /api/shares/<id>`), the public library (`GET /api/public/decks`),
  and pictures inside a shared deck (`GET /api/images/<id>?share=...`). A
  *broken* token is still a 401 on these, so an expired session is not quietly
  shown a signed-out page.
- `caller_email()` — the verified address, inside a handler.

Two bugs in the old decorator are fixed on the way: it fetched Auth0's JWKS on
**every request** with no timeout, which put an Auth0 round trip in front of
every call and turned an Auth0 slowdown into an outage here. The key set is now
cached, refreshed once on an unknown `kid` for rotation, and a stale set is
served if Auth0 is unreachable rather than locking everyone out.

### Routes whose URL carries an address

`/api/words/rand/<token>`, `/api/collections/<token>` and
`/api/collections/<token>/stats` keep their shape so existing clients keep
working, but the value in the path is ignored. The caller is the token.

## Where the address comes from

An Auth0 access token carries `sub`, not `email`. Both routes to the address
are supported, in this order:

1. A namespaced custom claim, `AUTH0_EMAIL_CLAIM`, default
   `https://recallcards.net/email`. If an Auth0 action adds it there is no
   extra network call at all.
2. Otherwise one `/userinfo` call per token, cached until the token expires.

Option 2 works with no Auth0 dashboard changes, which is why it is the
fallback. Adding the claim is worth doing later: it removes a round trip on the
first call with each new token. In an Auth0 Login Action:

```js
exports.onExecutePostLogin = async (event, api) => {
  if (event.authorization) {
    api.accessToken.setCustomClaim('https://recallcards.net/email', event.user.email);
  }
};
```

## Deploy the frontend first

The order matters, and this way there is no window where anything breaks:

1. **Frontend first.** It now sends `Authorization: Bearer <token>` *and* still
   sends the old `email`/`token` parameters. The old backend keeps reading the
   parameters, so the new frontend works against it unchanged.
2. **Backend second.** It reads the token and ignores the parameters.

Deploying the backend first instead would 401 every signed-in web user until
the frontend caught up.

The iOS client needs no release. It already attached the access token on every
call, so it starts being authenticated properly the moment the backend ships.

One small thing during a frontend-first window: `POST /api/profile` no longer
sends the address, so display names do not update until the backend lands. It
is cosmetic — a recipient sees "Someone" instead of a name — and the call
already ignores its own failures.

## Pictures in the browser

A browser sends no `Authorization` header for an `<img src>`, so pointing a tag
at `/api/images/<id>` would 401 and every card picture and deck cover would
break. `src/Components/AuthedImage.jsx` fetches the bytes with the token and
hands the tag a blob URL, with a small cache because the bytes behind an id
never change. Pictures in a *shared* deck are authorised by the share id in the
URL and stay plain `<img src>`, keeping the browser's own caching.

## Local development

There is no Auth0 round trip in dev, so the frontend sends the signed-in
address in an `X-Dev-User` header and the API trusts it — but only because
`RECALLCARDS_DEV_AUTH=true` is set in `docker-compose.dev.yml`, and it refuses
to honour the header at all when `FLASK_ENV` is `production`.

**This must never be set on the server.** With it on, the old hole is open
again by design.

## Tests

```sh
pip install -r requirements.txt -r requirements-dev.txt
python -m unittest discover -p 'test_*.py'
```

41 tests, in three files:

- `test_auth.py` (22) — the verification itself. Real RSA keys, real signed
  tokens; only the two network calls are stubbed. Covers a tampered payload, a
  token signed by the wrong key, `alg=none`, the wrong audience, the wrong
  issuer, expiry, key rotation, Auth0 being unreachable, and that the dev
  bypass is off unless asked for and refuses to run in production.
- `test_api_auth.py` (7) — walks the app's own URL map, so a route added later
  is covered without touching the file: it either appears in that file's
  `PUBLIC` list with a reason, or it must answer 401 to an anonymous caller.
- `test_isolation.py` (12) — two accounts with real cards in a database, and
  what one signed-in user can do to the other's data. Reading, writing,
  editing, deleting, sharing, publishing, revoking and recording a review are
  each attempted across accounts with the victim's address in every field, and
  each one lands on the caller's own deck or not at all.
