"""
RecallCards connector for Claude: an MCP server (Streamable HTTP) that lets a
signed-in user manage their flashcards from Claude.

    python -m connector.server          # listens on :8100, MCP at /mcp

Auth: OAuth 2.1 with Dynamic Client Registration. The login bounces through
Auth0 (connector/login_pages.py); the token Claude receives carries the user's
email, and every tool calls the RecallCards REST API with that user's token, so
the API does all authorization and scoping (connector/store.py).
"""
from __future__ import annotations

import os
from typing import Literal

import anyio
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token  # noqa: E402
from mcp.server.auth.settings import (  # noqa: E402
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402
from pydantic import AnyHttpUrl  # noqa: E402

from connector import login_pages  # noqa: E402
from connector import oauth_store  # noqa: E402
from connector import store  # noqa: E402
from connector.oauth_provider import RecallcardsOAuthProvider  # noqa: E402

PUBLIC_URL = os.getenv("CONNECTOR_PUBLIC_URL", "http://localhost:8100").rstrip("/")
SITE_URL = os.getenv("CONNECTOR_SITE_URL", PUBLIC_URL).rstrip("/")
SCOPE = "cards"
RESOURCE = f"{PUBLIC_URL}/mcp"

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "dev-43bumhcy.us.auth0.com")
AUTH0_AUDIENCE = os.getenv("CONNECTOR_AUTH0_AUDIENCE", "recallcards")
CLIENT_ID = os.getenv("CONNECTOR_AUTH0_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CONNECTOR_AUTH0_CLIENT_SECRET", "")

oauth_provider = RecallcardsOAuthProvider(PUBLIC_URL, SCOPE)
login_pages.configure(
    public_url=PUBLIC_URL,
    site_url=SITE_URL,
    oauth_provider=oauth_provider,
    auth0_domain=AUTH0_DOMAIN,
    auth0_audience=AUTH0_AUDIENCE,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    ost=oauth_store,
)


INSTRUCTIONS = """
Tools for the signed-in user's flashcards on RecallCards (https://recallcards.net).

A deck ("collection") holds cards; each card has a term (front) and a definition
(back). The user also has decks they follow via a share link, and a public
library of decks anyone can add.

Workflow:
1. list_collections to see the user's decks, then list_cards to read one before
   changing it.
2. Tell the user what you plan to add or change, then make the change. Only
   change what the user asked for; never invent facts for the back of a card.
3. delete_card and delete_collection are permanent -- confirm with the user first.
4. Share with share_deck (a private link) or publish_deck (the public library).
""".strip()

mcp = MCPServer(
    name="RecallCards",
    title="RecallCards",
    instructions=INSTRUCTIONS,
    website_url="https://recallcards.net",
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(PUBLIC_URL),
        resource_server_url=AnyHttpUrl(RESOURCE),
        required_scopes=[SCOPE],
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[SCOPE],
            default_scopes=[SCOPE],
        ),
        revocation_options=RevocationOptions(enabled=True),
        service_documentation_url=AnyHttpUrl(f"{SITE_URL}/"),
    ),
)


def _email() -> str:
    token = get_access_token()
    if token is None or token.subject is None:
        raise store.ConnectorError("Not signed in.")
    return str(token.subject)


async def _run(fn, *args):
    try:
        email = _email()
        return await anyio.to_thread.run_sync(lambda: fn(email, *args))
    except store.ConnectorError as e:
        raise ToolError(str(e)) from e


READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)


# --- read -----------------------------------------------------------------

@mcp.tool(annotations=READ)
async def list_collections() -> dict:
    """List the user's decks: the ones they own, the ones they follow via a link,
    which decks they have published, and which deck is the default."""
    return await _run(store.list_collections)


@mcp.tool(annotations=READ)
async def list_cards(collection: str) -> list[dict]:
    """List every card in one deck -- term, definition, and (for shared decks)
    who wrote or last edited each card."""
    return await _run(store.get_cards, collection)


@mcp.tool(annotations=READ)
async def get_progress(collection: str) -> dict:
    """Study progress for one deck: total cards, how many are known, how many need
    review, how many are unseen, and overall accuracy."""
    return await _run(store.get_progress, collection)


@mcp.tool(annotations=READ)
async def list_public_decks() -> list[dict]:
    """Browse decks other people have published to the public library; any of them
    can be added with follow_deck using its share_id."""
    return await _run(store.list_public_decks)


# --- cards ----------------------------------------------------------------

@mcp.tool(annotations=WRITE)
async def add_card(collection: str, term: str, definition: str) -> dict:
    """Add a card (or update the definition of an existing term) in a deck. If the
    deck does not exist yet it is created."""
    return await _run(store.add_card, collection, term, definition)


@mcp.tool(annotations=WRITE)
async def edit_card(collection: str, term: str, definition: str, new_term: str = "") -> dict:
    """Change a card's definition, and optionally rename its term (pass new_term)."""
    return await _run(store.edit_card, collection, term, new_term, definition)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_card(collection: str, term: str) -> dict:
    """Permanently remove one card from a deck. Confirm with the user first."""
    return await _run(store.delete_card, collection, term)


@mcp.tool(annotations=WRITE)
async def record_review(collection: str, term: str, outcome: Literal["correct", "incorrect"]) -> dict:
    """Record studying one card: 'correct' marks it known, 'incorrect' flags it for review."""
    return await _run(store.record_review, collection, term, outcome)


# --- collections ----------------------------------------------------------

@mcp.tool(annotations=WRITE)
async def create_collection(name: str) -> dict:
    """Create a new, empty deck."""
    return await _run(store.create_collection, name)


@mcp.tool(annotations=WRITE)
async def rename_collection(old_name: str, new_name: str) -> dict:
    """Rename a deck."""
    return await _run(store.rename_collection, old_name, new_name)


@mcp.tool(annotations=DESTRUCTIVE)
async def delete_collection(name: str) -> dict:
    """Permanently delete a deck and all its cards. Confirm with the user first."""
    return await _run(store.delete_collection, name)


# --- sharing --------------------------------------------------------------

@mcp.tool(annotations=WRITE)
async def share_deck(collection: str, allow_edit: bool = False) -> dict:
    """Create a share link for a deck. allow_edit lets followers add/edit its cards.
    Returns the link to give to someone."""
    return await _run(store.share_deck, collection, allow_edit)


@mcp.tool(annotations=WRITE)
async def publish_deck(collection: str, public: bool = True) -> dict:
    """List a deck in the public library (public=True) so anyone can find and add
    it, or take it back out (public=False)."""
    return await _run(store.publish_deck, collection, public)


@mcp.tool(annotations=WRITE)
async def follow_deck(share_id: str) -> dict:
    """Add a shared or published deck to the user's account by its share_id. The
    deck stays linked to its owner; the user's own study progress stays private."""
    return await _run(store.follow_deck, share_id)


# --- login routes (the Auth0 round trip) ----------------------------------

@mcp.custom_route("/connector/login", methods=["GET"])
async def route_login(request):
    return await login_pages.login_page(request)


@mcp.custom_route("/connector/oauth/done", methods=["GET"])
async def route_oauth_done(request):
    return await login_pages.oauth_done(request)


def app():
    allowed = [h.strip() for h in os.getenv(
        "CONNECTOR_ALLOWED_HOSTS", "localhost:8100,127.0.0.1:8100").split(",") if h.strip()]
    return mcp.streamable_http_app(
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed,
            allowed_origins=[f"https://{h}" for h in allowed] + [f"http://{h}" for h in allowed],
        ),
        host="0.0.0.0",
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app(), host="0.0.0.0", port=int(os.getenv("CONNECTOR_PORT", "8100")), log_level="info")
