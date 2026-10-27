"""
MCP OAuthAuthorizationServerProvider for RecallCards.

Claude registers as a client (DCR), then authorize() sends the browser to
/connector/login, which bounces through Auth0. When Auth0 returns the user's
verified email, complete_login() mints the authorization code Claude exchanges
for tokens. The token's `subject` is the user's email -- the same identity the
REST API scopes every operation to.

Clients, codes and tokens are persisted in Mongo (oauth_store).
"""
from __future__ import annotations

import time
from typing import Any

import anyio
from pydantic import AnyHttpUrl

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from connector import oauth_store as ost


async def _to_thread(fn, *args, **kwargs):
    if kwargs:
        return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))
    return await anyio.to_thread.run_sync(fn, *args)


class RecallcardsOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    def __init__(self, public_url: str, scope: str):
        self.public_url = public_url.rstrip("/")
        self.scope = scope
        self.resource = f"{self.public_url}/mcp"
        # Under /connector/* so it never collides with the website SPA routes.
        self.login_path = f"{self.public_url}/connector/login"

    def _resource(self, value: str | None) -> str:
        return value or self.resource

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        row = await _to_thread(ost.get_client, client_id)
        return OAuthClientInformationFull.model_validate(row) if row else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        await _to_thread(ost.save_client, client_info.model_dump(mode="json"))

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        scopes = params.scopes or [self.scope]
        login_state = await _to_thread(
            ost.save_login_state,
            {
                "redirect_uri": str(params.redirect_uri),
                "code_challenge": params.code_challenge,
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "client_id": client.client_id,
                "resource": self._resource(params.resource),
                "scopes": scopes,
                "client_state": params.state,
            },
        )
        return f"{self.login_path}?state={login_state}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        doc = await _to_thread(ost.get_authorization_code, authorization_code)
        if not doc or doc.get("client_id") != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            client_id=doc["client_id"],
            redirect_uri=AnyHttpUrl(doc["redirect_uri"]),
            redirect_uri_provided_explicitly=bool(doc["redirect_uri_provided_explicitly"]),
            expires_at=float(doc["expires_at"]),
            scopes=list(doc.get("scopes") or []),
            code_challenge=doc["code_challenge"],
            resource=self._resource(doc.get("resource")),
            subject=str(doc["subject"]),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if not client.client_id:
            raise ValueError("No client_id")
        await _to_thread(ost.delete_authorization_code, authorization_code.code)
        access, refresh, expires_in = await _to_thread(
            ost.issue_tokens,
            client_id=client.client_id,
            scopes=list(authorization_code.scopes),
            subject=str(authorization_code.subject),
            resource=self._resource(authorization_code.resource),
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=expires_in,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        row = await _to_thread(ost.load_refresh_token, refresh_token)
        if not row or row.get("client_id") != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=list(row.get("scopes") or []),
            expires_at=int(row["expires_at"]),
            resource=self._resource(row.get("resource")),
            subject=str(row["subject"]),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        rotated = await _to_thread(ost.rotate_refresh, refresh_token.token)
        if not rotated:
            raise ValueError("Invalid refresh token")
        access, refresh, expires_in = rotated
        granted = scopes or list(refresh_token.scopes)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=expires_in,
            scope=" ".join(granted),
            refresh_token=refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = await _to_thread(ost.load_access_token, token)
        if not row:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=list(row.get("scopes") or []),
            expires_at=int(row["expires_at"]),
            resource=self._resource(row.get("resource")),
            subject=str(row["subject"]),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        await _to_thread(ost.revoke_by_token, token.token)

    async def complete_login(self, login_state: str, subject: str) -> str:
        """After Auth0 returns the user's email: mint the auth code and return
        the URL that sends the browser back to Claude."""
        payload = await _to_thread(ost.pop_login_state, login_state)
        if not payload:
            raise ValueError("Invalid or expired login state")

        code_doc = {
            "client_id": payload["client_id"],
            "redirect_uri": payload["redirect_uri"],
            "redirect_uri_provided_explicitly": payload["redirect_uri_provided_explicitly"],
            "expires_at": time.time() + ost.CODE_TTL_SEC,
            "scopes": payload.get("scopes") or [self.scope],
            "code_challenge": payload["code_challenge"],
            "resource": self._resource(payload.get("resource")),
            "subject": str(subject),
        }
        code = await _to_thread(ost.save_authorization_code, code_doc)
        kwargs: dict[str, Any] = {"code": code}
        if payload.get("client_state") is not None:
            kwargs["state"] = payload["client_state"]
        return construct_redirect_uri(payload["redirect_uri"], **kwargs)
