import logging
import uuid
from typing import Any

from fastapi import Request
from jose import JWTError, jwt
from pydantic import Secret

from ..protocols import UserSessionState
from ..utils import get_root_url
from .oidc import ProxiedOIDCAuthenticator, exchange_code

logger = logging.getLogger(__name__)


class EntraAuthenticator(ProxiedOIDCAuthenticator):
    """OIDC authenticator tailored for Microsoft Entra claims and scopes."""

    def __init__(
        self,
        audience: str,
        client_id: str,
        well_known_uri: str,
        device_flow_client_id: str,
        extra_scopes: list[str] | None = None,
        confirmation_message: str = "",
        scopes_map: dict[str, list[str]] | None = None,
        client_secret: str = "",
        redirect_on_success: str | None = None,
    ):
        self.scopes_map = scopes_map if scopes_map is not None else {}
        self.extra_scopes = extra_scopes or []
        super().__init__(
            audience,
            client_id,
            well_known_uri,
            device_flow_client_id,
            scopes=None,
            confirmation_message=confirmation_message,
        )
        if client_secret:
            self._client_secret = Secret(client_secret)
        self.redirect_on_success = redirect_on_success

    @property
    def scopes(self) -> list[str]:
        mapped: set[str] = set()
        for tiled_scopes in self.scopes_map.values():
            mapped.update(tiled_scopes)
        return list(mapped)

    @scopes.setter
    def scopes(self, _value: list[str] | None) -> None:
        # Scope mapping is configured through `scopes_map`.
        return None

    async def decode_token(
        self, id_token: str, access_token: str | None = None
    ) -> dict[str, Any]:
        claims = await super().decode_token(id_token, access_token)
        original_sub = claims.get("sub")
        issuer = claims.get("iss", "")
        claims["sub"] = uuid.uuid5(uuid.NAMESPACE_URL, f"{issuer}|{original_sub}").hex
        claims["entra_sub"] = original_sub

        claims["entra_username"] = (
            claims.get("nameID")
            or claims.get("preferred_username")
            or claims.get("upn")
            or claims.get("email")
        )

        if user := claims.get("entra_username"):
            user = user.strip()
            if "\\" in user:
                user = user.rsplit("\\", 1)[-1]
            elif "@" in user:
                user = user.split("@", 1)[0]
        else:
            user = original_sub
            logger.warning(
                "EntraAuthenticator: no human-readable username claim found in token "
                "(checked nameID, preferred_username, upn, email). "
                "Falling back to Entra sub=%r.",
                original_sub,
            )
        claims["user"] = user

        scp_raw = claims.get("scp", "")
        tiled_scope_set = set()
        if scp_raw:
            for scope in scp_raw.split(" "):
                mapped_scopes = self.scopes_map.get(scope)
                if mapped_scopes is None:
                    logger.warning("Unmapped Entra scope in 'scp': %s", scope)
                    continue
                tiled_scope_set.update(mapped_scopes)
        else:
            for mapped_scopes in self.scopes_map.values():
                tiled_scope_set.update(mapped_scopes)
        claims["scope"] = " ".join(tiled_scope_set)

        return claims

    async def authenticate(self, request: Request) -> UserSessionState | None:
        code = request.query_params.get("code")
        if not code:
            logger.warning(
                "Authentication failed: No authorization code parameter provided."
            )
            return None
        redirect_uri = f"{get_root_url(request)}{request.url.path}"
        response = await exchange_code(
            self.token_endpoint,
            code,
            self._client_id,
            self._client_secret.get_secret_value(),
            redirect_uri,
            extra_scopes=self.extra_scopes,
        )
        response_body = response.json()
        if response.is_error:
            logger.error("Authentication error: %r", response_body)
            return None
        id_token = response_body["id_token"]
        access_token = response_body.get("access_token")
        refresh_token = response_body.get("refresh_token")
        try:
            verified_body = await self.decode_token(id_token, access_token)
        except JWTError:
            logger.exception(
                "Authentication error. Unverified token: %r",
                jwt.get_unverified_claims(id_token),
            )
            return None
        username = verified_body.get("user") or verified_body["sub"]
        state: dict[str, str] = {}
        if access_token:
            state["entra_access_token"] = access_token
        if refresh_token:
            state["entra_refresh_token"] = refresh_token
        return UserSessionState(username, state)
