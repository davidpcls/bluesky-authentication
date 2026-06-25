import base64
import functools
import logging
import time
from datetime import timedelta
from typing import Any, cast

import httpx
from fastapi import Request
from fastapi.security import OAuth2, OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from pydantic import Secret

from ..protocols import ExternalAuthenticator, UserSessionState
from ..utils import get_root_url

logger = logging.getLogger(__name__)


class OIDCAuthenticator(ExternalAuthenticator):
    """Authenticate users using an OpenID Connect authorization code flow."""

    configuration_schema = """
$schema": http://json-schema.org/draft-07/schema#
type: object
additionalProperties: false
properties:
  audience:
    type: string
  client_id:
    type: string
  client_secret:
    type: string
  well_known_uri:
    type: string
  confirmation_message:
    type: string
  redirect_on_success:
    type: string
  redirect_on_failure:
    type: string
"""

    def __init__(
        self,
        audience: str,
        client_id: str,
        client_secret: str,
        well_known_uri: str,
        confirmation_message: str = "",
        redirect_on_success: str | None = None,
        redirect_on_failure: str | None = None,
    ):
        self._audience = audience
        self._client_id = client_id
        self._client_secret = Secret(client_secret)
        self._well_known_url = well_known_uri
        self.confirmation_message = confirmation_message
        self.redirect_on_success = redirect_on_success
        self.redirect_on_failure = redirect_on_failure
        self._keys_cache: list[dict[str, Any]] | None = None
        self._keys_cache_expires_at = 0.0

    @functools.cached_property
    def _config_from_oidc_url(self) -> dict[str, Any]:
        response: httpx.Response = httpx.get(self._well_known_url)
        response.raise_for_status()
        return cast("dict[str, Any]", response.json())

    @functools.cached_property
    def client_id(self) -> str:
        return self._client_id

    @functools.cached_property
    def id_token_signing_alg_values_supported(self) -> list[str]:
        return cast(
            "list[str]",
            self._config_from_oidc_url.get("id_token_signing_alg_values_supported"),
        )

    @functools.cached_property
    def issuer(self) -> str:
        return cast("str", self._config_from_oidc_url.get("issuer"))

    @functools.cached_property
    def jwks_uri(self) -> str:
        return cast("str", self._config_from_oidc_url.get("jwks_uri"))

    @functools.cached_property
    def token_endpoint(self) -> str:
        return cast("str", self._config_from_oidc_url.get("token_endpoint"))

    @functools.cached_property
    def authorization_endpoint(self) -> httpx.URL:
        return httpx.URL(
            cast("str", self._config_from_oidc_url.get("authorization_endpoint"))
        )

    @functools.cached_property
    def device_authorization_endpoint(self) -> str:
        return cast(
            "str", self._config_from_oidc_url.get("device_authorization_endpoint")
        )

    @functools.cached_property
    def end_session_endpoint(self) -> str:
        return cast("str", self._config_from_oidc_url.get("end_session_endpoint"))

    def keys(self) -> list[dict[str, Any]]:
        if (
            self._keys_cache is not None
            and time.monotonic() < self._keys_cache_expires_at
        ):
            return self._keys_cache

        response = httpx.get(self.jwks_uri)
        response.raise_for_status()
        keys = cast("list[dict[str, Any]]", response.json().get("keys", []))
        self._keys_cache = keys
        self._keys_cache_expires_at = (
            time.monotonic() + timedelta(hours=1).total_seconds()
        )
        return keys

    def decode_token(
        self, id_token: str, access_token: str | None = None
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            jwt.decode(
                id_token,
                key=self.keys(),
                algorithms=self.id_token_signing_alg_values_supported,
                audience=self._audience,
                issuer=self.issuer,
                access_token=access_token,
            ),
        )

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
        )
        response_body = response.json()
        if response.is_error:
            logger.error("Authentication error: %r", response_body)
            return None
        response_body = response.json()
        id_token = response_body["id_token"]
        access_token = response_body.get("access_token")
        try:
            verified_body = self.decode_token(id_token, access_token)
        except JWTError:
            logger.exception(
                "Authentication error. Unverified token: %r",
                jwt.get_unverified_claims(id_token),
            )
            return None
        preferred_username = verified_body.get("preferred_username")
        if preferred_username and "@" in preferred_username:
            user_id = preferred_username.split("@")[0]
        elif preferred_username:
            user_id = preferred_username
        else:
            user_id = verified_body["sub"]
        logger.info(
            "OIDC authentication successful. user_id=%r (sub=%r, preferred_username=%r, email=%r, name=%r)",
            user_id,
            verified_body.get("sub"),
            verified_body.get("preferred_username"),
            verified_body.get("email"),
            verified_body.get("name"),
        )
        return UserSessionState(user_id, {})


class ProxiedOIDCAuthenticator(OIDCAuthenticator):
    """Expose OIDC bearer-token schema for authentication handled upstream."""

    configuration_schema = """
$schema": http://json-schema.org/draft-07/schema#
type: object
additionalProperties: false
properties:
  audience:
    type: string
  client_id:
    type: string
  well_known_uri:
    type: string
  scopes:
    type: array
    items:
      type: string
    description: |
      Optional list of OAuth2 scopes to request. If provided, authorization
      should be enforced by an external policy agent.
  device_flow_client_id:
    type: string
  confirmation_message:
    type: string
"""

    def __init__(
        self,
        audience: str,
        client_id: str,
        well_known_uri: str,
        device_flow_client_id: str,
        scopes: list[str] | None = None,
        confirmation_message: str = "",
    ):
        super().__init__(
            audience=audience,
            client_id=client_id,
            client_secret="",
            well_known_uri=well_known_uri,
            confirmation_message=confirmation_message,
        )
        self.scopes = scopes
        self.device_flow_client_id = device_flow_client_id
        self._oidc_bearer = OAuth2AuthorizationCodeBearer(
            authorizationUrl=str(self.authorization_endpoint),
            tokenUrl=self.token_endpoint,
        )

    @property
    def oauth2_schema(self) -> OAuth2:
        return self._oidc_bearer


async def exchange_code(
    token_uri: str,
    auth_code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    extra_scopes: list[str] | None = None,
) -> httpx.Response:
    scopes = {"openid", "offline_access"}
    if extra_scopes:
        scopes.update(extra_scopes)
    auth_value = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return httpx.post(
        url=token_uri,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": auth_code,
            "client_secret": client_secret,
            "scope": " ".join(sorted(scopes)),
        },
        headers={"Authorization": f"Basic {auth_value}"},
    )
