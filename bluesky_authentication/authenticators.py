import asyncio
import base64
import functools
import logging
import re
import secrets
import uuid
from collections.abc import Iterable
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional, cast

import httpx
from cachetools import TTLCache, cached
from fastapi import APIRouter, Request
from fastapi.security import OAuth2, OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from pydantic import Secret
from starlette.responses import RedirectResponse

from .protocols import ExternalAuthenticator, InternalAuthenticator, UserSessionState
from .utils import get_root_url, modules_available

logger = logging.getLogger(__name__)


class DummyAuthenticator(InternalAuthenticator):
    """
    For test and demo purposes only!

    Accept any username and any password.

    """

    def __init__(self, confirmation_message: str = ""):
        self.confirmation_message = confirmation_message

    async def authenticate(self, username: str, password: str) -> UserSessionState:
        return UserSessionState(username, {})


class DictionaryAuthenticator(InternalAuthenticator):
    """
    For test and demo purposes only!

    Check passwords from a dictionary of usernames mapped to passwords.
    """

    configuration_schema = """
$schema": http://json-schema.org/draft-07/schema#
type: object
additionalProperties: false
properties:
  users_to_password:
    type: object
    description: |
      Mapping usernames to password. Environment variable expansion should be
      used to avoid placing passwords directly in configuration.
  confirmation_message:
    type: string
    description: May be displayed by client after successful login.
"""

    def __init__(
        self, users_to_passwords: Mapping[str, str], confirmation_message: str = ""
    ):
        self._users_to_passwords = users_to_passwords
        self.confirmation_message = confirmation_message

    async def authenticate(
        self, username: str, password: str
    ) -> Optional[UserSessionState]:
        true_password = self._users_to_passwords.get(username)
        if not true_password:
            return
        if secrets.compare_digest(true_password, password):
            return UserSessionState(username, {})


class PAMAuthenticator(InternalAuthenticator):
    configuration_schema = """
$schema": http://json-schema.org/draft-07/schema#
type: object
additionalProperties: false
properties:
  service:
    type: string
    description: PAM service. Default is 'login'.
  confirmation_message:
    type: string
    description: May be displayed by client after successful login.
"""

    def __init__(self, service: str = "login", confirmation_message: str = ""):
        if not modules_available("pamela"):
            raise ModuleNotFoundError(
                "This PAMAuthenticator requires the module 'pamela' to be installed."
            )
        self.service = service
        self.confirmation_message = confirmation_message

    async def authenticate(
        self, username: str, password: str
    ) -> Optional[UserSessionState]:
        import pamela

        try:
            pamela.authenticate(username, password, service=self.service)
            return UserSessionState(username, {})
        except pamela.PAMError:
            return


class OIDCAuthenticator(ExternalAuthenticator):
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
        redirect_on_success: Optional[str] = None,
        redirect_on_failure: Optional[str] = None,
    ):
        self._audience = audience
        self._client_id = client_id
        self._client_secret = Secret(client_secret)
        self._well_known_url = well_known_uri
        self.confirmation_message = confirmation_message
        self.redirect_on_success = redirect_on_success
        self.redirect_on_failure = redirect_on_failure

    @functools.cached_property
    def _config_from_oidc_url(self) -> dict[str, Any]:
        response: httpx.Response = httpx.get(self._well_known_url)
        response.raise_for_status()
        return response.json()

    @functools.cached_property
    def client_id(self) -> str:
        return self._client_id

    @functools.cached_property
    def id_token_signing_alg_values_supported(self) -> list[str]:
        return cast(
            list[str],
            self._config_from_oidc_url.get("id_token_signing_alg_values_supported"),
        )

    @functools.cached_property
    def issuer(self) -> str:
        return cast(str, self._config_from_oidc_url.get("issuer"))

    @functools.cached_property
    def jwks_uri(self) -> str:
        return cast(str, self._config_from_oidc_url.get("jwks_uri"))

    @functools.cached_property
    def token_endpoint(self) -> str:
        return cast(str, self._config_from_oidc_url.get("token_endpoint"))

    @functools.cached_property
    def authorization_endpoint(self) -> httpx.URL:
        return httpx.URL(
            cast(str, self._config_from_oidc_url.get("authorization_endpoint"))
        )

    @functools.cached_property
    def device_authorization_endpoint(self) -> str:
        return cast(
            str, self._config_from_oidc_url.get("device_authorization_endpoint")
        )

    @functools.cached_property
    def end_session_endpoint(self) -> str:
        return cast(str, self._config_from_oidc_url.get("end_session_endpoint"))

    @cached(TTLCache(maxsize=1, ttl=timedelta(hours=1).total_seconds()))
    def keys(self) -> List[str]:
        return httpx.get(self.jwks_uri).raise_for_status().json().get("keys", [])

    def decode_token(
        self, id_token: str, access_token: Optional[str] = None
    ) -> dict[str, Any]:
        return jwt.decode(
            id_token,
            key=self.keys(),
            algorithms=self.id_token_signing_alg_values_supported,
            audience=self._audience,
            issuer=self.issuer,
            access_token=access_token,
        )

    async def authenticate(self, request: Request) -> Optional[UserSessionState]:
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
        scopes: Optional[List[str]] = None,
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


class EntraAuthenticator(ProxiedOIDCAuthenticator):
    def __init__(
        self,
        audience: str,
        client_id: str,
        well_known_uri: str,
        device_flow_client_id: str,
        extra_scopes: Optional[List[str]] = None,
        confirmation_message: str = "",
        scopes_map: Optional[Dict[str, list[str]]] = None,
        client_secret: str = "",
        redirect_on_success: Optional[str] = None,
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
        def scopes(self):
            mapped = set()
            for tiled_scopes in self.scopes_map.values():
                mapped.update(tiled_scopes)
            return list(mapped)

        @scopes.setter
        def scopes(self, value):
            pass

    def decode_token(
        self, id_token: str, access_token: Optional[str] = None
    ) -> dict[str, Any]:
        claims = super().decode_token(id_token, access_token)
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

    async def authenticate(self, request: Request) -> Optional[UserSessionState]:
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
            verified_body = self.decode_token(id_token, access_token)
        except JWTError:
            logger.exception(
                "Authentication error. Unverified token: %r",
                jwt.get_unverified_claims(id_token),
            )
            return None
        username = verified_body.get("user") or verified_body["sub"]
        state: dict = {}
        if access_token:
            state["entra_access_token"] = access_token
        if refresh_token:
            state["entra_refresh_token"] = refresh_token
        return UserSessionState(username, state)


async def exchange_code(
    token_uri: str,
    auth_code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    extra_scopes: Optional[List[str]] = None,
) -> httpx.Response:
    scopes = {"openid", "offline_access"}
    if extra_scopes:
        scopes.update(extra_scopes)
    auth_value = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    response = httpx.post(
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
    return response


class SAMLAuthenticator(ExternalAuthenticator):
    def __init__(
        self,
        saml_settings,
        attribute_name: str,
        confirmation_message: str = "",
    ):
        self.saml_settings = saml_settings
        self.attribute_name = attribute_name
        self.confirmation_message = confirmation_message
        self.authorization_endpoint = "/login"

        router = APIRouter()

        if not modules_available("onelogin"):
            raise ModuleNotFoundError(
                "This SAMLAuthenticator requires 'python3-saml' to be installed."
            )

        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        @router.get("/login")
        async def saml_login(request: Request) -> RedirectResponse:
            req = await prepare_saml_from_fastapi_request(request)
            auth = OneLogin_Saml2_Auth(req, self.saml_settings)
            callback_url = auth.login()
            return RedirectResponse(url=callback_url)

        self.include_routers = [router]

    async def authenticate(self, request: Request) -> Optional[UserSessionState]:
        if not modules_available("onelogin"):
            raise ModuleNotFoundError(
                "This SAMLAuthenticator requires the module 'oneline' to be installed."
            )
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        req = await prepare_saml_from_fastapi_request(request)
        auth = OneLogin_Saml2_Auth(req, self.saml_settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise Exception(
                "Error when processing SAML Response: %s %s"
                % (", ".join(errors), auth.get_last_error_reason())
            )
        if auth.is_authenticated():
            attribute_as_list = auth.get_attributes()[self.attribute_name]
            assert len(attribute_as_list) == 1
            return UserSessionState(attribute_as_list[0], {})
        else:
            return None


async def prepare_saml_from_fastapi_request(request: Request) -> Mapping[str, str]:
    form_data = await request.form()
    rv = {
        "http_host": request.client.host,
        "server_port": request.url.port,
        "script_name": request.url.path,
        "post_data": {},
        "get_data": {},
    }
    if request.query_params:
        rv["get_data"] = (request.query_params,)
    if "SAMLResponse" in form_data:
        SAMLResponse = form_data["SAMLResponse"]
        rv["post_data"]["SAMLResponse"] = SAMLResponse
    if "RelayState" in form_data:
        RelayState = form_data["RelayState"]
        rv["post_data"]["RelayState"] = RelayState
    return rv


class LDAPAuthenticator(InternalAuthenticator):
    def __init__(
        self,
        server_address,
        server_port=None,
        *,
        use_ssl=False,
        use_tls=True,
        connect_timeout=5,
        receive_timeout=60,
        bind_dn_template=None,
        allowed_groups=None,
        valid_username_regex=r"^[a-z][.a-z0-9_-]*$",
        lookup_dn=False,
        user_search_base=None,
        user_attribute=None,
        lookup_dn_search_filter="({login_attr}={login})",
        lookup_dn_search_user=None,
        lookup_dn_search_password=None,
        lookup_dn_user_dn_attribute=None,
        escape_userdn=False,
        search_filter="",
        attributes=None,
        auth_state_attributes=None,
        use_lookup_dn_username=True,
        confirmation_message="",
    ):
        self.use_ssl = use_ssl
        self.use_tls = use_tls
        self.connect_timeout = connect_timeout
        self.receive_timeout = receive_timeout
        self.bind_dn_template = bind_dn_template
        self.allowed_groups = allowed_groups
        self.valid_username_regex = valid_username_regex
        self.lookup_dn = lookup_dn
        self.user_search_base = user_search_base
        self.user_attribute = user_attribute
        self.lookup_dn_search_filter = lookup_dn_search_filter
        self.lookup_dn_search_user = lookup_dn_search_user
        self.lookup_dn_search_password = lookup_dn_search_password
        self.lookup_dn_user_dn_attribute = lookup_dn_user_dn_attribute
        self.escape_userdn = escape_userdn
        self.search_filter = search_filter
        self.attributes = attributes if attributes else []
        self.auth_state_attributes = (
            auth_state_attributes if auth_state_attributes else []
        )
        self.use_lookup_dn_username = use_lookup_dn_username

        if isinstance(server_address, str):
            server_address_list = [server_address]
        elif isinstance(server_address, Iterable):
            server_address_list = list(server_address)
        else:
            raise TypeError(
                f"Unsupported type of `server_address` (list): server_address={server_address} "
                f"type(server_address)={type(server_address)}"
            )
        if not server_address_list:
            raise ValueError(
                "No servers are specified: 'server_address' is an empty list"
            )

        self.server_address_list = server_address_list
        self.server_port = (
            server_port if server_port is not None else self._server_port_default()
        )
        self.confirmation_message = confirmation_message

    def _server_port_default(self):
        if self.use_ssl:
            return 636
        else:
            return 389

    async def resolve_username(self, username_supplied_by_user):
        import ldap3

        search_dn = self.lookup_dn_search_user
        if self.escape_userdn:
            search_dn = ldap3.utils.conv.escape_filter_chars(search_dn)
        conn = await asyncio.get_running_loop().run_in_executor(
            None, self.get_connection, search_dn, self.lookup_dn_search_password
        )
        is_bound = await asyncio.get_running_loop().run_in_executor(None, conn.bind)
        if not is_bound:
            msg = "Failed to connect to LDAP server with search user '{search_dn}'"
            logger.warning(msg.format(search_dn=search_dn))
            return (None, None)

        search_filter = self.lookup_dn_search_filter.format(
            login_attr=self.user_attribute, login=username_supplied_by_user
        )

        search_func = functools.partial(
            conn.search,
            search_base=self.user_search_base,
            search_scope=ldap3.SUBTREE,
            search_filter=search_filter,
            attributes=[self.lookup_dn_user_dn_attribute],
        )
        await asyncio.get_running_loop().run_in_executor(None, search_func)

        response = conn.response
        if len(response) == 0 or "attributes" not in response[0].keys():
            msg = (
                "No entry found for user '{username}' "
                "when looking up attribute '{attribute}'"
            )
            logger.warning(
                msg.format(
                    username=username_supplied_by_user, attribute=self.user_attribute
                )
            )
            return (None, None)

        user_dn = response[0]["attributes"][self.lookup_dn_user_dn_attribute]
        if isinstance(user_dn, list):
            if len(user_dn) == 0:
                return (None, None)
            elif len(user_dn) == 1:
                user_dn = user_dn[0]
            else:
                user_dn = user_dn[0]

        return (user_dn, response[0]["dn"])

    def get_connection(self, userdn, password):
        import ldap3

        server_pool = ldap3.ServerPool(None, ldap3.RANDOM, active=False)
        for address in self.server_address_list:
            if re.search(r".+:\d+", address):
                address_split = address.split(":")
                server_addr = ":".join(address_split[:-1])
                server_port = int(address_split[-1])
            else:
                server_addr = address
                server_port = self.server_port

            server = ldap3.Server(
                server_addr,
                port=server_port,
                use_ssl=self.use_ssl,
                connect_timeout=self.connect_timeout,
            )
            server_pool.add(server)

        auto_bind_no_ssl = (
            ldap3.AUTO_BIND_TLS_BEFORE_BIND if self.use_tls else ldap3.AUTO_BIND_NO_TLS
        )
        auto_bind = ldap3.AUTO_BIND_NO_TLS if self.use_ssl else auto_bind_no_ssl
        conn = ldap3.Connection(
            server_pool,
            user=userdn,
            password=password,
            auto_bind=auto_bind,
            receive_timeout=self.receive_timeout,
        )
        return conn

    async def get_user_attributes(self, conn, userdn):
        attrs = {}
        if self.auth_state_attributes:
            search_func = functools.partial(
                conn.search,
                userdn,
                "(objectClass=*)",
                attributes=self.auth_state_attributes,
            )
            found = await asyncio.get_running_loop().run_in_executor(None, search_func)
            if found:
                attrs = conn.entries[0].entry_attributes_as_dict
        return attrs

    async def authenticate(
        self, username: str, password: str
    ) -> Optional[UserSessionState]:
        import ldap3

        username_saved = username

        if not re.match(self.valid_username_regex, username):
            logger.warning(
                "username:%s Illegal characters in username, must match regex %s",
                username,
                self.valid_username_regex,
            )
            return None

        if password is None or password.strip() == "":
            logger.warning("username:%s Login denied for blank password", username)
            return None

        bind_dn_template = self.bind_dn_template
        if isinstance(bind_dn_template, str):
            bind_dn_template = [bind_dn_template]

        if not self.lookup_dn and not bind_dn_template:
            logger.warning(
                "Login not allowed, please configure 'lookup_dn' or 'bind_dn_template'."
            )
            return None

        if self.lookup_dn:
            username, resolved_dn = await self.resolve_username(username)
            if not username:
                return None
            if str(self.lookup_dn_user_dn_attribute).upper() == "CN":
                username = re.subn(r"([^\\]),", r"\1\,", username)[0]
            if not bind_dn_template:
                bind_dn_template = [resolved_dn]

        is_bound = False
        for dn in bind_dn_template:
            if not dn:
                logger.warning("Ignoring blank 'bind_dn_template' entry!")
                continue
            userdn = dn.format(username=username)
            if self.escape_userdn:
                userdn = ldap3.utils.conv.escape_filter_chars(userdn)
            try:
                conn = await asyncio.get_running_loop().run_in_executor(
                    None, self.get_connection, userdn, password
                )
            except ldap3.core.exceptions.LDAPBindError:
                is_bound = False
            else:
                if conn.bound:
                    is_bound = True
                else:
                    is_bound = await asyncio.get_running_loop().run_in_executor(
                        None, conn.bind
                    )

            if is_bound:
                break

        if not is_bound:
            msg = "Invalid password for user '{username}'"
            logger.warning(msg.format(username=username))
            return None

        if self.search_filter:
            search_filter = self.search_filter.format(
                userattr=self.user_attribute, username=username
            )

            search_func = functools.partial(
                conn.search,
                search_base=self.user_search_base,
                search_scope=ldap3.SUBTREE,
                search_filter=search_filter,
                attributes=self.attributes,
            )
            await asyncio.get_running_loop().run_in_executor(None, search_func)

            n_users = len(conn.response)
            if n_users == 0:
                msg = "User with '{userattr}={username}' not found in directory"
                logger.warning(
                    msg.format(userattr=self.user_attribute, username=username)
                )
                return None
            if n_users > 1:
                msg = (
                    "Duplicate users found! "
                    "{n_users} users found with '{userattr}={username}'"
                )
                logger.warning(
                    msg.format(
                        userattr=self.user_attribute, username=username, n_users=n_users
                    )
                )
                return None

        if self.allowed_groups:
            found = False
            for group in self.allowed_groups:
                group_filter = (
                    "(|"
                    "(member={userdn})"
                    "(uniqueMember={userdn})"
                    "(memberUid={uid})"
                    ")"
                )
                group_filter = group_filter.format(userdn=userdn, uid=username)
                group_attributes = ["member", "uniqueMember", "memberUid"]

                search_func = functools.partial(
                    conn.search,
                    group,
                    search_scope=ldap3.BASE,
                    search_filter=group_filter,
                    attributes=group_attributes,
                )
                found = await asyncio.get_running_loop().run_in_executor(
                    None, search_func
                )
                if found:
                    break

            if not found:
                msg = "username:{username} User not in any of the allowed groups"
                logger.warning(msg.format(username=username))
                return None

        if not self.use_lookup_dn_username:
            username = username_saved

        user_info = await self.get_user_attributes(conn, userdn)
        if user_info:
            logger.debug("username:%s attributes:%s", username, user_info)
            return UserSessionState(username, user_info)
        return UserSessionState(username, {})
