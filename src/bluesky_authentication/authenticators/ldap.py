import asyncio
import functools
import importlib
import logging
import re
from collections.abc import Iterable
from typing import Any

from ..protocols import InternalAuthenticator, UserSessionState

logger = logging.getLogger(__name__)


class LDAPAuthenticator(InternalAuthenticator):
    def __init__(
        self,
        server_address: str | Iterable[str],
        server_port: int | None = None,
        *,
        use_ssl: bool = False,
        use_tls: bool = True,
        connect_timeout: int = 5,
        receive_timeout: int = 60,
        bind_dn_template: str | list[str] | None = None,
        allowed_groups: list[str] | None = None,
        valid_username_regex: str = r"^[a-z][.a-z0-9_-]*$",
        lookup_dn: bool = False,
        user_search_base: str | None = None,
        user_attribute: str | None = None,
        lookup_dn_search_filter: str = "({login_attr}={login})",
        lookup_dn_search_user: str | None = None,
        lookup_dn_search_password: str | None = None,
        lookup_dn_user_dn_attribute: str | None = None,
        escape_userdn: bool = False,
        search_filter: str = "",
        attributes: list[str] | None = None,
        auth_state_attributes: list[str] | None = None,
        use_lookup_dn_username: bool = True,
        confirmation_message: str = "",
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
        self.attributes = attributes or []
        self.auth_state_attributes = auth_state_attributes or []
        self.use_lookup_dn_username = use_lookup_dn_username

        if isinstance(server_address, str):
            server_address_list = [server_address]
        else:
            server_address_list = list(server_address)
        if not server_address_list:
            msg = "No servers are specified: 'server_address' is an empty list"
            raise ValueError(msg)

        self.server_address_list = server_address_list
        self.server_port = (
            server_port if server_port is not None else self._server_port_default()
        )
        self.confirmation_message = confirmation_message

    def _server_port_default(self) -> int:
        if self.use_ssl:
            return 636
        return 389

    @staticmethod
    def _load_ldap3() -> Any:
        return importlib.import_module("ldap3")

    async def resolve_username(
        self, username_supplied_by_user: str
    ) -> tuple[str | None, str | None]:
        ldap3 = self._load_ldap3()

        search_dn = self.lookup_dn_search_user or ""
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
        if len(response) == 0 or "attributes" not in response[0]:
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
            user_dn = user_dn[0]

        return (user_dn, response[0]["dn"])

    def get_connection(self, userdn: str, password: str | None) -> Any:
        ldap3 = self._load_ldap3()

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
        return ldap3.Connection(
            server_pool,
            user=userdn,
            password=password,
            auto_bind=auto_bind,
            receive_timeout=self.receive_timeout,
        )

    async def get_user_attributes(self, conn: Any, userdn: str) -> dict[str, Any]:
        attrs: dict[str, Any] = {}
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
        self, username: str, password: str | None
    ) -> UserSessionState | None:
        ldap3 = self._load_ldap3()

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

        bind_dn_template: str | list[str] | None = self.bind_dn_template
        if isinstance(bind_dn_template, str):
            bind_dn_template = [bind_dn_template]

        if not self.lookup_dn and not bind_dn_template:
            logger.warning(
                "Login not allowed, please configure 'lookup_dn' or 'bind_dn_template'."
            )
            return None

        if self.lookup_dn:
            resolved_username, resolved_dn = await self.resolve_username(username)
            if not resolved_username:
                return None
            username = resolved_username
            if str(self.lookup_dn_user_dn_attribute).upper() == "CN":
                username = re.subn(r"([^\\]),", r"\1\\,", username)[0]
            if not bind_dn_template:
                if resolved_dn is None:
                    return None
                bind_dn_template = [resolved_dn]

        if bind_dn_template is None:
            return None

        is_bound = False
        userdn = ""
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
                    "(|(member={userdn})(uniqueMember={userdn})(memberUid={uid}))"
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
