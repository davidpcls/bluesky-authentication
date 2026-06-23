import asyncio
import os

import pytest

from bluesky_authentication.authenticators import LDAPAuthenticator

# Set this if there is an LDAP container running for testing.
TEST_LDAP = os.getenv("TILED_TEST_LDAP")


# fmt: off
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("ldap_server_address, ldap_server_port", [
    ("localhost", 1389),
    ("localhost:1389", 904),
    ("localhost:1389", None),
    ("127.0.0.1", 1389),
    ("127.0.0.1:1389", 904),
    (["localhost"], 1389),
    (["localhost", "127.0.0.1"], 1389),
    (["localhost", "127.0.0.1:1389"], 1389),
    (["localhost:1389", "127.0.0.1:1389"], None),
])
# fmt: on
@pytest.mark.parametrize("use_tls,use_ssl", [(False, False)])
def test_ldap_authenticator_basic(
    use_tls: bool,
    use_ssl: bool,
    ldap_server_address: str | list[str],
    ldap_server_port: int | None,
) -> None:
    if not TEST_LDAP:
        pytest.skip("Run an LDAP container and set TILED_TEST_LDAP to run")

    authenticator = LDAPAuthenticator(
        ldap_server_address,
        ldap_server_port,
        bind_dn_template="cn={username},ou=users,dc=example,dc=org",
        use_tls=use_tls,
        use_ssl=use_ssl,
    )

    async def testing() -> None:
        assert (await authenticator.authenticate("user01", "password1")).user_name == "user01"  # type: ignore[union-attr]
        assert (await authenticator.authenticate("user02", "password2")).user_name == "user02"  # type: ignore[union-attr]
        assert (await authenticator.authenticate("user02a", "password2")) is None
        assert (await authenticator.authenticate("user02", "password2a")) is None

    asyncio.run(testing())
