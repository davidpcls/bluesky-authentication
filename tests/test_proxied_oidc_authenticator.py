from typing import Any

import httpx
import pytest

from bluesky_authentication.authenticators import ProxiedOIDCAuthenticator


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
@pytest.mark.usefixtures("mock_oidc_server")  # type: ignore[untyped-decorator]
async def test_proxied_oidc_token_retrieval(
    well_known_url: str,
    well_known_response: dict[str, Any],
) -> None:
    """token_endpoint resolves from discovery doc; oauth2_schema extracts bearer."""
    authenticator = ProxiedOIDCAuthenticator(
        "tiled", "tiled", well_known_url, device_flow_client_id="tiled-cli"
    )
    test_request = httpx.Request(
        "GET", "http://example.com", headers={"Authorization": "bearer FOO"}
    )

    assert authenticator.token_endpoint == well_known_response["token_endpoint"]
    assert await authenticator.oauth2_schema(test_request) == "FOO"


@pytest.mark.usefixtures("mock_oidc_server")  # type: ignore[untyped-decorator]
def test_proxied_oidc_inherits_device_flow_client_id(
    well_known_url: str,
) -> None:
    """device_flow_client_id passed at construction is stored on the instance."""
    authenticator = ProxiedOIDCAuthenticator(
        "aud", "cid", well_known_url, device_flow_client_id="my-device-client"
    )
    assert authenticator.device_flow_client_id == "my-device-client"


@pytest.mark.usefixtures("mock_oidc_server")  # type: ignore[untyped-decorator]
def test_proxied_oidc_scopes_attribute_set_on_construction(
    well_known_url: str,
) -> None:
    """Custom scopes list passed at construction is stored as-is."""
    scopes = ["openid", "profile", "email"]
    authenticator = ProxiedOIDCAuthenticator(
        "aud",
        "cid",
        well_known_url,
        device_flow_client_id="cli",
        scopes=scopes,
    )
    assert authenticator.scopes == scopes


@pytest.mark.usefixtures("mock_oidc_server")  # type: ignore[untyped-decorator]
def test_proxied_oidc_scopes_defaults_to_none(
    well_known_url: str,
) -> None:
    """When no scopes are provided, the attribute defaults to None."""
    authenticator = ProxiedOIDCAuthenticator(
        "aud", "cid", well_known_url, device_flow_client_id="cli"
    )
    assert authenticator.scopes is None
