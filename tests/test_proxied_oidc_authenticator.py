from typing import Any

import httpx
import pytest
from respx import MockRouter

from bluesky_authentication.authenticators import ProxiedOIDCAuthenticator


@pytest.mark.asyncio
async def test_proxied_oidc_token_retrieval(
    well_known_url: str,
    well_known_response: dict[str, Any],
    mock_oidc_server: MockRouter,
) -> None:
    authenticator = ProxiedOIDCAuthenticator(
        "tiled", "tiled", well_known_url, device_flow_client_id="tiled-cli"
    )
    test_request = httpx.Request(
        "GET", "http://example.com", headers={"Authorization": "bearer FOO"}
    )

    assert authenticator.token_endpoint == well_known_response["token_endpoint"]
    assert "FOO" == await authenticator.oauth2_schema(test_request)
