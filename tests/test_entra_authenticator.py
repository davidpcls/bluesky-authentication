import logging
from typing import Any

import pytest

from bluesky_authentication.authenticators import EntraAuthenticator, OIDCAuthenticator


def test_entra_decoding_ignores_unmapped_scopes(caplog: pytest.LogCaptureFixture) -> None:
    def mock_decode_token(self, id_token: str, access_token: str) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/example-tenant/v2.0",
            "sub": "opaque-sub",
            "preferred_username": "alice@example.org",
            "scp": "known.scope unknown.scope",
        }

    original_decode_token = OIDCAuthenticator.decode_token
    OIDCAuthenticator.decode_token = mock_decode_token  # type: ignore[method-assign]
    try:
        caplog.set_level(logging.WARNING)

        authenticator = object.__new__(EntraAuthenticator)
        authenticator.scopes_map = {"known.scope": ["read:metadata"]}
        claims = authenticator.decode_token("id-token", "access-token")

        assert claims["entra_sub"] == "opaque-sub"
        assert claims["entra_username"] == "alice@example.org"
        assert claims["user"] == "alice"
        assert claims["scope"] == "read:metadata"
        assert any(
            "Unmapped Entra scope in 'scp': unknown.scope" in record.message
            for record in caplog.records
        )
    finally:
        OIDCAuthenticator.decode_token = original_decode_token
