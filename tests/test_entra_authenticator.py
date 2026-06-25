import logging
from typing import Any

import pytest

from bluesky_authentication.authenticators import EntraAuthenticator, OIDCAuthenticator


def test_entra_decoding_ignores_unmapped_scopes(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mock_decode_token(
        _self: Any, _id_token: str, _access_token: str | None = None
    ) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/example-tenant/v2.0",
            "sub": "opaque-sub",
            "preferred_username": "alice@example.org",
            "scp": "known.scope unknown.scope",
        }

    monkeypatch.setattr(OIDCAuthenticator, "decode_token", mock_decode_token)
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
