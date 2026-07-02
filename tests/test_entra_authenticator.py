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


def test_entra_decoding_empty_scp_grants_all_mapped_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When scp claim is absent, all mapped scopes are granted."""

    def mock_decode_token(
        _self: Any, _id_token: str, _access_token: str | None = None
    ) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/example-tenant/v2.0",
            "sub": "opaque-sub",
            "preferred_username": "bob@example.org",
            # no "scp" key
        }

    monkeypatch.setattr(OIDCAuthenticator, "decode_token", mock_decode_token)

    authenticator = object.__new__(EntraAuthenticator)
    authenticator.scopes_map = {
        "scope.a": ["read:metadata"],
        "scope.b": ["write:data"],
    }
    claims = authenticator.decode_token("id-token", "access-token")

    assert set(claims["scope"].split()) == {"read:metadata", "write:data"}


def test_entra_decoding_upn_style_username_trimmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """domain\\user UPN format is trimmed to just the user part."""

    def mock_decode_token(
        _self: Any, _id_token: str, _access_token: str | None = None
    ) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/example-tenant/v2.0",
            "sub": "opaque-sub",
            "preferred_username": "DOMAIN\\charlie",
            "scp": "",
        }

    monkeypatch.setattr(OIDCAuthenticator, "decode_token", mock_decode_token)

    authenticator = object.__new__(EntraAuthenticator)
    authenticator.scopes_map = {}
    claims = authenticator.decode_token("id-token", "access-token")

    assert claims["user"] == "charlie"


def test_entra_scopes_property_returns_union_of_all_map_values() -> None:
    """scopes property returns the union of all values in scopes_map."""
    authenticator = object.__new__(EntraAuthenticator)
    authenticator.scopes_map = {
        "scope.a": ["read:metadata", "read:data"],
        "scope.b": ["write:data"],
    }
    assert set(authenticator.scopes) == {"read:metadata", "read:data", "write:data"}


def test_entra_scopes_setter_is_a_noop() -> None:
    """Setting scopes has no effect — scopes_map is the source of truth."""
    authenticator = object.__new__(EntraAuthenticator)
    authenticator.scopes_map = {"scope.a": ["read:metadata"]}
    authenticator.scopes = ["something-else"]  # setter is a no-op by design
    assert set(authenticator.scopes) == {"read:metadata"}
