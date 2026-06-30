import logging
from typing import Any

import pytest

from bluesky_authentication.authenticators import EntraAuthenticator, OIDCAuthenticator


def _make_entra(scopes_map: dict[str, list[str]] | None = None) -> EntraAuthenticator:
    """Build an EntraAuthenticator without touching the network."""
    authenticator: EntraAuthenticator = object.__new__(EntraAuthenticator)
    authenticator.scopes_map = scopes_map if scopes_map is not None else {}
    return authenticator


# ---------------------------------------------------------------------------
# decode_token — scope mapping and username extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_entra_decoding_ignores_unmapped_scopes(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown Entra scopes produce a warning; only mapped scopes are returned."""

    async def _mock_decode(
        _self: Any, _id_token: str, _access_token: str | None = None
    ) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/example-tenant/v2.0",
            "sub": "opaque-sub",
            "preferred_username": "alice@example.org",
            "scp": "known.scope unknown.scope",
        }

    monkeypatch.setattr(OIDCAuthenticator, "decode_token", _mock_decode)
    caplog.set_level(logging.WARNING)

    authenticator = _make_entra({"known.scope": ["read:metadata"]})
    claims = await authenticator.decode_token("id-token", "access-token")

    assert claims["entra_sub"] == "opaque-sub"
    assert claims["entra_username"] == "alice@example.org"
    assert claims["user"] == "alice"
    assert claims["scope"] == "read:metadata"
    assert any(
        "Unmapped Entra scope in 'scp': unknown.scope" in r.message
        for r in caplog.records
    )


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_entra_decoding_empty_scp_grants_all_mapped_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``scp`` is absent/empty, all scopes_map values are granted (fallback)."""

    async def _mock_decode(
        _self: Any, _id_token: str, _access_token: str | None = None
    ) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/tenant/v2.0",
            "sub": "sub-xyz",
            "preferred_username": "bob@example.org",
            "scp": "",  # empty string — triggers the fallback branch
        }

    monkeypatch.setattr(OIDCAuthenticator, "decode_token", _mock_decode)

    authenticator = _make_entra({"scope.a": ["read:data"], "scope.b": ["write:data"]})
    claims = await authenticator.decode_token("id-token", "access-token")

    granted = set(claims["scope"].split())
    assert granted == {"read:data", "write:data"}


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_entra_decoding_upn_style_username_trimmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UPN-style username ``DOMAIN\\user`` is trimmed to ``user``."""

    async def _mock_decode(
        _self: Any, _id_token: str, _access_token: str | None = None
    ) -> dict[str, Any]:
        return {
            "iss": "https://login.microsoftonline.com/tenant/v2.0",
            "sub": "sub-abc",
            "preferred_username": "DOMAIN\\carol",
            "scp": "",
        }

    monkeypatch.setattr(OIDCAuthenticator, "decode_token", _mock_decode)

    authenticator = _make_entra({})
    claims = await authenticator.decode_token("id-token", "access-token")

    assert claims["user"] == "carol"


# ---------------------------------------------------------------------------
# scopes property / setter
# ---------------------------------------------------------------------------


def test_entra_scopes_property_returns_union_of_all_map_values() -> None:
    """``scopes`` is the union of all lists in scopes_map."""
    authenticator = _make_entra(
        {
            "scope.read": ["read:data", "read:meta"],
            "scope.write": ["write:data", "read:data"],  # overlap intentional
        }
    )
    assert set(authenticator.scopes) == {"read:data", "read:meta", "write:data"}


def test_entra_scopes_setter_is_a_noop() -> None:
    """The scopes setter does not mutate scopes_map or raise."""
    authenticator = _make_entra({"scope.read": ["read:data"]})
    before = set(authenticator.scopes)
    authenticator.scopes = ["injected:scope"]
    assert set(authenticator.scopes) == before
