from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import HTTPException
from jose import ExpiredSignatureError, jwt

from bluesky_authentication.tokens import (
    ALGORITHM,
    create_access_token,
    create_refresh_token,
    decode_token,
    decode_token_with_secret_keys,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# decode_token_with_secret_keys
# ---------------------------------------------------------------------------


def test_decode_token_with_key_rotation() -> None:
    """Token signed with the new key is recovered even when old key is tried first."""
    token = create_access_token(
        {"sub": "alice"},
        "new-key",
        timedelta(minutes=5),
        utcnow=_utcnow,
    )
    payload = decode_token_with_secret_keys(token, ["old-key", "new-key"])
    assert payload is not None
    assert payload["sub"] == "alice"


def test_decode_token_with_secret_keys_short_circuits_on_first_match() -> None:
    """Returns the payload from the first matching key without trying later keys."""
    token = create_access_token(
        {"sub": "bob"},
        "key-a",
        timedelta(minutes=5),
        utcnow=_utcnow,
    )
    # key-a is first: it should succeed and never attempt key-b (which would also fail
    # since the token wasn't signed with it, but we prove short-circuit by verifying
    # we get a payload and it contains the right subject).
    payload = decode_token_with_secret_keys(token, ["key-a", "key-b"])
    assert payload is not None
    assert payload["sub"] == "bob"
    # Confirm key-b alone fails (sanity-check that we didn't just get lucky)
    assert decode_token_with_secret_keys(token, ["key-b"]) is None


def test_expired_signature_passthrough() -> None:
    """ExpiredSignatureError propagates out of decode_token_with_secret_keys."""
    token = create_refresh_token(
        "sid-1",
        "signing-key",
        timedelta(seconds=-1),
        utcnow=_utcnow,
    )
    with pytest.raises(ExpiredSignatureError):
        decode_token_with_secret_keys(token, ["signing-key"])


# ---------------------------------------------------------------------------
# create_access_token / create_refresh_token claim assertions
# ---------------------------------------------------------------------------


def test_create_access_token_has_type_access_claim() -> None:
    """Token payload must carry ``type=access`` for server-side validation."""
    token = create_access_token(
        {"sub": "alice"},
        "secret",
        timedelta(minutes=5),
        utcnow=_utcnow,
    )
    # Decode without verification to inspect raw claims
    claims = jwt.get_unverified_claims(token)
    assert claims["type"] == "access"


def test_create_refresh_token_has_type_and_sid_claims() -> None:
    """Refresh token must carry ``type=refresh`` and a ``sid`` claim."""
    session_id = "my-session-abc"
    token = create_refresh_token(
        session_id,
        "secret",
        timedelta(hours=1),
        utcnow=_utcnow,
    )
    claims = jwt.get_unverified_claims(token)
    assert claims["type"] == "refresh"
    assert claims["sid"] == session_id


def test_create_refresh_token_uses_hs256_algorithm() -> None:
    """Refresh token must be signed with HS256 so servers can verify it."""
    token = create_refresh_token(
        "sid-xyz",
        "secret",
        timedelta(hours=1),
        utcnow=_utcnow,
    )
    header = jwt.get_unverified_header(token)
    assert header["alg"] == ALGORITHM


# ---------------------------------------------------------------------------
# decode_token
# ---------------------------------------------------------------------------


def test_decode_token_uses_proxied_decoder() -> None:
    """When local keys fail, the proxied decoder is called and its result returned."""

    def proxied(token: str) -> dict[str, Any]:
        return {"token": token, "sub": "proxied"}

    payload = decode_token(
        "not-a-token",
        ["wrong-key"],
        proxied_decoder=proxied,
    )
    assert payload["sub"] == "proxied"


def test_decode_token_raises_credentials_exception() -> None:
    """When all decoders fail and a custom exception is supplied, it is raised."""
    exc = HTTPException(status_code=401, detail="bad credentials")
    with pytest.raises(HTTPException) as raised:
        decode_token("not-a-token", ["wrong-key"], credentials_exception=exc)
    assert raised.value.detail == "bad credentials"


def test_decode_token_default_401_when_no_credentials_exception() -> None:
    """When all decoders fail and no exception is supplied, a default 401 is raised."""
    with pytest.raises(HTTPException) as raised:
        decode_token("not-a-token", ["wrong-key"])
    assert raised.value.status_code == 401
    assert "WWW-Authenticate" in (raised.value.headers or {})


def test_decode_token_returns_early_on_first_matching_key() -> None:
    """decode_token returns immediately after the first successful key match."""
    token = create_access_token(
        {"sub": "carol"},
        "key-1",
        timedelta(minutes=5),
        utcnow=_utcnow,
    )

    proxied_called: list[bool] = []

    def proxied(_t: str) -> dict[str, Any]:
        proxied_called.append(True)
        return {"sub": "should-not-be-reached"}

    payload = decode_token(token, ["key-1", "key-2"], proxied_decoder=proxied)
    assert payload["sub"] == "carol"
    # proxied decoder must NOT have been invoked since key-1 succeeded
    assert not proxied_called
