from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from fastapi import HTTPException
from jose import ExpiredSignatureError, JWTError, jwt

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import timedelta

ALGORITHM = "HS256"


def create_access_token(
    data: dict[str, Any],
    secret_key: str,
    expires_delta: timedelta,
    *,
    utcnow: Callable[[], Any],
) -> str:
    to_encode = data.copy()
    expire = utcnow() + expires_delta
    to_encode.update({"exp": expire, "type": "access"})
    return cast("str", jwt.encode(to_encode, secret_key, algorithm=ALGORITHM))


def create_refresh_token(
    session_id: str,
    secret_key: str,
    expires_delta: timedelta,
    *,
    utcnow: Callable[[], Any],
) -> str:
    expire = utcnow() + expires_delta
    to_encode = {
        "type": "refresh",
        "sid": session_id,
        "exp": expire,
    }
    return cast("str", jwt.encode(to_encode, secret_key, algorithm=ALGORITHM))


def decode_token_with_secret_keys(
    token: str,
    secret_keys: Sequence[str],
) -> dict[str, Any] | None:
    for secret_key in secret_keys:
        payload = _try_decode_with_secret_key(token, secret_key)
        if payload is not None:
            return payload
    return None


def _try_decode_with_secret_key(token: str, secret_key: str) -> dict[str, Any] | None:
    try:
        return cast(
            "dict[str, Any]", jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        )
    except ExpiredSignatureError:
        raise
    except JWTError:
        return None


def decode_token(
    token: str,
    secret_keys: Sequence[str],
    *,
    proxied_decoder: Callable[[str], dict[str, Any]] | None = None,
    credentials_exception: HTTPException | None = None,
) -> dict[str, Any]:
    payload = decode_token_with_secret_keys(token, secret_keys)
    if payload is not None:
        return payload
    if proxied_decoder is not None:
        return proxied_decoder(token)
    if credentials_exception is None:
        credentials_exception = HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raise credentials_exception


__all__ = [
    "ALGORITHM",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "decode_token_with_secret_keys",
]
