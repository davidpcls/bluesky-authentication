from __future__ import annotations

import importlib.util
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

    from fastapi import Request
    from starlette.types import Scope

    from .authenticators.oidc import ProxiedOIDCAuthenticator


def modules_available(*module_names: str) -> bool:
    for module_name in module_names:
        if not importlib.util.find_spec(module_name):
            break
    else:
        return True
    return False


def get_root_url(request: Request) -> str:
    return f"{get_root_url_low_level(request.headers, request.scope)}"


def get_root_url_low_level(request_headers: Mapping[str, str], scope: Scope) -> str:
    host = request_headers.get("x-forwarded-host", request_headers["host"])
    scheme = request_headers.get("x-forwarded-proto", scope["scheme"])
    root_path = scope.get("root_path", "")
    root_path = root_path.removesuffix("/")
    return f"{scheme}://{host}{root_path}"


def extract_scopes(decoded_access_token: dict[str, Any]) -> set[str]:
    """Extract the set of scopes from a decoded JWT payload.

    Handles both the ``scp`` claim (list or space-separated string) used by
    Entra / ProxiedOIDC tokens, and the ``scope`` claim (space-separated
    string) used by app-minted tokens.
    """
    if "scp" in decoded_access_token:
        scp = decoded_access_token["scp"]
        return set(scp) if isinstance(scp, list) else set(scp.split())
    if "scope" in decoded_access_token:
        return set(decoded_access_token["scope"].split())
    return set()


def find_proxied_authenticator(
    authenticators: dict[str, Any],
) -> ProxiedOIDCAuthenticator | None:
    """Return the first ``ProxiedOIDCAuthenticator`` in *authenticators*, or ``None``.

    This is used by both tiled and bluesky-httpserver to locate the proxied
    authenticator that can decode external OIDC tokens issued by an upstream
    IdP (as opposed to app-minted HMAC tokens).
    """
    # Late import to avoid circular dependencies; ProxiedOIDCAuthenticator
    # lives in the authenticators sub-package.
    from .authenticators.oidc import ProxiedOIDCAuthenticator  # noqa: PLC0415

    if not authenticators:
        return None
    for authenticator in authenticators.values():
        if isinstance(authenticator, ProxiedOIDCAuthenticator):
            return authenticator
    return None


__all__ = [
    "extract_scopes",
    "find_proxied_authenticator",
    "get_root_url",
    "get_root_url_low_level",
    "modules_available",
]
