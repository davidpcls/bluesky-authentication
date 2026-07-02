"""Copyright (c) 2026 David Pastl. All rights reserved.

bluesky-authentication: A common authentication package for use in web serving applications
"""

from __future__ import annotations

from ._version import version as __version__
from .authenticators import (
    DictionaryAuthenticator,
    DummyAuthenticator,
    EntraAuthenticator,
    LDAPAuthenticator,
    OIDCAuthenticator,
    PAMAuthenticator,
    ProxiedOIDCAuthenticator,
    SAMLAuthenticator,
)
from .integration import (
    AuthProviderRegistration,
    AuthRouteAdapter,
    build_authentication_router,
)
from .protocols import ExternalAuthenticator, InternalAuthenticator, UserSessionState
from .tokens import (
    ALGORITHM,
    create_access_token,
    create_refresh_token,
    decode_token,
    decode_token_with_secret_keys,
)
from .utils import (
    extract_scopes,
    find_proxied_authenticator,
)

__all__ = [
    "ALGORITHM",
    "AuthProviderRegistration",
    "AuthRouteAdapter",
    "DictionaryAuthenticator",
    "DummyAuthenticator",
    "EntraAuthenticator",
    "ExternalAuthenticator",
    "InternalAuthenticator",
    "LDAPAuthenticator",
    "OIDCAuthenticator",
    "PAMAuthenticator",
    "ProxiedOIDCAuthenticator",
    "SAMLAuthenticator",
    "UserSessionState",
    "__version__",
    "build_authentication_router",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "decode_token_with_secret_keys",
    "extract_scopes",
    "find_proxied_authenticator",
]
