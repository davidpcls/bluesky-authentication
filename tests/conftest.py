from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jose.backends import RSAKey
from respx import MockRouter


@pytest.fixture  # type: ignore[untyped-decorator]
def base_url() -> str:
    return "https://example.com/realms/example"


@pytest.fixture  # type: ignore[untyped-decorator]
def well_known_url(base_url: str) -> str:
    return f"{base_url}.well-known/openid-configuration"


@pytest.fixture  # type: ignore[untyped-decorator]
def well_known_response(base_url: str) -> dict[str, Any]:
    return {
        "id_token_signing_alg_values_supported": ["RS256"],
        "issuer": base_url,
        "jwks_uri": f"{base_url}protocol/openid-connect/certs",
        "authorization_endpoint": f"{base_url}protocol/openid-connect/auth",
        "token_endpoint": f"{base_url}protocol/openid-connect/token",
        "device_authorization_endpoint": f"{base_url}protocol/openid-connect/auth/device",
        "end_session_endpoint": f"{base_url}protocol/openid-connect/logout",
    }


@pytest.fixture  # type: ignore[untyped-decorator]
def keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return (private_key, public_key)


@pytest.fixture  # type: ignore[untyped-decorator]
def json_web_keyset(
    keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> list[dict[str, Any]]:
    _, public_key = keys
    return [RSAKey(key=public_key, algorithm="RS256").to_dict()]


@pytest.fixture  # type: ignore[untyped-decorator]
def mock_oidc_server(
    respx_mock: MockRouter,
    well_known_url: str,
    well_known_response: dict[str, Any],
    json_web_keyset: list[dict[str, Any]],
) -> MockRouter:
    respx_mock.get(well_known_url).mock(
        return_value=httpx.Response(httpx.codes.OK, json=well_known_response)
    )
    respx_mock.get(well_known_response["jwks_uri"]).mock(
        return_value=httpx.Response(httpx.codes.OK, json={"keys": json_web_keyset})
    )
    return respx_mock
