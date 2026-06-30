import time
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import ExpiredSignatureError, jwt
from respx import MockRouter
from starlette.datastructures import URL, QueryParams

from bluesky_authentication.authenticators import OIDCAuthenticator


def token(issued: bool, expired: bool) -> dict[str, str | float]:
    now = time.time()
    return {
        "aud": "tiled",
        "exp": (now - 1500) if expired else (now + 1500),
        "iat": (now - 1500) if issued else (now + 1500),
        "iss": "https://example.com/realms/example",
        "sub": "Jane Doe",
    }


def encrypted_token(
    token_value: dict[str, str | float], private_key: rsa.RSAPrivateKey
) -> str:
    return cast(
        "str",
        jwt.encode(
            token_value,
            key=private_key,
            algorithm="RS256",
            headers={"kid": "secret"},
        ),
    )


def test_oidc_authenticator_caching(
    mock_oidc_server: Any,
    well_known_url: str,
    well_known_response: dict[str, Any],
    json_web_keyset: list[dict[str, Any]],
) -> None:
    authenticator = OIDCAuthenticator(
        "tiled", "tiled", "secret", well_known_uri=well_known_url
    )
    assert authenticator.client_id == "tiled"
    assert (
        authenticator.authorization_endpoint
        == well_known_response["authorization_endpoint"]
    )
    assert (
        authenticator.id_token_signing_alg_values_supported
        == well_known_response["id_token_signing_alg_values_supported"]
    )
    assert authenticator.issuer == well_known_response["issuer"]
    assert authenticator.jwks_uri == well_known_response["jwks_uri"]
    assert authenticator.token_endpoint == well_known_response["token_endpoint"]
    assert (
        authenticator.device_authorization_endpoint
        == well_known_response["device_authorization_endpoint"]
    )
    assert (
        authenticator.end_session_endpoint
        == well_known_response["end_session_endpoint"]
    )

    assert len(mock_oidc_server.calls) == 1
    call_request = mock_oidc_server.calls[0].request
    assert call_request.method == "GET"
    assert call_request.url == well_known_url

    assert authenticator.keys() == json_web_keyset
    assert len(mock_oidc_server.calls) == 2
    keys_request = mock_oidc_server.calls[1].request
    assert keys_request.method == "GET"
    assert keys_request.url == well_known_response["jwks_uri"]

    for _ in range(10):
        assert authenticator.keys() == json_web_keyset

    # TTLCache: JWKS fetched once, cached for subsequent calls
    assert len(mock_oidc_server.calls) == 2


@pytest.mark.parametrize("issued", [True, False])  # type: ignore[untyped-decorator]
@pytest.mark.parametrize("expired", [True, False])  # type: ignore[untyped-decorator]
@pytest.mark.usefixtures("mock_oidc_server")  # type: ignore[untyped-decorator]
def test_oidc_decoding(
    well_known_url: str,
    issued: bool,
    expired: bool,
    keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    private_key, _ = keys
    authenticator = OIDCAuthenticator(
        "tiled", "tiled", "secret", well_known_uri=well_known_url
    )
    access_token = token(issued, expired)
    encrypted_access_token = encrypted_token(access_token, private_key)

    if not expired:
        assert authenticator.decode_token(encrypted_access_token) == access_token
    else:
        with pytest.raises(ExpiredSignatureError):
            authenticator.decode_token(encrypted_access_token)


def create_mock_oidc_request(query_params: dict[str, str] | None = None):
    if query_params is None:
        query_params = {}

    class MockRequest:
        def __init__(self, query_params: dict[str, str]):
            self.query_params = QueryParams(query_params)
            self.scope = {
                "type": "http",
                "scheme": "http",
                "server": ("localhost", 8000),
                "path": "/api/v1/auth/provider/orcid/code",
                "headers": [],
            }
            self.headers = {"host": "localhost:8000"}
            self.url = URL("http://localhost:8000/api/v1/auth/provider/orcid/code")

    return MockRequest(query_params)


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_mock(
    mock_oidc_server: MockRouter,
    well_known_url: str,
    well_known_response: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_jwt_payload = {
        "sub": "0009-0008-8698-7745",
        "aud": "APP-TEST-CLIENT-ID",
        "iss": well_known_response["issuer"],
        "exp": 9999999999,
        "iat": 1000000000,
        "given_name": "Test User",
    }

    mock_oidc_server.post(well_known_response["token_endpoint"]).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-access-token",
                "id_token": "mock-id-token",
                "token_type": "bearer",
            },
        )
    )

    authenticator = OIDCAuthenticator(
        audience="APP-TEST-CLIENT-ID",
        client_id="APP-TEST-CLIENT-ID",
        client_secret="test-secret",
        well_known_uri=well_known_url,
    )

    mock_request = create_mock_oidc_request({"code": "test-auth-code"})

    def mock_jwt_decode(*_args, **_kwargs):
        return mock_jwt_payload

    def mock_jwk_construct(*_args, **_kwargs):
        class MockJWK:
            pass

        return MockJWK()

    monkeypatch.setattr("jose.jwt.decode", mock_jwt_decode)
    monkeypatch.setattr("jose.jwk.construct", mock_jwk_construct)

    user_session = await authenticator.authenticate(mock_request)

    assert user_session is not None
    assert user_session.user_name == "0009-0008-8698-7745"


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_preferred_username_without_at_used_as_is(
    mock_oidc_server: MockRouter,
    well_known_url: str,
    well_known_response: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """preferred_username without @ is used verbatim as user_name."""
    mock_oidc_server.post(well_known_response["token_endpoint"]).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-access-token",
                "id_token": "mock-id-token",
                "token_type": "bearer",
            },
        )
    )
    authenticator = OIDCAuthenticator(
        audience="APP-TEST-CLIENT-ID",
        client_id="APP-TEST-CLIENT-ID",
        client_secret="test-secret",
        well_known_uri=well_known_url,
    )
    mock_request = create_mock_oidc_request({"code": "test-auth-code"})
    monkeypatch.setattr(
        "jose.jwt.decode",
        lambda *_a, **_kw: {
            "sub": "some-sub",
            "aud": "APP-TEST-CLIENT-ID",
            "preferred_username": "alice",
        },
    )
    monkeypatch.setattr("jose.jwk.construct", lambda *_a, **_kw: object())
    result = await authenticator.authenticate(mock_request)
    assert result is not None
    assert result.user_name == "alice"


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_falls_back_to_sub_when_no_preferred_username(
    mock_oidc_server: MockRouter,
    well_known_url: str,
    well_known_response: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When preferred_username is absent, sub is used as user_name."""
    mock_oidc_server.post(well_known_response["token_endpoint"]).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-access-token",
                "id_token": "mock-id-token",
                "token_type": "bearer",
            },
        )
    )
    authenticator = OIDCAuthenticator(
        audience="APP-TEST-CLIENT-ID",
        client_id="APP-TEST-CLIENT-ID",
        client_secret="test-secret",
        well_known_uri=well_known_url,
    )
    mock_request = create_mock_oidc_request({"code": "test-auth-code"})
    monkeypatch.setattr(
        "jose.jwt.decode",
        lambda *_a, **_kw: {"sub": "opaque-sub-id", "aud": "APP-TEST-CLIENT-ID"},
    )
    monkeypatch.setattr("jose.jwk.construct", lambda *_a, **_kw: object())
    result = await authenticator.authenticate(mock_request)
    assert result is not None
    assert result.user_name == "opaque-sub-id"


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_missing_code_parameter(well_known_url: str) -> None:
    authenticator = OIDCAuthenticator(
        audience="APP-TEST-CLIENT-ID",
        client_id="APP-TEST-CLIENT-ID",
        client_secret="test-secret",
        well_known_uri=well_known_url,
    )

    mock_request = create_mock_oidc_request({})

    result = await authenticator.authenticate(mock_request)
    assert result is None


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_token_exchange_failure(
    well_known_url: str,
    mock_oidc_server: MockRouter,
    well_known_response: dict[str, Any],
) -> None:
    mock_oidc_server.post(well_known_response["token_endpoint"]).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_client",
                "error_description": "Client not found: APP-TEST-CLIENT-ID",
            },
        )
    )

    authenticator = OIDCAuthenticator(
        audience="APP-TEST-CLIENT-ID",
        client_id="APP-TEST-CLIENT-ID",
        client_secret="test-secret",
        well_known_uri=well_known_url,
    )

    mock_request = create_mock_oidc_request({"code": "invalid-code"})

    result = await authenticator.authenticate(mock_request)
    assert result is None
