import time
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import ExpiredSignatureError, jwt
from respx import MockRouter
from starlette.datastructures import URL, QueryParams

from bluesky_authentication.authenticators import OIDCAuthenticator


def _make_claims(*, expired: bool) -> dict[str, str | float]:
    now = time.time()
    return {
        "aud": "tiled",
        "exp": (now - 1500) if expired else (now + 1500),
        "iat": now - 60,  # always a reasonable past timestamp
        "iss": "https://example.com/realms/example",
        "sub": "Jane Doe",
    }


def _encrypt(claims: dict[str, str | float], private_key: rsa.RSAPrivateKey) -> str:
    return cast(
        "str",
        jwt.encode(
            claims,
            key=private_key,
            algorithm="RS256",
            headers={"kid": "secret"},
        ),
    )


def _mock_request(query_params: dict[str, str] | None = None) -> Any:
    if query_params is None:
        query_params = {}

    class _MockRequest:
        def __init__(self, params: dict[str, str]) -> None:
            self.query_params = QueryParams(params)
            self.scope = {
                "type": "http",
                "scheme": "http",
                "server": ("localhost", 8000),
                "path": "/api/v1/auth/provider/orcid/code",
                "headers": [],
            }
            self.headers = {"host": "localhost:8000"}
            self.url = URL("http://localhost:8000/api/v1/auth/provider/orcid/code")

    return _MockRequest(query_params)


# ---------------------------------------------------------------------------
# Key caching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_caching(
    mock_oidc_server: Any,
    well_known_url: str,
    well_known_response: dict[str, Any],
    json_web_keyset: list[dict[str, Any]],
) -> None:
    """JWKS endpoint is called once; subsequent calls return the cached keyset."""
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

    assert await authenticator.keys() == json_web_keyset
    assert len(mock_oidc_server.calls) == 2
    keys_request = mock_oidc_server.calls[1].request
    assert keys_request.method == "GET"
    assert keys_request.url == well_known_response["jwks_uri"]

    for _ in range(10):
        assert await authenticator.keys() == json_web_keyset

    assert len(mock_oidc_server.calls) == 2


# ---------------------------------------------------------------------------
# Token decoding (expired vs. valid; `iat` value is intentionally NOT varied
# because python-jose does not validate `iat` by default)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
@pytest.mark.parametrize("expired", [True, False])  # type: ignore[untyped-decorator]
@pytest.mark.usefixtures("mock_oidc_server")  # type: ignore[untyped-decorator]
async def test_oidc_decoding(
    well_known_url: str,
    expired: bool,
    keys: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Expired tokens raise ExpiredSignatureError; valid tokens decode correctly."""
    private_key, _ = keys
    authenticator = OIDCAuthenticator(
        "tiled", "tiled", "secret", well_known_uri=well_known_url
    )
    claims = _make_claims(expired=expired)
    token = _encrypt(claims, private_key)

    if not expired:
        assert await authenticator.decode_token(token) == claims
    else:
        with pytest.raises(ExpiredSignatureError):
            await authenticator.decode_token(token)


# ---------------------------------------------------------------------------
# authenticate() — happy paths and error paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_mock(
    mock_oidc_server: MockRouter,
    well_known_url: str,
    well_known_response: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full authenticate flow returns UserSessionState with sub as user_name."""
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

    mock_request = _mock_request({"code": "test-auth-code"})

    def mock_jwt_decode(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return mock_jwt_payload

    def mock_jwk_construct(*_args: Any, **_kwargs: Any) -> object:
        class _MockJWK:
            pass

        return _MockJWK()

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
    """preferred_username without '@' is used verbatim as the user_name."""
    mock_oidc_server.post(well_known_response["token_endpoint"]).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "tok",
                "id_token": "id-tok",
                "token_type": "bearer",
            },
        )
    )

    authenticator = OIDCAuthenticator(
        audience="aud",
        client_id="cid",
        client_secret="sec",
        well_known_uri=well_known_url,
    )

    monkeypatch.setattr(
        "jose.jwt.decode",
        lambda *_a, **_kw: {
            "sub": "opaque-sub",
            "preferred_username": "plain-username",
        },
    )
    monkeypatch.setattr(
        "jose.jwk.construct",
        lambda *_a, **_kw: object(),
    )

    result = await authenticator.authenticate(_mock_request({"code": "c"}))
    assert result is not None
    assert result.user_name == "plain-username"


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_falls_back_to_sub_when_no_preferred_username(
    mock_oidc_server: MockRouter,
    well_known_url: str,
    well_known_response: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When preferred_username is absent, ``sub`` is used as user_name."""
    mock_oidc_server.post(well_known_response["token_endpoint"]).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "tok",
                "id_token": "id-tok",
                "token_type": "bearer",
            },
        )
    )

    authenticator = OIDCAuthenticator(
        audience="aud",
        client_id="cid",
        client_secret="sec",
        well_known_uri=well_known_url,
    )

    monkeypatch.setattr(
        "jose.jwt.decode",
        lambda *_a, **_kw: {"sub": "unique-sub-id"},
    )
    monkeypatch.setattr(
        "jose.jwk.construct",
        lambda *_a, **_kw: object(),
    )

    result = await authenticator.authenticate(_mock_request({"code": "c"}))
    assert result is not None
    assert result.user_name == "unique-sub-id"


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_missing_code_parameter(
    well_known_url: str,
) -> None:
    """Missing ``code`` query parameter causes authenticate() to return None."""
    authenticator = OIDCAuthenticator(
        audience="APP-TEST-CLIENT-ID",
        client_id="APP-TEST-CLIENT-ID",
        client_secret="test-secret",
        well_known_uri=well_known_url,
    )
    result = await authenticator.authenticate(_mock_request({}))
    assert result is None


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_oidc_authenticator_token_exchange_failure(
    well_known_url: str,
    mock_oidc_server: MockRouter,
    well_known_response: dict[str, Any],
) -> None:
    """HTTP error from the token endpoint causes authenticate() to return None."""
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

    result = await authenticator.authenticate(_mock_request({"code": "invalid-code"}))
    assert result is None
