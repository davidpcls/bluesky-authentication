from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi import APIRouter, Request

from bluesky_authentication.integration import (
    AuthProviderRegistration,
    AuthRouteAdapter,
    build_authentication_router,
)
from bluesky_authentication.protocols import (
    ExternalAuthenticator,
    InternalAuthenticator,
    UserSessionState,
)


class _InternalAuthenticator(InternalAuthenticator):
    async def authenticate(
        self, username: str, password: str
    ) -> UserSessionState | None:
        if username == "alice" and password == "secret":
            return UserSessionState(user_name="alice")
        return None


class _ExternalAuthenticator(ExternalAuthenticator):
    async def authenticate(self, request: Request) -> UserSessionState | None:
        del request
        return UserSessionState(user_name="alice")


@dataclass
class _RecordingAdapter(AuthRouteAdapter):
    included_providers: list[str]

    def _route(self, name: str) -> Callable[..., Any]:
        async def endpoint() -> dict[str, str]:
            return {"route": name}

        return endpoint

    def include_base_routes(self, router: APIRouter) -> None:
        router.add_api_route(
            "/session/refresh", self._route("refresh"), methods=["POST"]
        )

    def build_internal_token_route(
        self, authenticator: InternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"internal-token-{provider}")

    def build_external_code_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"external-code-{provider}")

    def build_external_authorize_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"external-authorize-{provider}")

    def build_device_code_authorize_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"device-authorize-{provider}")

    def build_device_code_form_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"device-form-{provider}")

    def build_device_code_submit_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"device-submit-{provider}")

    def build_device_code_token_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> Callable[..., Any]:
        del authenticator
        return self._route(f"device-token-{provider}")

    def include_authenticator_routes(
        self,
        router: APIRouter,
        *,
        provider: str,
        authenticator: InternalAuthenticator | ExternalAuthenticator,
    ) -> None:
        del router, authenticator
        self.included_providers.append(provider)


def test_build_authentication_router_wires_internal_and_external_routes() -> None:
    adapter = _RecordingAdapter(included_providers=[])
    providers = [
        AuthProviderRegistration("local", _InternalAuthenticator()),
        AuthProviderRegistration("oidc", _ExternalAuthenticator()),
    ]

    router = build_authentication_router(providers, adapter)

    by_path: dict[str, set[str]] = {}
    for route in router.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if path is None or methods is None:
            continue
        by_path.setdefault(path, set()).update(methods)

    assert by_path["/session/refresh"] == {"POST"}
    assert by_path["/provider/local/token"] == {"POST"}
    assert by_path["/provider/oidc/code"] == {"GET"}
    assert by_path["/provider/oidc/authorize"] == {"GET", "POST"}
    assert by_path["/provider/oidc/device_code"] == {"GET", "POST"}
    assert by_path["/provider/oidc/token"] == {"POST"}
    assert adapter.included_providers == ["local", "oidc"]


def test_build_authentication_router_allows_external_code_methods_override() -> None:
    adapter = _RecordingAdapter(included_providers=[])
    providers = [AuthProviderRegistration("oidc", _ExternalAuthenticator())]

    router = build_authentication_router(
        providers,
        adapter,
        external_code_methods=("GET", "POST"),
    )

    code_route = next(
        route
        for route in router.routes
        if getattr(route, "path", "") == "/provider/oidc/code"
    )
    assert code_route.methods == {"GET", "POST"}
