from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import APIRouter

from .protocols import ExternalAuthenticator, InternalAuthenticator


@dataclass(frozen=True)
class AuthProviderRegistration:
    """Configuration entry for one authentication provider."""

    provider: str
    authenticator: InternalAuthenticator | ExternalAuthenticator


RouteHandler = Callable[..., Any]


class AuthRouteAdapter(Protocol):
    """Adapter that maps shared route wiring to host-application handlers."""

    def include_base_routes(self, router: APIRouter) -> None:
        """Add non-provider-specific auth routes to ``router``."""

    def build_internal_token_route(
        self, authenticator: InternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build username/password token handler for a provider."""

    def build_external_code_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build external provider callback handler for a provider."""

    def build_external_authorize_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build external provider redirect route handler."""

    def build_device_code_authorize_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build device-code initiation route handler."""

    def build_device_code_form_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build device-code user-code form route handler."""

    def build_device_code_submit_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build device-code user-code submission handler."""

    def build_device_code_token_route(
        self, authenticator: ExternalAuthenticator, provider: str
    ) -> RouteHandler:
        """Build device-code polling token handler."""

    def include_authenticator_routes(
        self,
        router: APIRouter,
        *,
        provider: str,
        authenticator: InternalAuthenticator | ExternalAuthenticator,
    ) -> None:
        """Optionally include authenticator-defined custom routes."""


def build_authentication_router(
    providers: Iterable[AuthProviderRegistration],
    adapter: AuthRouteAdapter,
    *,
    provider_route_prefix: str = "/provider",
    external_code_methods: Sequence[str] = ("GET",),
) -> APIRouter:
    """Build a provider-aware FastAPI router shared across host applications.

    Parameters
    ----------
    providers:
        Provider/authenticator registrations.
    adapter:
        Host-application adapter that supplies concrete route handlers.
    provider_route_prefix:
        Prefix for provider-specific routes, default ``/provider``.
    external_code_methods:
        HTTP methods used for the external callback endpoint.
    """

    router = APIRouter()
    adapter.include_base_routes(router)

    for registration in providers:
        provider = registration.provider
        authenticator = registration.authenticator
        base = f"{provider_route_prefix}/{provider}"

        if isinstance(authenticator, InternalAuthenticator):
            router.add_api_route(
                f"{base}/token",
                adapter.build_internal_token_route(authenticator, provider),
                methods=["POST"],
            )
        elif isinstance(authenticator, ExternalAuthenticator):
            router.add_api_route(
                f"{base}/code",
                adapter.build_external_code_route(authenticator, provider),
                methods=list(external_code_methods),
            )
            router.add_api_route(
                f"{base}/authorize",
                adapter.build_external_authorize_route(authenticator, provider),
                methods=["GET"],
            )
            router.add_api_route(
                f"{base}/authorize",
                adapter.build_device_code_authorize_route(authenticator, provider),
                methods=["POST"],
            )
            router.add_api_route(
                f"{base}/device_code",
                adapter.build_device_code_form_route(authenticator, provider),
                methods=["GET"],
            )
            router.add_api_route(
                f"{base}/device_code",
                adapter.build_device_code_submit_route(authenticator, provider),
                methods=["POST"],
            )
            router.add_api_route(
                f"{base}/token",
                adapter.build_device_code_token_route(authenticator, provider),
                methods=["POST"],
            )

        adapter.include_authenticator_routes(
            router,
            provider=provider,
            authenticator=authenticator,
        )

    return router


__all__ = [
    "AuthProviderRegistration",
    "AuthRouteAdapter",
    "RouteHandler",
    "build_authentication_router",
]
