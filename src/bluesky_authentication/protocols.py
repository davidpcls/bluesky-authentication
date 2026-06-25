from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request


@dataclass
class UserSessionState:
    """Data transfer class to communicate custom session state information."""

    user_name: str
    state: dict[str, Any] | None = field(default=None)


class InternalAuthenticator(ABC):
    """Base class for authenticators that use username/password credentials."""

    @abstractmethod
    async def authenticate(
        self, username: str, password: str
    ) -> UserSessionState | None:
        raise NotImplementedError


class ExternalAuthenticator(ABC):
    """Base class for authenticators that use external identity providers."""

    @abstractmethod
    async def authenticate(self, request: Request) -> UserSessionState | None:
        raise NotImplementedError
