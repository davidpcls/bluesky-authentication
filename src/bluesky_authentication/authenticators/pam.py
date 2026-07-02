import importlib
from typing import Any

from ..protocols import InternalAuthenticator, UserSessionState
from ..utils import modules_available


class PAMAuthenticator(InternalAuthenticator):
    """Authenticate users against the host's PAM service."""

    configuration_schema = """
"$schema": http://json-schema.org/draft-07/schema#
type: object
additionalProperties: false
properties:
  service:
    type: string
    description: PAM service. Default is 'login'.
  confirmation_message:
    type: string
    description: May be displayed by client after successful login.
"""

    def __init__(self, service: str = "login", confirmation_message: str = ""):
        if not modules_available("pamela"):
            msg = "This PAMAuthenticator requires the module 'pamela' to be installed."
            raise ModuleNotFoundError(msg)
        self.service = service
        self.confirmation_message = confirmation_message

    @staticmethod
    def _load_pamela() -> Any:
        return importlib.import_module("pamela")

    async def authenticate(
        self, username: str, password: str
    ) -> UserSessionState | None:
        pamela = self._load_pamela()

        try:
            pamela.authenticate(username, password, service=self.service)
            return UserSessionState(username, {})
        except pamela.PAMError:
            return None
