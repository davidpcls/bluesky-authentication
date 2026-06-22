from typing import Optional

from ..protocols import InternalAuthenticator, UserSessionState
from ..utils import modules_available


class PAMAuthenticator(InternalAuthenticator):
    configuration_schema = """
$schema": http://json-schema.org/draft-07/schema#
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
            raise ModuleNotFoundError(
                "This PAMAuthenticator requires the module 'pamela' to be installed."
            )
        self.service = service
        self.confirmation_message = confirmation_message

    async def authenticate(
        self, username: str, password: str
    ) -> Optional[UserSessionState]:
        import pamela

        try:
            pamela.authenticate(username, password, service=self.service)
            return UserSessionState(username, {})
        except pamela.PAMError:
            return
