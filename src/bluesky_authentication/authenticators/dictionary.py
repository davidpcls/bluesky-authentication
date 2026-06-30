import secrets
from collections.abc import Mapping

from ..protocols import InternalAuthenticator, UserSessionState


class DictionaryAuthenticator(InternalAuthenticator):
    """
    For test and demo purposes only!

    Check passwords from a dictionary of usernames mapped to passwords.
    """

    configuration_schema = """
"$schema": http://json-schema.org/draft-07/schema#
type: object
additionalProperties: false
properties:
  users_to_password:
    type: object
    description: |
      Mapping usernames to password. Environment variable expansion should be
      used to avoid placing passwords directly in configuration.
  confirmation_message:
    type: string
    description: May be displayed by client after successful login.
"""

    def __init__(
        self, users_to_passwords: Mapping[str, str], confirmation_message: str = ""
    ):
        self._users_to_passwords = users_to_passwords
        self.confirmation_message = confirmation_message

    async def authenticate(
        self, username: str, password: str
    ) -> UserSessionState | None:
        true_password = self._users_to_passwords.get(username)
        if not true_password:
            return None
        if secrets.compare_digest(true_password, password):
            return UserSessionState(username, {})
        return None
