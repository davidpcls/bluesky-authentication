from ..protocols import InternalAuthenticator, UserSessionState


class DummyAuthenticator(InternalAuthenticator):
    """
    For test and demo purposes only!

    Accept any username and any password.

    """

    def __init__(self, confirmation_message: str = ""):
        self.confirmation_message = confirmation_message

    async def authenticate(self, username: str, password: str) -> UserSessionState:
        return UserSessionState(username, {})
