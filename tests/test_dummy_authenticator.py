from __future__ import annotations

import pytest

from bluesky_authentication.authenticators import DummyAuthenticator


@pytest.fixture  # type: ignore[untyped-decorator]
def auth() -> DummyAuthenticator:
    return DummyAuthenticator(confirmation_message="Logged in as demo user.")


async def test_any_credentials_return_user_session_state(
    auth: DummyAuthenticator,
) -> None:
    """DummyAuthenticator accepts any username and any password."""
    result = await auth.authenticate("anyone", "anything")
    assert result is not None
    assert result.user_name == "anyone"


async def test_username_propagated_to_session_state(
    auth: DummyAuthenticator,
) -> None:
    """The supplied username is echoed into UserSessionState.user_name."""
    result = await auth.authenticate("specific-user", "irrelevant")
    assert result.user_name == "specific-user"


def test_confirmation_message_stored(auth: DummyAuthenticator) -> None:
    """confirmation_message is stored verbatim for callers to display."""
    assert auth.confirmation_message == "Logged in as demo user."


def test_empty_confirmation_message_is_default() -> None:
    """Default confirmation_message is an empty string."""
    auth = DummyAuthenticator()
    assert auth.confirmation_message == ""
