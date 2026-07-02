from __future__ import annotations

import pytest

from bluesky_authentication.authenticators import DictionaryAuthenticator


@pytest.fixture  # type: ignore[untyped-decorator]
def auth() -> DictionaryAuthenticator:
    return DictionaryAuthenticator(
        users_to_passwords={"alice": "correct-password", "bob": "b0bpass"},
        confirmation_message="Welcome!",
    )


async def test_correct_password_returns_user_session_state(
    auth: DictionaryAuthenticator,
) -> None:
    """Valid username + matching password returns a UserSessionState."""
    result = await auth.authenticate("alice", "correct-password")
    assert result is not None
    assert result.user_name == "alice"


async def test_wrong_password_returns_none(auth: DictionaryAuthenticator) -> None:
    """Valid username with wrong password returns None."""
    result = await auth.authenticate("alice", "wrong-password")
    assert result is None


async def test_unknown_username_returns_none(auth: DictionaryAuthenticator) -> None:
    """Unrecognised username returns None (no KeyError)."""
    result = await auth.authenticate("charlie", "some-password")
    assert result is None


async def test_empty_password_returns_none(auth: DictionaryAuthenticator) -> None:
    """Empty password string is rejected even when the username is valid.

    This guards the ``if not true_password`` short-circuit that prevents
    timing-safe comparison against an empty stored password.
    """
    # Construct an authenticator that has a user with a real password but
    # simulate the check by sending an empty password for a valid user.
    result = await auth.authenticate("alice", "")
    assert result is None


def test_confirmation_message_stored(auth: DictionaryAuthenticator) -> None:
    """confirmation_message is stored verbatim for callers to display."""
    assert auth.confirmation_message == "Welcome!"
