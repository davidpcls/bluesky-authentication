from __future__ import annotations

import importlib.metadata

import bluesky_authentication as m


def test_version() -> None:
    assert importlib.metadata.version("bluesky_authentication") == m.__version__
