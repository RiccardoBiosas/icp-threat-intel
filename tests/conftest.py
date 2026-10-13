"""Shared fixtures. Every test not marked ``live`` runs with outbound sockets blocked."""

import socket
from collections.abc import Iterator
from typing import Any

import pytest

TEST_CONTACT = "test@example.invalid"


class NetworkBlocked(RuntimeError):
    """Raised when a non-live test tries to open a network connection."""


@pytest.fixture(autouse=True)
def _block_network(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    if request.node.get_closest_marker("live") is None:

        def _refuse(*_args: Any, **_kwargs: Any) -> None:
            raise NetworkBlocked("network access is not allowed in unit tests")

        monkeypatch.setattr(socket.socket, "connect", _refuse)
        monkeypatch.setattr(socket.socket, "connect_ex", _refuse)
        monkeypatch.setattr(socket, "create_connection", _refuse)
    yield
