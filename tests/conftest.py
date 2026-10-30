"""Pytest fixtures for the core package: in-process mock servers.

The mock itself lives in :mod:`wp_detect.testing` (shipped, reusable by plugin
authors); this is just the fixture wiring."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from wp_detect.http import Client
from wp_detect.testing import PlainHandler, WordPressHandler, serve


@pytest.fixture
def wp_url() -> Iterator[str]:
    server, url = serve(WordPressHandler)
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture
def plain_url() -> Iterator[str]:
    server, url = serve(PlainHandler)
    try:
        yield url
    finally:
        server.shutdown()


@pytest.fixture
def wp_client(wp_url: str) -> Iterator[Client]:
    with Client(wp_url, delay=0, verify_tls=False) as c:
        yield c
