"""Scans do not silently use an environment proxy."""

from __future__ import annotations

from wp_detect.http import Client


def test_client_ignores_env_proxy_by_default(monkeypatch) -> None:
    # Even with proxy variables in the environment, the client must not trust
    # them — a scan goes where it was pointed, not through a surprise proxy.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    with Client("https://example.test/") as c:
        assert c._client.trust_env is False
