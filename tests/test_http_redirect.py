"""P0-01 acceptance tests: origin-restricted redirect handling.

Every request is served by ``httpx.MockTransport``, so these run with no
external I/O. They pin the security contract: the client stays on the initial
target's origin, counts and throttles each hop, and never mistakes a redirect
for a successful response.
"""

from __future__ import annotations

import httpx
import pytest

from wp_detect.http import (
    BudgetExceeded,
    Client,
    OffOriginRedirect,
    TooManyRedirects,
)

BASE = "https://site.test/"


def _client(handler, **kw):
    """A Client whose transport records every URL actually sent."""
    seen: list[str] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return handler(request)

    c = Client(BASE, delay=0, transport=httpx.MockTransport(_record), **kw)
    c.seen = seen  # type: ignore[attr-defined]
    return c


def _redirect(to: str, code: int = 302) -> httpx.Response:
    return httpx.Response(code, headers={"Location": to})


def test_same_origin_relative_redirect_followed() -> None:
    def h(req):
        return _redirect("/b") if req.url.path == "/a" else httpx.Response(200, text="OK")

    with _client(h) as c:
        r = c.get("/a")
    assert r.status == 200 and r.text == "OK"
    assert r.url == "https://site.test/b"
    assert c.request_count == 2  # the hop is counted


def test_same_origin_absolute_redirect_followed() -> None:
    def h(req):
        if req.url.path == "/a":
            return _redirect("https://site.test/b")
        return httpx.Response(200, text="OK")

    with _client(h) as c:
        r = c.get("/a")
    assert r.status == 200 and r.text == "OK"


@pytest.mark.parametrize(
    "loc",
    [
        "https://evil.test/b",            # off-host
        "https://site.test:8443/b",       # off-port
        "http://site.test/b",             # off-scheme (https -> http)
        "//evil.test/b",                  # protocol-relative, off-host
        "https://user:pass@site.test/b",  # userinfo
    ],
)
def test_off_origin_redirect_refused(loc) -> None:
    def h(req):
        if req.url.path == "/a":
            return _redirect(loc)
        return httpx.Response(200, text="SHOULD NOT REACH")

    with _client(h) as c:
        with pytest.raises(OffOriginRedirect):
            c.get("/a")
        # Only the initial, same-origin request was sent; nothing off-origin.
        assert c.seen == ["https://site.test/a"]


def test_off_origin_initial_path_refused() -> None:
    def h(req):
        return httpx.Response(200, text="SHOULD NOT REACH")

    with _client(h) as c:
        with pytest.raises(OffOriginRedirect):
            c.get("https://evil.test/x")
        assert c.seen == []  # zero sends


def test_non_http_scheme_refused() -> None:
    def h(req):
        return httpx.Response(200)

    with _client(h) as c:
        with pytest.raises(OffOriginRedirect):
            c.get("ftp://site.test/x")
        assert c.seen == []


def test_redirect_hop_limit() -> None:
    def h(req):
        n = int(req.url.path[2:])  # "/rN"
        return _redirect(f"/r{n + 1}")

    with _client(h, max_redirects=5) as c:
        with pytest.raises(TooManyRedirects):
            c.get("/r0")
    assert c.request_count == 6  # initial + 5 follows, then stop


def test_redirect_cycle_detected() -> None:
    def h(req):
        if req.url.path == "/a":
            return _redirect("/b")
        if req.url.path == "/b":
            return _redirect("/a")
        return httpx.Response(200)

    with _client(h, max_redirects=10) as c:
        with pytest.raises(TooManyRedirects):
            c.get("/a")
    assert c.request_count == 2  # /a, /b, loop caught before a third send


def test_budget_stops_before_redirect_hop() -> None:
    def h(req):
        return _redirect("/b") if req.url.path == "/a" else httpx.Response(200, text="OK")

    with _client(h, max_requests=1) as c:
        with pytest.raises(BudgetExceeded):
            c.get("/a")
    assert c.request_count == 1
    assert c.seen == ["https://site.test/a"]  # the hop was never sent


def test_each_hop_counted_and_throttled(monkeypatch) -> None:
    def h(req):
        p = req.url.path
        if p == "/a":
            return _redirect("/b")
        if p == "/b":
            return _redirect("/c")
        return httpx.Response(200, text="OK")

    with _client(h) as c:
        calls = {"n": 0}
        monkeypatch.setattr(c, "_throttle", lambda: calls.__setitem__("n", calls["n"] + 1))
        r = c.get("/a")
    assert r.text == "OK"
    assert c.request_count == 3  # /a, /b, /c
    assert calls["n"] == 3  # throttled once per hop
