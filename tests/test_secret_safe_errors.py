"""HTTP boundary / invalid-URL exceptions must not
embed the raw URL (credentials, path, query, fragment) in their message, so a
secret cannot leak through ``str(exc)``, a log line, a Finding ``error`` or a
JSON snapshot. The exception *types* and the boundary behaviour are unchanged.
"""

from __future__ import annotations

import json

import httpx
import pytest

from wp_detect.http import (
    BudgetExceeded,
    Client,
    OffOriginRedirect,
    TooManyRedirects,
    _origin,
)

BASE = "https://site.test/"


def _client(handler, **kw):
    seen: list[str] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return handler(request)

    c = Client(BASE, delay=0, transport=httpx.MockTransport(_record), **kw)
    c.seen = seen  # type: ignore[attr-defined]
    return c


def _redirect(to: str, code: int = 302) -> httpx.Response:
    return httpx.Response(code, headers={"Location": to})


def _assert_no_secret(msg: str, *secrets: str) -> None:
    low = msg.lower()
    for s in secrets:
        assert s not in msg and s.lower() not in low, f"{s!r} leaked in: {msg!r}"


# -- _origin(): userinfo, scheme, host, port ------------------------------

def test_origin_userinfo_is_not_echoed() -> None:
    url = "https://alice:s3cr3t@example.com/wp-admin"
    with pytest.raises(OffOriginRedirect) as ei:
        _origin(url)
    _assert_no_secret(str(ei.value), "alice", "s3cr3t", "example.com", url)


def test_origin_unsupported_scheme_is_not_echoed() -> None:
    url = "ftp://host.example/secret/path"
    with pytest.raises(OffOriginRedirect) as ei:
        _origin(url)
    _assert_no_secret(str(ei.value), "host.example", "/secret/path", url)


def test_origin_missing_host_is_not_echoed() -> None:
    url = "https:///lonely/path?token=ABCDEF"
    with pytest.raises(OffOriginRedirect) as ei:
        _origin(url)
    _assert_no_secret(str(ei.value), "ABCDEF", "/lonely/path", url)


def test_origin_invalid_port_is_not_echoed() -> None:
    url = "https://host.example:99999/p?token=ABCDEF"
    with pytest.raises(OffOriginRedirect) as ei:
        _origin(url)
    _assert_no_secret(str(ei.value), "ABCDEF", "host.example", "99999", url)


# -- _check_origin(): off-origin request ----------------------------------

_LEAKY = "https://other.example/path?token=TOP_SECRET#fragment"


def test_check_origin_off_origin_is_not_echoed() -> None:
    with _client(lambda req: httpx.Response(200)) as c:
        with pytest.raises(OffOriginRedirect) as ei:
            c._check_origin(_LEAKY)
    msg = str(ei.value)
    # neither the rejected URL (and its secret-bearing parts) nor the target
    # origin tuple (host:port) appears.
    _assert_no_secret(msg, "TOP_SECRET", "other.example", "/path", "fragment", _LEAKY, "site.test")


def test_off_origin_redirect_via_send_is_not_echoed() -> None:
    def h(req):
        if req.url.path == "/a":
            return _redirect(_LEAKY)
        return httpx.Response(200, text="SHOULD NOT REACH")

    with _client(h) as c:
        with pytest.raises(OffOriginRedirect) as ei:
            c.get("/a")
        assert c.seen == ["https://site.test/a"]  # boundary still enforced
    _assert_no_secret(str(ei.value), "TOP_SECRET", "other.example", "/path", "fragment", _LEAKY)


# -- TooManyRedirects: loop and hop-limit ---------------------------------

def test_redirect_loop_message_is_not_echoed() -> None:
    def h(req):
        # /a -> /b?token=... -> /b?token=... (loops back to the secret URL)
        if req.url.path == "/a":
            return _redirect("/b?token=TOP_SECRET")
        return _redirect("/b?token=TOP_SECRET")

    with _client(h) as c:
        with pytest.raises(TooManyRedirects) as ei:
            c.get("/a")
    _assert_no_secret(str(ei.value), "TOP_SECRET", "/b", "token")


def test_hop_limit_message_is_not_echoed() -> None:
    def h(req):
        # Always redirect to a fresh secret-bearing URL until the hop limit.
        n = req.url.path.count("x")
        return _redirect(f"/x{req.url.path}?token=TOP_SECRET")

    with _client(h, max_redirects=2) as c:
        with pytest.raises(TooManyRedirects) as ei:
            c.get("/start")
    _assert_no_secret(str(ei.value), "TOP_SECRET", "/start", "token")


# -- secondary exposure: transcribed into a Finding error / JSON ----------

def test_exception_transcribed_to_json_has_no_secret() -> None:
    try:
        _origin("https://alice:s3cr3t@example.com/")
    except OffOriginRedirect as exc:
        error = f"{type(exc).__name__}: {exc}"  # scanner.py records this shape
    blob = json.dumps({"check": "detect", "error": error})
    _assert_no_secret(blob, "alice", "s3cr3t", "example.com")
    assert "OffOriginRedirect" in error  # type name preserved for diagnosis


# -- type preserved + boundary still rejected (regression guard) ----------

def test_types_preserved_and_boundaries_rejected() -> None:
    with _client(lambda req: httpx.Response(200)) as c:
        with pytest.raises(OffOriginRedirect):
            c.get("https://evil.test/x")
        assert c.seen == []
    # BudgetExceeded still names only the configured integer, no URL.
    with _client(lambda req: httpx.Response(200), max_requests=0) as c:
        with pytest.raises(BudgetExceeded) as ei:
            c.get("/a")
    assert "0" in str(ei.value)
