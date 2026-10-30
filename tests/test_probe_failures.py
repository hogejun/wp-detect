"""Detection probe failures make a scan partial (never silently complete),
and malformed URLs are refused."""

from __future__ import annotations

import httpx
import pytest

from wp_detect.http import BudgetExceeded, Client, OffOriginRedirect, TooManyRedirects, _origin
from wp_detect.scanner import scan

WP_HOME = '<html><head><meta name="generator" content="WordPress 6.4" /></head></html>'
WP_HOME_NO_VERSION = "<html><body>/wp-content/themes/x/style.css</body></html>"


class _Resp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status = status
        self.url = "https://x/"
        self.headers: dict = {}
        self.elapsed = 0.0
        self.set_cookies: list = []

    def header(self, name):  # noqa: D401
        return None


class _FakeClient:
    """Duck-typed stand-in for http.Client: routes map a path to a response or
    an exception to raise."""

    base_url = "https://x/"

    def __init__(self, routes):
        self.routes = routes

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, path):
        v = self.routes.get(path, _Resp("", 404))
        if isinstance(v, BaseException):
            raise v
        return v


# -- probe failures are not "complete" -----------------------------

def test_budget_exceeded_on_probe_makes_scan_failed() -> None:
    fc = _FakeClient({"/": _Resp(WP_HOME), "/wp-json/": BudgetExceeded("budget gone")})
    r = scan(fc, only=["detect"])
    assert r.scan_status != "complete"
    assert r.scan_status == "failed"  # detect itself could not finish


def test_off_origin_redirect_on_probe_is_partial_not_complete() -> None:
    fc = _FakeClient({"/": _Resp(WP_HOME), "/wp-json/": OffOriginRedirect("off")})
    r = scan(fc, only=["detect"])
    assert r.is_wordpress is True          # still detected from the homepage
    assert r.scan_status == "partial"      # but a probe was refused
    assert "detect" in r.failed_checks


def test_timeout_on_readme_is_partial_and_recorded() -> None:
    fc = _FakeClient({
        "/": _Resp(WP_HOME_NO_VERSION),           # no version -> readme is probed
        "/wp-json/": _Resp("", 404),
        "/readme.html": httpx.TimeoutException("slow"),
        "/feed/": _Resp("", 404),
    })
    r = scan(fc, only=["detect"])
    assert r.scan_status == "partial"
    detect = r.results[0]
    assert detect.status == "partial"
    assert any("readme.html" in reason for reason in detect.incomplete_reasons)
    # Secret-free: only path + exception type, no raw message/URL.
    assert all(":" in reason and "slow" not in reason for reason in detect.incomplete_reasons)


def test_all_probes_ok_is_complete() -> None:
    fc = _FakeClient({
        "/": _Resp(WP_HOME),
        "/wp-json/": _Resp('{"namespaces":["wp/v2"]}', 200),
        "/readme.html": _Resp("", 404),
        "/feed/": _Resp("", 404),
    })
    r = scan(fc, only=["detect"])
    assert r.scan_status == "complete"
    assert r.failed_checks == []


def test_homepage_failure_is_fatal() -> None:
    fc = _FakeClient({"/": httpx.ConnectError("refused")})
    with pytest.raises(httpx.HTTPError):
        scan(fc, only=["detect"])


def test_too_many_redirects_on_probe_is_partial() -> None:
    fc = _FakeClient({"/": _Resp(WP_HOME), "/wp-json/": TooManyRedirects("loop")})
    r = scan(fc, only=["detect"])
    assert r.scan_status == "partial"


# -- malformed URLs are refused ------------------------------------

@pytest.mark.parametrize("url", [
    "https:///path",          # no host
    "http://",                # no host
    "https://h:99999/",       # port out of range
    "https://u:p@h/",         # userinfo
    "ftp://h/",               # non-HTTP scheme
])
def test_origin_rejects_malformed(url) -> None:
    with pytest.raises(OffOriginRedirect):
        _origin(url)


def test_origin_accepts_ipv6() -> None:
    assert _origin("https://[::1]:8443/") == ("https", "::1", 8443)


def test_client_refuses_bad_port_at_construction() -> None:
    with pytest.raises(OffOriginRedirect):
        Client("https://h:99999/")
