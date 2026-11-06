"""Bounded transient-error retry in the client.

Every request is served by ``httpx.MockTransport`` whose handler can raise a
transient transport error a set number of times before succeeding, so the retry
path is exercised with no network and no real sleeping (backoff is monkeypatched).
"""

from __future__ import annotations

import httpx
import pytest

from wp_detect.http import Client

BASE = "https://site.test/"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Record backoff waits instead of sleeping."""
    waits: list[float] = []
    monkeypatch.setattr("wp_detect.http.time.sleep", lambda s: waits.append(s))
    return waits


def _client(handler, **kw):
    return Client(BASE, delay=0, transport=httpx.MockTransport(handler), **kw)


def _fail_then_ok(n, exc_factory):
    """Handler that raises a transient error on the first ``n`` calls, then 200."""
    calls = {"n": 0}

    def _h(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= n:
            raise exc_factory(request)
        return httpx.Response(200, text="OK")

    _h.calls = calls  # type: ignore[attr-defined]
    return _h


def _connect_timeout(request):
    return httpx.ConnectTimeout("connect timed out", request=request)


def _read_timeout(request):
    return httpx.ReadTimeout("read timed out", request=request)


def _reset(request):
    return httpx.ReadError("connection reset", request=request)


# -- recovery ------------------------------------------------------------

@pytest.mark.parametrize("exc", [_connect_timeout, _read_timeout, _reset])
def test_single_transient_is_retried_and_recovers(exc) -> None:
    h = _fail_then_ok(1, exc)
    c = _client(h, max_retries=1)
    resp = c.get("/a")
    assert resp.status == 200
    assert h.calls["n"] == 2            # one failure + one success
    assert c.request_count == 2         # every attempt counts against the budget


def test_retry_is_opt_in_off_by_default() -> None:
    # Default max_retries=0: the transient error propagates with no retry, so
    # existing callers see no behavior change.
    h = _fail_then_ok(1, _connect_timeout)
    c = _client(h)  # no max_retries -> default 0
    with pytest.raises(httpx.ConnectTimeout):
        c.get("/a")
    assert h.calls["n"] == 1
    assert c.request_count == 1


def test_retries_are_bounded_then_raise() -> None:
    # Always transient; max_retries=1 -> exactly two attempts, then propagate.
    h = _fail_then_ok(99, _reset)
    c = _client(h, max_retries=1)
    with pytest.raises(httpx.ReadError):
        c.get("/a")
    assert h.calls["n"] == 2
    assert c.request_count == 2


def test_higher_retry_count_recovers_later() -> None:
    h = _fail_then_ok(2, _read_timeout)
    c = _client(h, max_retries=3)
    assert c.get("/a").status == 200
    assert h.calls["n"] == 3


# -- what must NOT be retried -------------------------------------------

def test_http_status_is_not_retried() -> None:
    seen = {"n": 0}

    def _h(request):
        seen["n"] += 1
        return httpx.Response(503, text="busy")

    c = _client(_h, max_retries=3)
    assert c.get("/a").status == 503
    assert seen["n"] == 1               # a status code is not a transient error


def test_non_transient_exception_is_not_retried() -> None:
    def _h(request):
        raise ZeroDivisionError("not a transport error")

    c = _client(_h, max_retries=3)
    with pytest.raises(ZeroDivisionError):
        c.get("/a")


def test_connect_error_is_excluded_and_not_retried() -> None:
    # ConnectError (TLS verify failure / DNS / connection-refused) is permanent,
    # not transport-transient, so it is NOT retried even with retries enabled.
    def _h(request):
        raise httpx.ConnectError("certificate verify failed", request=request)

    c = _client(_h, max_retries=3)
    with pytest.raises(httpx.ConnectError):
        c.get("/a")
    assert c.request_count == 1


def test_non_idempotent_method_is_not_retried() -> None:
    h = _fail_then_ok(1, _reset)
    c = _client(h, max_retries=3)
    with pytest.raises(httpx.ReadError):
        c.request_body("POST", "/xmlrpc.php", "<x/>", content_type="text/xml")
    assert h.calls["n"] == 1            # POST is not idempotent -> no retry


def test_body_bearing_request_is_not_retried_even_if_method_safe() -> None:
    # A body-bearing probe must not be replayed regardless of method.
    h = _fail_then_ok(1, _reset)
    c = _client(h, max_retries=3)
    with pytest.raises(httpx.ReadError):
        c.request_body("OPTIONS", "/x", "<x/>", content_type="text/xml")
    assert h.calls["n"] == 1


def test_retry_not_attempted_when_budget_exhausted(_no_sleep) -> None:
    # Budget of 1: the first attempt consumes it, so there is no room to retry.
    # The transient error propagates and NO backoff is slept.
    h = _fail_then_ok(99, _connect_timeout)
    c = _client(h, max_retries=5, max_requests=1)
    with pytest.raises(httpx.ConnectTimeout):
        c.get("/a")
    assert c.request_count == 1
    assert _no_sleep == []              # no sleep after the budget is out


# -- backoff -------------------------------------------------------------

def test_backoff_is_exponential_and_capped(_no_sleep) -> None:
    h = _fail_then_ok(99, _reset)
    c = _client(h, max_retries=4, retry_backoff=0.5, retry_backoff_max=1.5)
    with pytest.raises(httpx.ReadError):
        c.get("/a")
    # attempts 1..4 -> 0.5, 1.0, min(1.5, 2.0)=1.5, min(1.5, 4.0)=1.5
    assert _no_sleep == [0.5, 1.0, 1.5, 1.5]


def test_backoff_disabled_when_zero(_no_sleep) -> None:
    h = _fail_then_ok(1, _reset)
    c = _client(h, max_retries=1, retry_backoff=0.0)
    assert c.get("/a").status == 200
    assert _no_sleep == []              # no backoff sleeps recorded


# -- retry on a redirected hop ------------------------------------------

def test_transient_on_redirect_target_is_retried() -> None:
    state = {"n": 0}

    def _h(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"Location": "/b"})
        # /b fails transiently once, then succeeds
        state["n"] += 1
        if state["n"] == 1:
            raise _reset(request)
        return httpx.Response(200, text="OK")

    c = _client(_h, max_retries=1)
    assert c.get("/a").status == 200
    assert state["n"] == 2              # /b retried after its transient error
