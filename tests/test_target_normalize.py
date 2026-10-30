"""Scheme detection without the ambiguous ``"//" in raw`` heuristic, and
rejection of empty ``?`` / ``#`` delimiters, for ``normalize_target()`` and
``safe_display()``. Error strings and the log-safe display never echo the
input, a secret, a path or userinfo.
"""

from __future__ import annotations

import pytest

from wp_detect.http import normalize_target, safe_display

# -- T01-T25: normalize_target --------------------------------------------

ACCEPT = [
    ("T01", "example.com", "https://example.com"),
    ("T02", "example.com//path", "https://example.com//path"),
    ("T04", "localhost:8080/path", "https://localhost:8080/path"),
    ("T05", "example.com:8443/a", "https://example.com:8443/a"),
    ("T06", "http://example.com/a", "http://example.com/a"),
    ("T07", "HTTP://example.com/a", "http://example.com/a"),
    ("T19", "https://[::1]:8443/a", "https://[::1]:8443/a"),
    ("T23", "https://h/a%3Fb%23c", "https://h/a%3Fb%23c"),
]


@pytest.mark.parametrize("tid, raw, expected", ACCEPT, ids=[t[0] for t in ACCEPT])
def test_normalize_accepts(tid, raw, expected) -> None:
    assert normalize_target(raw) == expected


def test_normalize_preserves_double_slash_path() -> None:  # T03
    assert normalize_target("https://h/a//b") == "https://h/a//b"


REJECT = [
    ("T08", "https:/example.com"),
    ("T09", "http:example.com"),
    ("T10", "//example.com/a"),
    ("T11", "javascript:alert(1)"),
    ("T12", "mailto:user@example.com"),
    ("T13", "https://h\\evil.com"),
    ("T14", "https://h/a?"),
    ("T15", "https://h/a#"),
    ("T20", "https://[::1/a"),
    ("T21", "https://h:abc/"),
    ("T22", "https://h:99999/"),
    ("T24", "https://h/a b"),
    ("T25", "https://h/a\n"),
]


@pytest.mark.parametrize("tid, raw", REJECT, ids=[t[0] for t in REJECT])
def test_normalize_rejects(tid, raw) -> None:
    with pytest.raises(ValueError) as ei:
        normalize_target(raw)
    assert raw not in str(ei.value)  # never echo the input


SECRET_REJECT = [
    ("T16", "https://h/a?token=TOPSECRET"),
    ("T17", "https://h/a#TOPSECRET"),
    ("T18", "https://user:TOPSECRET@h/a"),
]


@pytest.mark.parametrize("tid, raw", SECRET_REJECT, ids=[t[0] for t in SECRET_REJECT])
def test_normalize_rejects_without_leaking_secret(tid, raw) -> None:
    with pytest.raises(ValueError) as ei:
        normalize_target(raw)
    msg = str(ei.value)
    assert "TOPSECRET" not in msg
    assert "user" not in msg or "userinfo" in msg  # the word "userinfo" is ok
    assert raw not in msg


def test_normalize_rejects_empty_and_non_str() -> None:
    for bad in ["", None, 123]:
        with pytest.raises(ValueError):
            normalize_target(bad)  # type: ignore[arg-type]


# -- safe_display ---------------------------------------------------------

def test_safe_display_valid_inputs() -> None:
    assert safe_display("example.com") == "https://example.com"              # T01
    assert safe_display("example.com//path") == "https://example.com"        # T02
    assert safe_display("localhost:8080/path") == "https://localhost:8080"   # T04
    assert safe_display("https://[::1]:8443/a") == "https://[::1]:8443"      # T19
    assert safe_display("https://h/p") == "https://h"


def test_safe_display_invalid_is_placeholder_without_leaking() -> None:
    # T16: query present -> invalid -> <target>, with no secret/path shown.
    d = safe_display("https://h/a?token=TOPSECRET")
    assert d == "<target>"
    assert "TOPSECRET" not in d and "/a" not in d
    # T18: userinfo -> invalid -> <target>, no secret/userinfo shown.
    d = safe_display("https://user:TOPSECRET@h/a")
    assert d == "<target>"
    assert "TOPSECRET" not in d and "user" not in d


@pytest.mark.parametrize("raw", [
    "javascript:alert(1)",
    "mailto:user@example.com",
    "//example.com/a",
    "https:/example.com",
    "https://h:99999/",
    "https://[::1/a",
    "",
])
def test_safe_display_ambiguous_is_placeholder(raw) -> None:
    assert safe_display(raw) == "<target>"
