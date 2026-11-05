"""Response exposes the raw (body-capped) bytes, the encoding used to decode
``text``, and whether the body was truncated at ``max_body_bytes`` — so a caller
can measure an exact byte length or strict-decode instead of approximating from
``text`` (issue #2)."""

from __future__ import annotations

import pytest

from wp_detect.http import Client
from wp_detect.testing import BaseHandler, serve


def _serve_bytes(raw: bytes, ctype: str = "text/plain; charset=utf-8"):
    class _H(BaseHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return _H


def _get(handler, **client_kw):
    server, url = serve(handler)
    try:
        with Client(url, delay=0, verify_tls=False, **client_kw) as c:
            return c.get("/")
    finally:
        server.shutdown()


def test_content_and_encoding_exposed() -> None:
    resp = _get(_serve_bytes(b"hello bytes"))
    assert resp.content == b"hello bytes"
    assert resp.text == "hello bytes"
    assert (resp.encoding or "").lower() == "utf-8"
    assert resp.truncated is False
    # exact byte length is now available without re-encoding text
    assert len(resp.content) == 11


def test_non_utf8_bytes_preserved_for_strict_decode() -> None:
    raw = b"\xff\xfe raw \x80 bytes"
    resp = _get(_serve_bytes(raw, ctype="text/plain; charset=utf-8"))
    assert resp.content == raw                 # raw bytes preserved exactly
    assert "�" in resp.text               # text is the defensive (replace) decode
    with pytest.raises(UnicodeDecodeError):    # caller can strict-decode and detect the failure
        resp.content.decode("utf-8")


def test_truncation_keeps_exactly_the_first_cap_bytes() -> None:
    # Over the cap: keep exactly the first max_body_bytes (not an empty content
    # from dropping the whole over-cap chunk), and flag truncation.
    resp = _get(_serve_bytes(b"A" * 5000), max_body_bytes=1000)
    assert resp.truncated is True
    assert resp.content == b"A" * 1000         # exact prefix retained, not b""
    assert resp.text == "A" * 1000

    # Just one byte over the cap -> still capped to exactly the cap.
    over1 = _get(_serve_bytes(b"A" * 1001), max_body_bytes=1000)
    assert over1.truncated is True and over1.content == b"A" * 1000

    # Exactly at the cap -> whole body, not truncated.
    at = _get(_serve_bytes(b"A" * 1000), max_body_bytes=1000)
    assert at.truncated is False and at.content == b"A" * 1000

    # Under the cap -> whole body, not truncated.
    under = _get(_serve_bytes(b"A" * 100), max_body_bytes=1000)
    assert under.truncated is False and under.content == b"A" * 100


def test_defaults_are_backward_compatible() -> None:
    # The new fields default so existing Response constructions still work.
    from wp_detect.http import Response

    r = Response(url="https://x/", status=200, headers={}, text="", elapsed=0.0)
    assert r.content == b"" and r.encoding is None and r.truncated is False
