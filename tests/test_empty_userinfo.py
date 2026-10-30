"""An *empty* userinfo (``https://@h/``, ``https://:@h/``) is still
userinfo and must be rejected by both the target validator (_prepare_url via
normalize_target/safe_display) and the client origin check (_origin). The
presence check uses ``is not None`` so an empty-string username/password (which
urlparse produces whenever an ``@`` is present) does not slip through a truthy
test.
"""

from __future__ import annotations

import httpx
import pytest

from wp_detect.http import (
    Client,
    OffOriginRedirect,
    _origin,
    normalize_target,
    safe_display,
)

# (raw, accepted)
CASES = [
    ("https://example.com/", True),
    ("https://@example.com/", False),
    ("https://:@example.com/", False),
    ("https://user@example.com/", False),
    ("https://:pass@example.com/", False),
    ("https://user:@example.com/", False),
    ("https://user:pass@example.com/", False),
    ("example.com/path", True),
]


@pytest.mark.parametrize("raw, ok", CASES, ids=[c[0] for c in CASES])
def test_normalize_target_userinfo(raw, ok) -> None:
    if ok:
        assert normalize_target(raw).startswith("https://")
    else:
        with pytest.raises(ValueError) as ei:
            normalize_target(raw)
        msg = str(ei.value)
        assert "pass" not in msg and "user" not in msg or "userinfo" in msg
        assert raw not in msg


@pytest.mark.parametrize("raw, ok", CASES, ids=[c[0] for c in CASES])
def test_safe_display_userinfo(raw, ok) -> None:
    d = safe_display(raw)
    if ok:
        assert d == "https://example.com"
    else:
        assert d == "<target>"


EMPTY_USERINFO = ["https://@example.com/", "https://:@example.com/"]


@pytest.mark.parametrize("raw", EMPTY_USERINFO)
def test_origin_rejects_empty_userinfo(raw) -> None:
    with pytest.raises(OffOriginRedirect) as ei:
        _origin(raw)
    assert raw not in str(ei.value)


def test_empty_userinfo_redirect_is_not_sent() -> None:
    """A redirect to a same-host URL that carries an (empty) userinfo must be
    refused before any request to it is sent."""
    seen: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path == "/a":
            return httpx.Response(302, headers={"Location": "https://@site.test/b"})
        return httpx.Response(200, text="SHOULD NOT REACH")

    with Client("https://site.test/", delay=0, transport=httpx.MockTransport(record)) as c:
        with pytest.raises(OffOriginRedirect):
            c.get("/a")
    assert seen == ["https://site.test/a"]  # the userinfo target was never sent
