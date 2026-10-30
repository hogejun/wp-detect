"""Thin HTTP client used by every check.

Design goals:
  * **Benign by default.** All requests are plain GET/HEAD. We never POST
    payloads. The User-Agent defaults to a common browser (Chrome) so scans
    are not blanket-blocked by UA filters; `--user-agent wp-detect` sends the
    honest tool UA, and any custom string is accepted verbatim.
  * **Stays on the target.** Redirects are resolved by us, not httpx, and are
    followed only within the initial target's origin (same scheme, host and
    port). A redirect that points elsewhere — or a request whose path resolves
    off-origin — is refused rather than followed, so a scan of one site never
    silently reaches out to another (an SSRF/scope-escape guard).
  * **Low impact.** A global request budget and a small inter-request delay
    keep the scanner from hammering a site; every redirect hop counts against
    the budget and is throttled too. This is a *detector*, not a stress tool.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import ParseResult, urljoin, urlparse

import httpx

# The honest tool UA, available via `--user-agent wp-detect`.
WP_DETECT_UA = "wp-detect/0.1 (security-detection)"

# Convenience aliases for `--user-agent`: a short name expands to a realistic
# browser UA string (any other value is used verbatim).
USER_AGENT_ALIASES = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
    "Gecko/20100101 Firefox/127.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0",
    "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "android": "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
    "wp-detect": WP_DETECT_UA,
}

# Default: a common browser UA (Chrome), so scans are not blanket-blocked by
# UA filters. Use `--user-agent wp-detect` for the honest tool identifier.
DEFAULT_USER_AGENT = USER_AGENT_ALIASES["chrome"]


def resolve_user_agent(value: str | None) -> str | None:
    """Expand a known alias (case-insensitive) to a full UA; else return as-is."""
    if value is None:
        return None
    return USER_AGENT_ALIASES.get(value.lower(), value)


class BudgetExceeded(RuntimeError):
    """Raised when the configured request budget is exhausted."""


class OffOriginRedirect(RuntimeError):
    """A request or redirect targeted an origin other than the initial target
    (or used a non-HTTP(S) scheme or embedded userinfo). We refuse to send it,
    so a scan cannot be bounced to a host it was never pointed at."""


class TooManyRedirects(RuntimeError):
    """The redirect chain exceeded the hop limit or looped back on itself."""


# 3xx statuses that carry a Location we may follow (same-origin only).
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


def _normalize_host(host: str) -> str:
    """IDNA-encode so unicode and punycode spellings of a name compare equal.
    ``urlparse`` already lower-cases the host; IPs/ASCII pass through."""
    if not host:
        return host
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host


def _origin(url: str) -> tuple[str, str, int]:
    """Return ``(scheme, host, port)`` with default ports applied. Raises
    :class:`OffOriginRedirect` for a non-HTTP(S) scheme or any userinfo.

    Error messages are fixed, secret-free reasons and never echo ``url`` — it
    may carry credentials (userinfo), a token in the query, or a path that is
    itself sensitive, and the exception string can be transcribed into a log,
    a Finding ``error`` or a JSON snapshot."""
    p = urlparse(url)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise OffOriginRedirect("unsupported URL scheme (only http/https allowed)")
    # ``is not None`` (not truthiness): an empty userinfo (``https://@h/`` or
    # ``https://:@h/``) is still userinfo — urlparse yields "" there, which a
    # truthy test would miss.
    if p.username is not None or p.password is not None:
        raise OffOriginRedirect("URL must not contain credentials (userinfo)")
    host = _normalize_host(p.hostname or "")
    if not host:
        raise OffOriginRedirect("URL is missing a host")
    # An out-of-range port makes urlparse raise ValueError on .port; normalize
    # it to the same refusal rather than letting a raw ValueError escape.
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise OffOriginRedirect("URL has an invalid port") from None
    return (scheme, host, port)


# Forbidden anywhere in a target: ASCII controls (incl. newline/NUL/tab),
# space (0x20), DEL (0x7f) and backslash. Rejecting these outright keeps a
# smuggled separator or whitespace out of the parsed authority.
_FORBIDDEN_RE = re.compile(r"[\x00-\x20\x7f\\]")
# An explicit scheme followed by an authority: ``scheme://…``.
_SCHEME_AUTHORITY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
# An explicit scheme with no authority marker: ``scheme:…`` (also matches a
# bare ``host:port`` because a dot is a valid scheme char — disambiguated by
# _HOSTPORT_AFTER_COLON_RE, which only treats ``:<digits>`` as a port).
_SCHEME_ONLY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_HOSTPORT_AFTER_COLON_RE = re.compile(r"^\d+(?:/|$)")


def _prepare_url(raw: object) -> ParseResult:
    """Shared, non-public URL preparation for :func:`normalize_target` and
    :func:`safe_display`. Determines the scheme *without* the ambiguous
    ``"//" in raw`` heuristic, validates the string and authority, and returns
    a ``urlparse`` result whose scheme is a lower-cased ``http``/``https``.

    Raises :class:`ValueError` (secret-free — the message never echoes the
    input, a path, a query, a fragment or userinfo) for anything invalid or
    ambiguous: a non-string/empty input, forbidden characters, a literal
    ``?``/``#`` (even empty), a scheme-relative ``//…``, a non-HTTP(S) or
    ``//``-less scheme (``http:x``, ``https:/x``, ``mailto:``, ``javascript:``),
    userinfo, a missing host, an out-of-range/invalid port, or a malformed
    authority (e.g. an unclosed IPv6 bracket).
    """
    if not isinstance(raw, str) or raw == "":
        raise ValueError("target must be a non-empty string")
    if _FORBIDDEN_RE.search(raw):
        raise ValueError("target contains control characters, spaces or backslashes")
    # A literal ?/# is a query/fragment delimiter even when empty; only the
    # percent-encoded forms (%3F/%23) are allowed inside a path. Judged on the
    # raw input so a trailing "a?" or "a#" is rejected too.
    if "?" in raw or "#" in raw:
        raise ValueError("a query string or fragment is not allowed in a target URL")
    if raw.startswith("//"):
        raise ValueError("scheme-relative URL is not allowed")

    m = _SCHEME_AUTHORITY_RE.match(raw)
    if m:
        if m.group(1).lower() not in ("http", "https"):
            raise ValueError("target must be an http(s) URL")
        candidate = raw
    else:
        m2 = _SCHEME_ONLY_RE.match(raw)
        if m2 and not _HOSTPORT_AFTER_COLON_RE.match(raw[m2.end():]):
            # An explicit scheme with no authority that is not a bare
            # host:port — never HTTPS-complete these (http:x, https:/x,
            # mailto:…, javascript:…).
            raise ValueError("target must be an http(s) URL")
        # Scheme omitted (including a bare ``host:port``): default to https.
        candidate = "https://" + raw

    try:
        parsed = urlparse(candidate)
        username, password, hostname = parsed.username, parsed.password, parsed.hostname
    except ValueError:
        # Malformed authority (e.g. an unclosed IPv6 bracket) — normalize the
        # raw ValueError to a secret-free one.
        raise ValueError("target is not a valid URL") from None
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("target must be an http(s) URL")
    # ``is not None`` (not truthiness): an empty userinfo (``https://@h/`` or
    # ``https://:@h/``) is still userinfo — urlparse yields "" there whenever an
    # ``@`` is present, which a truthy test would let through.
    if username is not None or password is not None:
        raise ValueError("credentials (userinfo) are not allowed in a target URL")
    if not hostname:
        raise ValueError("target is missing a host")
    try:
        parsed.port  # noqa: B018 — accessing .port validates the range
    except ValueError:
        raise ValueError("target has an invalid port") from None
    return parsed._replace(scheme=parsed.scheme.lower())


def normalize_target(raw: str) -> str:
    """Validate and normalize a scan-target URL, secret-safe.

    Accepts a plain ``http(s)`` URL; the scheme is optional and defaults to
    ``https`` (a bare ``host:port`` is treated as host+port, not a scheme).
    Rejects embedded credentials (userinfo), a query string or fragment (even
    an empty ``?``/``#``), control characters/whitespace/backslashes, a
    ``//``-less or non-HTTP(S) scheme, and an out-of-range port. Error messages
    never echo the raw URL, which may itself carry a secret (``?token=…``). The
    existing path (including any ``//``) and trailing slash are preserved.
    """
    return _prepare_url(raw).geturl()


def safe_display(url: object) -> str:
    """A log-safe rendering of a target: ``scheme://host[:port]`` only, with no
    path, query, fragment or credentials (so a secret in any of those is never
    printed). An IPv6 host keeps its brackets.

    This is *not* a validator substitute: an invalid or ambiguous input yields
    the fixed placeholder ``<target>`` rather than a guessed/"repaired" URL,
    and no exception escapes.
    """
    try:
        p = _prepare_url(url)
    except ValueError:
        return "<target>"
    host = p.hostname or ""
    if ":" in host:  # IPv6 literal — keep the brackets for display
        host = f"[{host}]"
    try:
        port = p.port
    except ValueError:  # pragma: no cover — _prepare_url already validated it
        port = None
    suffix = f":{port}" if port else ""
    return f"{p.scheme}://{host}{suffix}"


@dataclass(slots=True)
class Response:
    """Normalized, trimmed view of an HTTP response.

    We keep only what checks need and cap the body so a misbehaving target
    cannot blow up memory.
    """

    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float
    # Raw Set-Cookie lines, preserved individually (a dict would collapse them).
    set_cookies: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Client:
    """A small, polite wrapper over :class:`httpx.Client`."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        delay: float = 0.3,
        max_requests: int = 200,
        max_redirects: int = 5,
        verify_tls: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        max_body_bytes: int = 1_000_000,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.host = urlparse(self.base_url).netloc
        # The origin every request/redirect must stay within.
        self._origin = _origin(self.base_url)
        self.delay = delay
        self.max_requests = max_requests
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self.request_count = 0
        self._last_request = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_tls,
            # Do not silently route scans through a proxy picked up from the
            # environment (HTTP_PROXY/HTTPS_PROXY/NO_PROXY); a scan must go where
            # it was pointed. A proxy, if ever needed, should be an explicit opt-in.
            trust_env=False,
            # We resolve redirects ourselves so we can enforce the origin and
            # count/throttle each hop; httpx must not follow them silently.
            follow_redirects=False,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=5),
            transport=transport,
        )

    # -- context manager -------------------------------------------------
    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # -- core request ----------------------------------------------------
    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        wait = self.delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)

    def request(self, method: str, path: str) -> Response:
        """Issue one request against ``path`` (relative to the base URL)."""
        return self._send(method, path)

    def request_body(
        self, method: str, path: str, body: str, *, content_type: str
    ) -> Response:
        """Issue a request carrying a body.

        Used only for benign, action-free probes such as XML-RPC
        ``system.listMethods``. The caller is responsible for keeping the body
        harmless; nothing in this package sends a payload that changes state.
        """
        return self._send(method, path, body=body, content_type=content_type)

    def _check_origin(self, url: str) -> None:
        """Refuse to send a request whose URL leaves the initial target's
        origin (or uses a forbidden scheme/userinfo).

        The message embeds neither the rejected URL (which may carry a token in
        its query/path/fragment or credentials in its userinfo) nor the target
        origin tuple — a fixed reason only."""
        if _origin(url) != self._origin:
            raise OffOriginRedirect("refusing off-origin request")

    def _send(
        self,
        method: str,
        path: str,
        *,
        body: str | None = None,
        content_type: str | None = None,
    ) -> Response:
        # Resolve the target against the base URL. A ``path`` that resolves off
        # the target's origin (e.g. an absolute "https://other/…") is refused
        # before anything is sent.
        url = urljoin(self.base_url, path.lstrip("/"))
        self._check_origin(url)
        content = body.encode("utf-8") if body is not None else None
        visited = {url}
        hops = 0

        while True:
            if self.request_count >= self.max_requests:
                raise BudgetExceeded(
                    f"request budget of {self.max_requests} exhausted"
                )
            self._throttle()
            self.request_count += 1
            start = time.monotonic()
            headers = {"Content-Type": content_type} if content_type else None
            with self._client.stream(
                method, url, content=content, headers=headers
            ) as resp:
                status = resp.status_code
                location = resp.headers.get("location")
                if status in _REDIRECT_CODES and location:
                    # A redirect: don't download its body, just note the target.
                    self._last_request = time.monotonic()
                    hops += 1
                    if hops > self.max_redirects:
                        # Neither the request path nor the redirect target is
                        # echoed — a Location/path may carry a token.
                        raise TooManyRedirects(
                            f"exceeded {self.max_redirects} redirects"
                        )
                    next_url = urljoin(url, location)
                    self._check_origin(next_url)
                    if next_url in visited:
                        raise TooManyRedirects("redirect loop detected")
                    visited.add(next_url)
                    # Never replay a body across a redirect; 303 forces GET.
                    if content is not None or status == 303:
                        method = "GET"
                        content = None
                        content_type = None
                    url = next_url
                    continue

                # Final response: read the body, capped.
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total <= self.max_body_bytes:
                        chunks.append(chunk)
                    else:
                        break
                data = b"".join(chunks)
                elapsed = time.monotonic() - start
                self._last_request = time.monotonic()
                # Decode defensively; sites lie about encodings.
                text = data.decode(resp.encoding or "utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                # Preserve each Set-Cookie line (the dict above keeps only one).
                set_cookies = list(resp.headers.get_list("set-cookie"))
                return Response(
                    url=str(resp.url),
                    status=status,
                    headers=resp_headers,
                    text=text,
                    elapsed=elapsed,
                    set_cookies=set_cookies,
                )

    def get(self, path: str) -> Response:
        return self.request("GET", path)

    def head(self, path: str) -> Response:
        return self.request("HEAD", path)
