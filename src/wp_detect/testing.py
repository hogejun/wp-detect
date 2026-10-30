"""Reusable in-process mock servers for testing checks.

This module is part of the public API: a plugin author can start a mock
WordPress site and point a :class:`wp_detect.http.Client` at it to exercise a
custom check without any external I/O.

``WordPressHandler`` serves the minimal signals the built-in ``detect`` and
``headers`` checks look for. A plugin (or the private overlay) subclasses it to
add its own routes/behaviours, or uses :func:`wordpress_app` for simple
GET-only extensions, then runs it with :func:`serve`.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# -- minimal response bodies --------------------------------------------
HOME = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-content/themes/lightning/style.css">
<script src="/wp-includes/js/wp-emoji-release.min.js"></script>
</head><body>hello wp-json</body></html>"""
REST_ROOT = '{"namespaces":["oembed/1.0","wp/v2"]}'
README = "<html><body><h1>WordPress</h1> Version 6.4.2 </body></html>"


class BaseHandler(BaseHTTPRequestHandler):
    """Quiet handler with a small ``_send`` helper."""

    def log_message(self, *a):  # silence test output
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


class WordPressHandler(BaseHandler):
    """A minimal WordPress site: detection markers + a couple of headers.

    Subclass and extend ``ROUTES`` / ``HOME_HEADERS`` (and override
    ``do_GET``/``do_POST``/``do_OPTIONS`` for richer behaviour)."""

    HOME = HOME
    HOME_HEADERS = {
        "X-Pingback": "https://x/xmlrpc.php",
        "Set-Cookie": "wordpress_test_cookie=WP; path=/",
    }
    ROUTES = {
        "/wp-json/": (200, REST_ROOT, "application/json"),
        "/readme.html": (200, README, "text/html"),
    }

    def do_GET(self):
        p = self.path
        if p == "/" or p.startswith("/?"):
            return self._send(200, self.HOME, headers=self.HOME_HEADERS)
        if p in self.ROUTES:
            code, body, ctype = self.ROUTES[p]
            return self._send(code, body, ctype)
        return self._send(404, "not found")


class PlainHandler(BaseHandler):
    """A non-WordPress site: everything is a soft 200 HTML page."""

    def do_GET(self):
        return self._send(200, "<!doctype html><html><body>just a site</body></html>")


def wordpress_app(extra_routes=None, extra_headers=None):
    """Return a :class:`WordPressHandler` subclass with extra GET routes and/or
    home headers merged in (for simple, GET-only extensions)."""
    return type(
        "CustomWordPressHandler",
        (WordPressHandler,),
        {
            "ROUTES": {**WordPressHandler.ROUTES, **(extra_routes or {})},
            "HOME_HEADERS": {**WordPressHandler.HOME_HEADERS, **(extra_headers or {})},
        },
    )


def serve(handler_cls) -> tuple[ThreadingHTTPServer, str]:
    """Start ``handler_cls`` on an ephemeral localhost port. Returns
    ``(server, base_url)``; call ``server.shutdown()`` when done."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"
