"""Minimal stdlib HTTP plumbing shared by the two consoles."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


class Router(BaseHTTPRequestHandler):
    """Subclasses set `routes`: {(method, path): handler(payload) -> (status, body)}."""

    routes: dict[tuple[str, str], Callable] = {}
    page: str = ""
    server_version = "ratify-console"

    def log_message(self, fmt, *args):  # quiet; the consoles are the log
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            return self._send(200, self.page.encode("utf-8"), "text/html; charset=utf-8")
        self._dispatch("GET", None)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            return self._json(400, {"error": "invalid JSON body"})
        self._dispatch("POST", payload)

    def _dispatch(self, method: str, payload) -> None:
        path = self.path.split("?", 1)[0]
        handler = self.routes.get((method, path))
        if handler is None:
            return self._json(404, {"error": f"no route for {method} {path}"})
        try:
            status, body = handler(payload)
        except Exception as exc:  # surface the failure in the console, don't 500 silently
            return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
        self._json(status, body)


def serve(handler_cls, port: int, banner: str) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    print(banner)
    print(f"  http://localhost:{port}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
