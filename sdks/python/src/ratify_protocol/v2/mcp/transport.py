"""HTTPS to the pinned endpoint only.

- https only, certificate and hostname verification on;
- the host, port and paths come from the pin, never from a response;
- no redirects are followed (any 3xx is an error);
- no proxy auto-discovery: only an ``HTTPS_PROXY`` environment variable is
  honoured (CONNECT tunnel; TLS is still verified against the pinned host).
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.request
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from .._version import __version__
from .errors import TransportError

MAX_RESPONSE_BYTES = 8 << 20
TIMEOUT_SECONDS = 30.0


@dataclass
class Response:
    status: int
    headers: dict
    message: Optional[dict]


def parse_body(content_type: str, body: bytes) -> Optional[dict]:
    """Return the single JSON message carried by an application/json or
    text/event-stream body. ``None`` for an empty body."""
    if not body.strip():
        return None
    media = content_type.split(";", 1)[0].strip().lower()
    if media == "application/json":
        text = body.decode("utf-8")
    elif media == "text/event-stream":
        text = _first_sse_data(body.decode("utf-8"))
        if text is None:
            raise TransportError("event stream carried no message")
    else:
        raise TransportError("unexpected response content type")
    try:
        msg = json.loads(text)
    except ValueError:
        raise TransportError("response is not valid JSON") from None
    if not isinstance(msg, dict):
        raise TransportError("response is not a JSON object")
    return msg


def _first_sse_data(text: str) -> Optional[str]:
    data: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            if data:
                return "\n".join(data)
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            data.append(value)
    return "\n".join(data) if data else None


class HttpsClient:
    def __init__(self, endpoint: str, *, ca_file: Optional[str] = None, timeout: float = TIMEOUT_SECONDS):
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.hostname:
            raise TransportError("endpoint must be https")
        self.host = parts.hostname
        self.port = parts.port or 443
        self.timeout = timeout
        # ca_file is for tests against a local server; production uses the
        # platform trust store.
        self.context = ssl.create_default_context(cafile=ca_file)
        self.context.check_hostname = True
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def _connection(self) -> http.client.HTTPSConnection:
        proxies = urllib.request.getproxies_environment()
        proxy = proxies.get("https")
        if proxy and not urllib.request.proxy_bypass_environment(self.host, proxies):
            p = urlsplit(proxy if "://" in proxy else "http://" + proxy)
            if p.scheme != "http" or not p.hostname:
                raise TransportError("HTTPS_PROXY must be an http:// proxy URL")
            conn = http.client.HTTPSConnection(p.hostname, p.port or 8080, timeout=self.timeout,
                                               context=self.context)
            conn.set_tunnel(self.host, self.port)
            return conn
        return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)

    def post(self, path: str, body: bytes, headers: dict) -> Response:
        all_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"ratify-mcp-signer/{__version__}",
        }
        all_headers.update(headers)
        conn = self._connection()
        try:
            try:
                conn.request("POST", path, body=body, headers=all_headers)
                resp = conn.getresponse()
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
            except ssl.SSLError:
                raise TransportError("TLS verification of the hosted endpoint failed") from None
            except (OSError, http.client.HTTPException):
                raise TransportError("could not reach the hosted endpoint") from None
        finally:
            conn.close()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TransportError("response too large")
        if 300 <= resp.status < 400:
            raise TransportError(f"hosted endpoint answered with a redirect (HTTP {resp.status}); redirects are not followed")
        headers_out = {k.lower(): v for k, v in resp.getheaders()}
        try:
            msg = parse_body(headers_out.get("content-type", ""), raw)
        except UnicodeDecodeError:
            raise TransportError("response is not UTF-8") from None
        return Response(resp.status, headers_out, msg)
