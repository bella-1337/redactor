"""HTTP server for the PII review page (standard library only).

Routes:
  GET  /, /app.js, /app.css   the page (fixed files, no path lookup)
  GET  /health                liveness for Docker
  GET  /api/config            public limits and supported file types
  POST /api/analyze           detect personal data in pasted text (JSON)
  POST /api/analyze-document  detect personal data in an uploaded file (raw body;
                              X-File-Name gives the extension)
  POST /api/mask              mask the items the user selected (JSON)

Every POST route needs `Authorization: Bearer <LiteLLM virtual key>`, or in the
desktop app (PII_REVIEW_AUTH=local) the token it made for this run.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any, Callable, Mapping

from pii_review import __version__
from pii_review.review import (
    ASSIST_LANGUAGES,
    DOCUMENT_TYPES,
    AssistClient,
    TEXT_EXTENSIONS,
    KeyValidator,
    Presidio,
    RateLimiter,
    Reviewer,
    ReviewError,
    Settings,
    UpstreamError,
    XbergExtractor,
    settings_from_environment,
)

LOG = logging.getLogger("pii_review")

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

MAX_CONCURRENT_REQUESTS = 8
# The page renders at most this many characters of a text in its preview; the
# analysis and masking always cover the whole text.
PREVIEW_CHARS = 1_000_000


class Service:
    """Shared state for every request handler thread."""

    def __init__(
        self,
        settings: Settings,
        reviewer: Reviewer,
        validator: KeyValidator,
        static_loader: Callable[[str], bytes] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.reviewer = reviewer
        self.validator = validator
        self.key_limiter = RateLimiter(settings.requests_per_minute, clock)
        self.failed_auth_limiter = RateLimiter(settings.failed_auth_per_minute, clock)
        self.slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self.static_loader = static_loader or (
            lambda name: resources.files("pii_review").joinpath("static", name).read_bytes()
        )

    def public_config(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "language": self.settings.language,
            "languages": list(ASSIST_LANGUAGES),
            "language_detection": self.reviewer.assist is not None,
            "preview_chars": PREVIEW_CHARS,
            "max_text_bytes": self.settings.max_text_bytes,
            "max_file_bytes": self.settings.max_file_bytes,
            "documents": self.reviewer.extractor is not None,
            "text_extensions": sorted(TEXT_EXTENSIONS),
            "document_extensions": sorted(DOCUMENT_TYPES),
            "image_extensions": sorted(ext for ext, kind in DOCUMENT_TYPES.items() if kind.image),
            # The languages xberg/xberg-config.toml gives Tesseract.
            "ocr_languages": ["English", "German", "French"],
            "operators": ["replace", "mask", "redact"],
            # "local": the desktop app's window holds the token; no key prompt.
            "auth": self.settings.auth,
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "pii-review"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    service: Service  # set by make_server

    # -- plumbing -----------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence the default access log, which would print raw request lines."""

    def _route(self) -> str:
        path = self.path.split("?", 1)[0]
        known = {"/health", "/api/config", "/api/analyze", "/api/analyze-document", "/api/mask", *STATIC_FILES}
        return path if path in known else "other"

    def _send(self, status: int, body: bytes, content_type: str, *, cache: str = "no-store") -> None:
        self.send_response(status)
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._status = status

    def _json(self, status: int, payload: Mapping[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _client_ip(self) -> str:
        # Traefik is the only route in and ignores client-supplied forwarding
        # headers, so X-Real-Ip is the TCP peer it saw.
        return self.headers.get("X-Real-Ip") or self.client_address[0]

    def _timed(self, handler: Callable[[], None]) -> None:
        started = time.monotonic()
        self._status = 0
        if not self.service.slots.acquire(blocking=False):
            self.close_connection = True
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "The service is busy. Try again in a moment.")
        else:
            try:
                handler()
            except Exception as error:  # never leak details to the caller
                LOG.error("unhandled %s on %s", type(error).__name__, self._route())
                if not self._status:
                    self.close_connection = True
                    self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Something went wrong.")
            finally:
                self.service.slots.release()
        if self._route() != "/health":
            LOG.info(
                "%s %s %s %dms",
                self.command,
                self._route(),
                self._status,
                (time.monotonic() - started) * 1000,
            )

    # -- methods ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._timed(self._get)

    def do_HEAD(self) -> None:  # noqa: N802
        self._timed(self._get)

    def do_POST(self) -> None:  # noqa: N802
        self._timed(self._post)

    def _method_not_allowed(self) -> None:
        self.close_connection = True
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed.")

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = lambda self: self._timed(self._method_not_allowed)  # noqa: E731

    def _get(self) -> None:
        route = self._route()
        if route == "/health":
            self._json(HTTPStatus.OK, {"status": "ok"})
        elif route == "/api/config":
            self._json(HTTPStatus.OK, self.service.public_config())
        elif route in STATIC_FILES:
            name, content_type = STATIC_FILES[route]
            self._send(HTTPStatus.OK, self.service.static_loader(name), content_type, cache="no-cache")
        else:
            self._error(HTTPStatus.NOT_FOUND, "Not found.")

    def _read_json(self) -> Mapping[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ReviewError("Send JSON.", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        length_header = self.headers.get("Content-Length")
        if length_header is None or not length_header.isdigit():
            raise ReviewError("Content-Length is required.", HTTPStatus.LENGTH_REQUIRED)
        length = int(length_header)
        if length > self.service.settings.max_body_bytes:
            raise ReviewError("The request is too large.", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError) as error:
            raise ReviewError("The request is not valid JSON.") from error
        if not isinstance(payload, dict):
            raise ReviewError("The request is not valid JSON.")
        return payload

    def _read_upload(self) -> tuple[str, bytearray]:
        """Read a raw file upload in chunks, refusing it from Content-Length if too large."""
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/octet-stream":
            raise ReviewError("Send the file as application/octet-stream.", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        filename = urllib.parse.unquote(self.headers.get("X-File-Name", ""))
        length_header = self.headers.get("Content-Length")
        if length_header is None or not length_header.isdigit():
            raise ReviewError("Content-Length is required.", HTTPStatus.LENGTH_REQUIRED)
        length = int(length_header)
        limit = self.service.settings.max_file_bytes
        if length > limit:
            raise ReviewError(
                f"The document is {length // 1048576} MiB; the limit is {limit // 1048576} MiB.",
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
        data = bytearray(length)
        view = memoryview(data)
        received = 0
        while received < length:
            count = self.rfile.readinto(view[received : received + 1048576])
            if not count:
                raise ReviewError("The upload was interrupted.")
            received += count
        view.release()
        return filename, data

    def _authenticate(self) -> str | None:
        """Return the caller's key fingerprint, or answer the request and return None."""
        client = self._client_ip()
        header = self.headers.get("Authorization", "")
        scheme, _, key = header.partition(" ")
        local = self.service.settings.auth == "local"
        if scheme.lower() != "bearer" or not key.strip():
            self._error(
                HTTPStatus.UNAUTHORIZED,
                "This window lost its session. Restart PII Review." if local else "Enter your LiteLLM virtual key.",
            )
            return None
        key = key.strip()
        # Only rejected keys count, so users sharing one NAT address are not
        # throttled by each other's normal use.
        if self.service.failed_auth_limiter.exceeded(client):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "Too many rejected keys. Wait a minute.")
            return None
        accepted = self.service.validator.check(key)
        if accepted is None:
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "The gateway is unavailable. Try again later.")
            return None
        if not accepted:
            self.service.failed_auth_limiter.allow(client)
            LOG.warning("rejected a key")
            self._error(
                HTTPStatus.UNAUTHORIZED,
                "This window lost its session. Restart PII Review." if local else "The key was not accepted.",
            )
            return None
        return self.service.validator.fingerprint(key)

    def _post(self) -> None:
        route = self._route()
        if route not in {"/api/analyze", "/api/analyze-document", "/api/mask"}:
            self.close_connection = True
            self._error(HTTPStatus.NOT_FOUND, "Not found.")
            return
        # Reject unauthenticated callers before reading a large body.
        fingerprint = self._authenticate()
        if fingerprint is None:
            self.close_connection = True
            return
        if not self.service.key_limiter.allow(fingerprint):
            self.close_connection = True
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "Too many requests for this key. Wait a minute.")
            return
        try:
            if route == "/api/analyze-document":
                filename, data = self._read_upload()
                result = self.service.reviewer.analyze_document(filename, data)
                del data
            elif route == "/api/analyze":
                result = self.service.reviewer.analyze(self._read_json())
            else:
                result = self.service.reviewer.mask(self._read_json())
        except ReviewError as error:
            self.close_connection = True
            self._error(error.status, str(error))
            return
        except UpstreamError as error:
            LOG.error("%s failed: %s", route, error)
            self._error(HTTPStatus.BAD_GATEWAY, "A masking service is unavailable. Try again later.")
            return
        self._json(HTTPStatus.OK, result)


def build_service(settings: Settings) -> Service:
    reviewer = Reviewer(
        settings=settings,
        presidio=Presidio(settings),
        extractor=XbergExtractor(settings.xberg_url, timeout=settings.xberg_timeout) if settings.xberg_url else None,
        assist=AssistClient(settings) if settings.assist_url else None,
    )
    return Service(settings, reviewer, KeyValidator(settings.gateways))


def make_server(service: Service, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"service": service})
    server = ThreadingHTTPServer((host, service.settings.port), handler)
    server.daemon_threads = True
    return server


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        settings = settings_from_environment()
    except ValueError as error:
        LOG.error("invalid configuration: %s", error)
        return 2
    if settings.auth != "gateway":
        LOG.error("invalid configuration: PII_REVIEW_AUTH=local is for the desktop app (python -m pii_review.desktop)")
        return 2
    server = make_server(build_service(settings))
    LOG.info(
        "listening on port %d; %d gateway(s); documents %s; local-model assist %s",
        settings.port,
        len(settings.gateways),
        "enabled" if settings.xberg_url else "disabled",
        "enabled" if settings.assist_url else "disabled",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
