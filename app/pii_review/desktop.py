"""Desktop entry point: the page, Presidio, and Xberg in one app, for one user.

The Tauri shell (desktop/src-tauri) starts this with the bundled interpreter:

    python -I -m pii_review.desktop --resources <dir> [--settings <file>]

and talks to it over stdin and stdout only:

- stdout carries one JSON object per line: {"status": "..."} while starting,
  then {"port": N, "token": "..."} once the page answers on 127.0.0.1:N, or
  {"error": "..."} if it cannot start. Logs go to stderr and name no content.
- When stdin closes (the app quit or crashed), Xberg is stopped and this exits.

Differences from the compose deployment:

- Presidio's analyzer and anonymizer run in this process (`InProcessPresidio`),
  answering the same JSON as their REST APIs, so `review.Presidio` is unchanged.
- Xberg runs as a child process on a free 127.0.0.1 port. It has the host's
  network, not an internal one; its configuration still refuses local paths
  and file URIs, and its caches go to a temporary directory removed on exit.
- No LiteLLM key: every API call needs a random token made for this run, which
  only the app's own window receives. Set PII_REVIEW_GATEWAYS in the settings
  file to require LiteLLM keys instead.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping

from pii_review.review import (
    AssistClient,
    Body,
    HttpResponse,
    KeyValidator,
    LocalTokenValidator,
    Presidio,
    Reviewer,
    Settings,
    Transport,
    XbergExtractor,
    settings_from_environment,
)
from pii_review.server import Service, make_server

LOG = logging.getLogger("pii_review.desktop")

# Presidio's endpoints inside this process; `InProcessPresidio` answers them.
ANALYZER_URL = "http://analyzer.in-process.invalid"
ANONYMIZER_URL = "http://anonymizer.in-process.invalid"

# Settings a user may change in the settings file (or the environment). The
# service URLs, port, and authentication mode are the app's own.
USER_SETTINGS = frozenset(
    {
        "PII_REVIEW_GATEWAYS",
        "PII_REVIEW_LANGUAGE",
        "PII_REVIEW_MAX_TEXT_BYTES",
        "PII_REVIEW_MAX_FILE_BYTES",
        "PII_REVIEW_XBERG_TIMEOUT_SECONDS",
        "PII_REVIEW_REQUESTS_PER_MINUTE",
        "PII_REVIEW_ANALYZE_PARALLEL",
        "PII_REVIEW_ASSIST_URL",
        "PII_REVIEW_ASSIST_MODEL",
        "PII_REVIEW_ASSIST_KEY",
        "PII_REVIEW_ASSIST_MAX_CALLS",
    }
)

XBERG_START_SECONDS = 60


class Stopping(Exception):
    """The app quit while the engine was starting."""

# 250 MiB: the largest upload plus multipart framing (as in compose.yml).
XBERG_MAX_BODY_BYTES = "262144000"


def emit(**message: Any) -> None:
    """Write one protocol line for the shell."""
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def read_settings_file(path: Path | None) -> dict[str, str]:
    """KEY=VALUE lines, as in .env.example; comments and unknown keys are ignored."""
    if path is None or not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in USER_SETTINGS:
            values[key] = value.strip().strip('"').strip("'")
        else:
            LOG.warning("settings file: ignoring %s", key[:64])
    return values


def desktop_settings(
    settings_file: Path | None, xberg_url: str, environ: Mapping[str, str] = os.environ
) -> Settings:
    """The user's settings (environment over file), with the app's own services and port."""
    values = read_settings_file(settings_file)
    values.update({key: value for key, value in environ.items() if key in USER_SETTINGS})
    gateways = values.get("PII_REVIEW_GATEWAYS", "").strip()
    values["PII_REVIEW_AUTH"] = "gateway" if gateways else "local"
    # One analysis at a time: the in-process analyzer serves one piece at once.
    values.setdefault("PII_REVIEW_ANALYZE_PARALLEL", "1")
    values["PII_REVIEW_ANALYZER_URL"] = ANALYZER_URL
    values["PII_REVIEW_ANONYMIZER_URL"] = ANONYMIZER_URL
    values["PII_REVIEW_XBERG_URL"] = xberg_url
    settings = settings_from_environment(values)
    # Port 0: the system picks a free port, reported to the shell.
    return replace(settings, port=0)


# ---------------------------------------------------------------------------
# Presidio in this process
# ---------------------------------------------------------------------------


def _offline_tldextract() -> None:
    """Presidio's email recognizer uses tldextract, which downloads the public
    suffix list and caches it in the user's home. Use its bundled copy instead."""
    import tldextract
    import tldextract.tldextract as module

    module.TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def load_presidio(config_dir: Path) -> tuple[Any, Any]:
    """Build the analyzer from the same three YAML files the compose analyzer mounts."""
    _offline_tldextract()
    from presidio_analyzer import AnalyzerEngineProvider
    from presidio_anonymizer import AnonymizerEngine

    for name in ("presidio-analyzer", "presidio-anonymizer", "presidio_analyzer", "presidio_anonymizer"):
        logging.getLogger(name).setLevel(logging.WARNING)
    analyzer = AnalyzerEngineProvider(
        analyzer_engine_conf_file=config_dir / "analyzer-engine.yaml",
        nlp_engine_conf_file=config_dir / "analyzer.yaml",
        recognizer_registry_conf_file=config_dir / "recognizers.yaml",
    ).create_engine()
    return analyzer, AnonymizerEngine()


class InProcessPresidio:
    """A `review.Transport` that answers Presidio's /analyze and /anonymize in this process.

    Requests and answers are the REST APIs' JSON, so `review.Presidio` parses
    them exactly as it parses the containers'. Any other URL is refused.
    """

    def __init__(self, analyzer: Any, anonymizer: Any) -> None:
        self.analyzer = analyzer
        self.anonymizer = anonymizer
        # spaCy pipelines are not documented as thread-safe.
        self._analyze_lock = threading.Lock()

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: Body, timeout: float
    ) -> HttpResponse:
        if method != "POST" or not isinstance(body, bytes):
            return HttpResponse(405, {}, b"{}")
        try:
            request = json.loads(body)
            if url == f"{ANALYZER_URL}/analyze":
                answer = self._analyze(request)
            elif url == f"{ANONYMIZER_URL}/anonymize":
                answer = self._anonymize(request)
            else:
                return HttpResponse(404, {}, b"{}")
        except Exception as error:  # the caller turns any non-200 into UpstreamError
            LOG.error("in-process presidio failed: %s", type(error).__name__)
            return HttpResponse(500, {}, b"{}")
        return HttpResponse(200, {"Content-Type": "application/json"}, answer.encode("utf-8"))

    def _analyze(self, request: Mapping[str, Any]) -> str:
        with self._analyze_lock:
            results = self.analyzer.analyze(text=request["text"], language=request["language"])
        return json.dumps(results, default=lambda item: item.to_dict(), sort_keys=True)

    def _anonymize(self, request: Mapping[str, Any]) -> str:
        from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor

        result = self.anonymizer.anonymize(
            text=request["text"],
            analyzer_results=AppEntitiesConvertor.analyzer_results_from_json(request.get("analyzer_results")),
            operators=AppEntitiesConvertor.operators_config_from_json(request.get("anonymizers")),
        )
        return result.to_json()


# ---------------------------------------------------------------------------
# Xberg
# ---------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class XbergProcess:
    """`xberg serve` on 127.0.0.1, with caches in a temporary directory."""

    def __init__(self, resources: Path) -> None:
        name = "xberg.exe" if os.name == "nt" else "xberg"
        self.binary = resources / "xberg" / name
        self.config = resources / "config" / "xberg.toml"
        self.tessdata = resources / "tessdata"
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.scratch = Path(tempfile.mkdtemp(prefix="pii-review-xberg-"))
        self.process: subprocess.Popen[bytes] | None = None
        # Once stopped (the app quit, even mid-start), Xberg never starts.
        self._lock = threading.Lock()
        self._stopped = False

    def environment(self) -> dict[str, str]:
        environment = {
            "RUST_LOG": os.environ.get("XBERG_LOG_LEVEL", "warn"),
            "TESSDATA_PREFIX": str(self.tessdata),
            "XBERG_CACHE_DIR": str(self.scratch / "cache"),
            "HF_HOME": str(self.scratch / "huggingface"),
            "HOME": str(self.scratch),
            "TMPDIR": str(self.scratch),
            "TEMP": str(self.scratch),
            "TMP": str(self.scratch),
            "XBERG_MAX_REQUEST_BODY_BYTES": XBERG_MAX_BODY_BYTES,
            "XBERG_MAX_MULTIPART_FIELD_BYTES": XBERG_MAX_BODY_BYTES,
            # Only this process calls the API; no browser origin needs it.
            "XBERG_CORS_ORIGINS": "http://pii-review.invalid",
        }
        # Windows needs these to start any process.
        for key in ("SYSTEMROOT", "WINDIR", "PATH"):
            if key in os.environ:
                environment[key] = os.environ[key]
        return environment

    def start(self) -> None:
        command = [
            str(self.binary), "serve",
            "--host", "127.0.0.1", "--port", str(self.port),
            "--config", str(self.config),
        ]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        with self._lock:
            if self._stopped:
                raise Stopping()
            self.process = subprocess.Popen(
                command,
                env=self.environment(),
                cwd=self.scratch,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=sys.stderr,
                creationflags=flags,
            )

    def wait_ready(self, seconds: float = XBERG_START_SECONDS) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(f"Xberg exited with code {self.process.returncode}")
            try:
                with urllib.request.urlopen(f"{self.url}/health", timeout=2) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.25)
        raise RuntimeError("Xberg did not start in time")

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(self.scratch, ignore_errors=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_desktop_service(
    settings: Settings, presidio_transport: Transport, token: str, validator: Any = None
) -> Service:
    reviewer = Reviewer(
        settings=settings,
        presidio=Presidio(settings, transport=presidio_transport),
        extractor=XbergExtractor(settings.xberg_url, timeout=settings.xberg_timeout),
        assist=AssistClient(settings) if settings.assist_url else None,
    )
    if validator is None:
        validator = LocalTokenValidator(token) if settings.auth == "local" else KeyValidator(settings.gateways)
    return Service(settings, reviewer, validator)


def wait_for_stdin_close(stop: Callable[[], None]) -> None:
    """Block until the shell closes stdin (it quit or crashed), then stop."""
    try:
        while sys.stdin.buffer.read(4096):
            pass
    except (OSError, ValueError):
        pass
    stop()


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    parser = argparse.ArgumentParser(prog="pii_review.desktop")
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--settings", type=Path)
    args = parser.parse_args(argv)
    resources: Path = args.resources.resolve()

    xberg = XbergProcess(resources)
    try:
        settings = desktop_settings(args.settings, xberg.url)
    except ValueError as error:
        emit(error=f"The settings file is not valid: {error}")
        return 2

    stopped = threading.Event()
    lock = threading.Lock()
    server_holder: list[Any] = []

    def stop() -> None:
        with lock:
            if stopped.is_set():
                return
            stopped.set()
            server = server_holder[0] if server_holder else None
        xberg.stop()
        if server is not None:
            # Returns once serve_forever has ended (immediately if it is about to start).
            server.shutdown()

    threading.Thread(target=wait_for_stdin_close, args=(stop,), name="stdin-watch", daemon=True).start()
    # serve_forever runs on the main thread, so a signal stops it from another one.
    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: threading.Thread(target=stop, daemon=True).start())

    try:
        emit(status="Starting the document reader…")
        xberg.start()
        emit(status="Loading the English, German, and French language models…")
        analyzer, anonymizer = load_presidio(resources / "config" / "presidio")
        xberg.wait_ready()
    except Stopping:
        return 0
    except Exception as error:
        if stopped.is_set():
            return 0
        LOG.error("start failed: %s: %s", type(error).__name__, error)
        emit(error="PII Review could not start its services. See the log for details.")
        stop()
        return 1

    token = secrets.token_urlsafe(32)
    server = make_server(build_desktop_service(settings, InProcessPresidio(analyzer, anonymizer), token), "127.0.0.1")
    with lock:
        if stopped.is_set():
            server.server_close()
            return 0
        server_holder.append(server)
    port = server.server_address[1]
    LOG.info(
        "listening on 127.0.0.1:%d; auth %s; local-model assist %s",
        port,
        settings.auth,
        "enabled" if settings.assist_url else "disabled",
    )
    emit(port=port, token=token if settings.auth == "local" else "")
    try:
        server.serve_forever()
    finally:
        server.server_close()
        stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
