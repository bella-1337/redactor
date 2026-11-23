"""Analysis, masking, document extraction, and key checks for the PII review tool.

Everything here runs in memory. Request text, detected values, file contents,
and keys are never logged; log lines name only the operation and its outcome.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

LOG = logging.getLogger("pii_review")

# All text is analysed, in pieces: Presidio's analyzer holds a whole spaCy
# document in memory, and one 1.5 MB text exhausted a 2 GiB analyzer, so no
# request to it carries more than ANALYZE_CHUNK_BYTES.
ANALYZE_CHUNK_BYTES = 100_000
# Characters re-read at each piece boundary, so an entity split by a boundary is
# still found whole.
ANALYZE_OVERLAP_CHARS = 200
# Text per anonymizer request: well inside its 30-second worker timeout.
ANONYMIZE_SEGMENT_CHARS = 25_000
MAX_TEXT_BYTES_LIMIT = 250_000_000
# Uploads go to Xberg's API as multipart bodies; compose.yml allows 250 MiB
# there, which leaves room for the multipart framing.
MAX_FILE_BYTES_LIMIT = 250_000_000
DEFAULT_MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_SELECTIONS = 1_000_000
MAX_CUSTOM_TERMS = 50
MAX_CUSTOM_TERM_CHARS = 200
CUSTOM_TERM_ENTITY = "CUSTOM_TERM"
DEFAULT_OPERATOR_KEY = "DEFAULT"

ENTITY_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
LANGUAGE_RE = re.compile(r"[a-z]{2}")
# Printable ASCII without spaces: rules out header injection and absurd sizes.
API_KEY_RE = re.compile(r"[\x21-\x7e]{8,4096}")
ASSIST_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")

OPERATORS: dict[str, Callable[[str], dict[str, Any]]] = {
    # Same placeholder the gateway's presidio-pii guardrail writes.
    "replace": lambda entity: {"type": "replace", "new_value": f"<{entity}>"},
    "mask": lambda _entity: {
        "type": "mask",
        "masking_char": "*",
        "chars_to_mask": 1_000_000,
        "from_end": False,
    },
    "redact": lambda _entity: {"type": "redact"},
}

TEXT_EXTENSIONS = frozenset({".txt", ".md", ".csv", ".tsv", ".json", ".log"})
ZIP_MAGIC = (b"PK\x03\x04",)


@dataclass(frozen=True)
class DocumentType:
    mime_type: str
    magic: tuple[bytes, ...] = ()
    text_like: bool = False


DOCUMENT_TYPES: Mapping[str, DocumentType] = {
    ".pdf": DocumentType("application/pdf", (b"%PDF-",)),
    ".docx": DocumentType(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ZIP_MAGIC
    ),
    ".xlsx": DocumentType(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ZIP_MAGIC
    ),
    ".pptx": DocumentType(
        "application/vnd.openxmlformats-officedocument.presentationml.presentation", ZIP_MAGIC
    ),
    ".odt": DocumentType("application/vnd.oasis.opendocument.text", ZIP_MAGIC),
    ".ods": DocumentType("application/vnd.oasis.opendocument.spreadsheet", ZIP_MAGIC),
    ".odp": DocumentType("application/vnd.oasis.opendocument.presentation", ZIP_MAGIC),
    ".rtf": DocumentType("application/rtf", (b"{\\rtf",)),
    ".html": DocumentType("text/html", text_like=True),
    ".htm": DocumentType("text/html", text_like=True),
    ".eml": DocumentType("message/rfc822", text_like=True),
}


class ReviewError(Exception):
    """An error whose message is safe to show to the user."""

    status = 400

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        if status is not None:
            self.status = status


class UpstreamError(Exception):
    """An internal service failed. The message is for logs and never names content."""


@dataclass(frozen=True)
class Settings:
    gateways: tuple[str, ...]
    analyzer_url: str = "http://presidio-analyzer:3000"
    anonymizer_url: str = "http://presidio-anonymizer:3000"
    xberg_url: str = "http://xberg:8000"
    xberg_timeout: int = 1800
    language: str = "en"
    max_text_bytes: int = MAX_TEXT_BYTES_LIMIT
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    requests_per_minute: int = 30
    failed_auth_per_minute: int = 10
    port: int = 8080
    # OpenAI-compatible endpoint of a local model for language detection and
    # extra finds, such as a LiteLLM gateway (/v1) or Ollama (/v1); empty: off.
    assist_url: str = ""
    assist_model: str = "pii-assist"
    assist_key: str = field(default="", repr=False)
    assist_max_calls: int = 8
    # Analyzer requests in flight at once; match PRESIDIO_ANALYZER_WORKERS.
    analyze_parallel: int = 2

    @property
    def max_body_bytes(self) -> int:
        """Largest JSON body worth reading: the text back for masking, plus selections.

        Browsers escape only quotes, backslashes, and control characters, so text
        at most doubles; each selection takes about 100 bytes.
        """
        return self.max_text_bytes * 2 + MAX_SELECTIONS * 100 + 65_536


def _http_url(name: str, value: str, *, allow_empty: bool = False) -> str:
    value = value.strip()
    if not value and allow_empty:
        return ""
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an http(s) URL with a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{name} must not contain credentials, a query, or a fragment")
    return value.rstrip("/")


def _bounded_int(name: str, raw: str | None, default: int, low: int, high: int) -> int:
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def settings_from_environment(environ: Mapping[str, str] = os.environ) -> Settings:
    """Read and validate the configuration; any invalid value stops the service."""
    gateways = tuple(
        _http_url("PII_REVIEW_GATEWAYS", item)
        for item in environ.get("PII_REVIEW_GATEWAYS", "").split(",")
        if item.strip()
    )
    if not gateways:
        raise ValueError("PII_REVIEW_GATEWAYS must list at least one LiteLLM gateway URL")
    assist_model = environ.get("PII_REVIEW_ASSIST_MODEL", "pii-assist").strip() or "pii-assist"
    if not ASSIST_MODEL_RE.fullmatch(assist_model):
        raise ValueError("PII_REVIEW_ASSIST_MODEL must be a model name such as pii-assist or qwen3.5:4b")
    language = environ.get("PII_REVIEW_LANGUAGE", "en").strip() or "en"
    if not LANGUAGE_RE.fullmatch(language):
        raise ValueError("PII_REVIEW_LANGUAGE must be a two-letter language code")
    return Settings(
        gateways=gateways,
        analyzer_url=_http_url(
            "PII_REVIEW_ANALYZER_URL",
            environ.get("PII_REVIEW_ANALYZER_URL", "http://presidio-analyzer:3000"),
        ),
        anonymizer_url=_http_url(
            "PII_REVIEW_ANONYMIZER_URL",
            environ.get("PII_REVIEW_ANONYMIZER_URL", "http://presidio-anonymizer:3000"),
        ),
        xberg_url=_http_url(
            "PII_REVIEW_XBERG_URL",
            environ.get("PII_REVIEW_XBERG_URL", "http://xberg:8000"),
            allow_empty=True,
        ),
        xberg_timeout=_bounded_int(
            "PII_REVIEW_XBERG_TIMEOUT_SECONDS", environ.get("PII_REVIEW_XBERG_TIMEOUT_SECONDS"), 1800, 10, 7200
        ),
        language=language,
        max_text_bytes=_bounded_int(
            "PII_REVIEW_MAX_TEXT_BYTES",
            environ.get("PII_REVIEW_MAX_TEXT_BYTES"),
            MAX_TEXT_BYTES_LIMIT,
            1_000,
            MAX_TEXT_BYTES_LIMIT,
        ),
        max_file_bytes=_bounded_int(
            "PII_REVIEW_MAX_FILE_BYTES",
            environ.get("PII_REVIEW_MAX_FILE_BYTES"),
            DEFAULT_MAX_FILE_BYTES,
            1_024,
            MAX_FILE_BYTES_LIMIT,
        ),
        requests_per_minute=_bounded_int(
            "PII_REVIEW_REQUESTS_PER_MINUTE",
            environ.get("PII_REVIEW_REQUESTS_PER_MINUTE"),
            30,
            1,
            600,
        ),
        port=_bounded_int("PII_REVIEW_PORT", environ.get("PII_REVIEW_PORT"), 8080, 1024, 65535),
        assist_url=_http_url("PII_REVIEW_ASSIST_URL", environ.get("PII_REVIEW_ASSIST_URL", ""), allow_empty=True),
        assist_model=assist_model,
        assist_key=_assist_key(environ.get("PII_REVIEW_ASSIST_KEY", "")),
        analyze_parallel=_bounded_int(
            "PII_REVIEW_ANALYZE_PARALLEL", environ.get("PII_REVIEW_ANALYZE_PARALLEL"), 2, 1, 16
        ),
        assist_max_calls=_bounded_int(
            "PII_REVIEW_ASSIST_MAX_CALLS", environ.get("PII_REVIEW_ASSIST_MAX_CALLS"), 8, 1, 30
        ),
    )


def _assist_key(value: str) -> str:
    value = value.strip()
    if value and not API_KEY_RE.fullmatch(value):
        raise ValueError("PII_REVIEW_ASSIST_KEY must be an API key without spaces")
    return value


# ---------------------------------------------------------------------------
# Internal HTTP
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a key must reach only the configured gateway."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# No proxy from the environment and no redirects for any internal call.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


@dataclass
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


# A body is bytes, or an iterable of byte chunks sent in order (with an explicit
# Content-Length header), so a large upload is never copied into one buffer.
Body = bytes | Iterable[bytes | memoryview] | None
Transport = Callable[[str, str, Mapping[str, str], Body, float], HttpResponse]


def urllib_transport(
    method: str, url: str, headers: Mapping[str, str], body: Body, timeout: float
) -> HttpResponse:
    # urllib verifies TLS certificates by default (https gateways and model APIs).
    request = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return HttpResponse(response.status, dict(response.headers.items()), response.read())
    except urllib.error.HTTPError as error:
        with error:
            return HttpResponse(error.code, dict(error.headers.items()), error.read())


def _post_json(
    transport: Transport, url: str, payload: bytes, timeout: float, service: str
) -> Any:
    try:
        response = transport(
            "POST", url, {"Content-Type": "application/json", "Accept": "application/json"}, payload, timeout
        )
    except (OSError, ValueError) as error:
        raise UpstreamError(f"{service} unreachable: {type(error).__name__}") from error
    if response.status != 200:
        raise UpstreamError(f"{service} returned HTTP {response.status}")
    try:
        return json.loads(response.body)
    except ValueError as error:
        raise UpstreamError(f"{service} returned invalid JSON") from error


# ---------------------------------------------------------------------------
# Rate limiting and key checks
# ---------------------------------------------------------------------------


class RateLimiter:
    """Fixed one-minute windows per identity, bounded in memory."""

    def __init__(self, limit: int, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self.limit = limit
        self.clock = clock
        self.max_keys = max_keys
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def _current(self, identity: str, now: float) -> tuple[float, int]:
        start, count = self._windows.get(identity, (now, 0))
        return (now, 0) if now - start >= 60 else (start, count)

    def exceeded(self, identity: str) -> bool:
        """True when the identity has used its budget, without counting this call."""
        with self._lock:
            return self._current(identity, self.clock())[1] >= self.limit

    def allow(self, identity: str) -> bool:
        """Count one request; False when the budget is already used."""
        now = self.clock()
        with self._lock:
            start, count = self._current(identity, now)
            if count >= self.limit:
                return False
            if identity not in self._windows and len(self._windows) >= self.max_keys:
                self._windows = {
                    key: value for key, value in self._windows.items() if now - value[0] < 60
                }
                if len(self._windows) >= self.max_keys:
                    return False
            self._windows[identity] = (start, count + 1)
            return True


class KeyValidator:
    """Accept a key that one of the LiteLLM gateways accepts.

    Each gateway authenticates the key exactly as it would for a model call,
    including expiry and blocking. Only successes are cached, keyed by an HMAC
    with a per-process secret, so a revoked key stops working within the TTL.
    """

    def __init__(
        self,
        gateways: tuple[str, ...],
        transport: Transport = urllib_transport,
        ttl_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 10_000,
    ) -> None:
        self.gateways = gateways
        self.transport = transport
        self.ttl = ttl_seconds
        self.clock = clock
        self.max_entries = max_entries
        self._secret = secrets.token_bytes(32)
        self._accepted: dict[str, float] = {}
        self._lock = threading.Lock()

    def fingerprint(self, key: str) -> str:
        return hmac.new(self._secret, key.encode("ascii"), hashlib.sha256).hexdigest()

    def check(self, key: str) -> bool | None:
        """True if accepted, False if every reachable gateway refused it, None if none answered."""
        if not API_KEY_RE.fullmatch(key):
            return False
        fingerprint = self.fingerprint(key)
        now = self.clock()
        with self._lock:
            expires = self._accepted.get(fingerprint)
            if expires is not None and expires > now:
                return True
        refused = False
        for gateway in self.gateways:
            try:
                response = self.transport(
                    "GET", f"{gateway}/v1/models", {"Authorization": f"Bearer {key}"}, None, 10
                )
            except (OSError, ValueError) as error:
                LOG.warning("key check: gateway unreachable (%s)", type(error).__name__)
                continue
            if response.status == 200:
                with self._lock:
                    if len(self._accepted) >= self.max_entries:
                        self._accepted = {k: v for k, v in self._accepted.items() if v > now}
                    if len(self._accepted) < self.max_entries:
                        self._accepted[fingerprint] = now + self.ttl
                return True
            if response.status in {400, 401, 403}:
                refused = True
            else:
                LOG.warning("key check: gateway returned HTTP %s", response.status)
        return False if refused else None


# ---------------------------------------------------------------------------
# Presidio
# ---------------------------------------------------------------------------


def require_text(value: Any, max_bytes: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError("Enter some text or choose a document.")
    size = len(value.encode("utf-8"))
    if size > max_bytes:
        raise ReviewError(
            f"The text is {size // 1000} KB; the limit is {max_bytes // 1000} KB. "
            "Split it and review each part.",
            status=413,
        )
    return value


def parse_analyzer_results(results: Any, text: str) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        raise UpstreamError("analyzer returned an unexpected shape")
    detections: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        entity, start, end, score = (
            item.get("entity_type"), item.get("start"), item.get("end"), item.get("score")
        )
        if (
            not isinstance(entity, str)
            or not ENTITY_TYPE_RE.fullmatch(entity)
            or type(start) is not int
            or type(end) is not int
            or not 0 <= start < end <= len(text)
            or not isinstance(score, (int, float))
        ):
            continue
        metadata = item.get("recognition_metadata")
        recognizer = metadata.get("recognizer_name") if isinstance(metadata, dict) else None
        detections.append(
            {
                "entity_type": entity,
                "start": start,
                "end": end,
                "score": round(max(0.0, min(1.0, float(score))), 2),
                "recognizer": recognizer if isinstance(recognizer, str) else None,
            }
        )
    detections.sort(key=lambda item: (item["start"], -item["end"], item["entity_type"]))
    for index, item in enumerate(detections):
        item["id"] = index
    return detections


def find_custom_terms(text: str, terms: Any) -> list[dict[str, Any]]:
    """Every case-insensitive occurrence of terms the user adds by hand."""
    if terms is None:
        return []
    if not isinstance(terms, list) or len(terms) > MAX_CUSTOM_TERMS:
        raise ReviewError(f"Add at most {MAX_CUSTOM_TERMS} extra terms.")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for term in terms:
        if not isinstance(term, str):
            raise ReviewError("Extra terms must be text.")
        term = term.strip()
        if not term or term.casefold() in seen:
            continue
        if len(term) > MAX_CUSTOM_TERM_CHARS:
            raise ReviewError(f"Extra terms can be at most {MAX_CUSTOM_TERM_CHARS} characters.")
        seen.add(term.casefold())
        # re.escape makes the term a literal: no user-controlled pattern.
        for match in re.finditer(re.escape(term), text, re.IGNORECASE):
            results.append(
                {"entity_type": CUSTOM_TERM_ENTITY, "start": match.start(), "end": match.end(), "score": 1.0}
            )
            if len(results) > MAX_SELECTIONS:
                raise ReviewError("The extra terms match too often; use more specific terms.")
    return results


def parse_selections(text: str, selections: Any) -> list[dict[str, Any]]:
    if not isinstance(selections, list) or len(selections) > MAX_SELECTIONS:
        raise ReviewError("The selection is invalid.")
    parsed: list[dict[str, Any]] = []
    for item in selections:
        if not isinstance(item, dict):
            raise ReviewError("The selection is invalid.")
        entity, start, end = item.get("entity_type"), item.get("start"), item.get("end")
        if (
            not isinstance(entity, str)
            or not ENTITY_TYPE_RE.fullmatch(entity)
            or type(start) is not int
            or type(end) is not int
            or not 0 <= start < end <= len(text)
        ):
            raise ReviewError("The selection does not match the text. Analyse it again.")
        score = item.get("score", 1.0)
        score = float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else 1.0
        parsed.append({"entity_type": entity, "start": start, "end": end, "score": max(0.0, min(1.0, score))})
    return parsed


def merge_overlaps(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mask the union of overlapping selections, labelled by the best of them.

    Presidio's anonymizer keeps only one of two overlapping results, which can
    leave part of a selected span visible ("Lindenstraße 12" masked as
    "<LOCATION> 12"). Each group of overlapping selections becomes one span
    covering all of them, with the type of the highest-scoring, then longest,
    member.
    """
    merged: list[dict[str, Any]] = []
    group: list[dict[str, Any]] = []
    group_end = -1

    def flush() -> None:
        if group:
            best = max(group, key=lambda item: (item["score"], item["end"] - item["start"]))
            merged.append(
                {
                    "entity_type": best["entity_type"],
                    "start": min(item["start"] for item in group),
                    "end": group_end,
                    "score": best["score"],
                }
            )

    for item in sorted(results, key=lambda item: (item["start"], -item["end"])):
        if group and item["start"] < group_end:
            group.append(item)
            group_end = max(group_end, item["end"])
            continue
        flush()
        group = [item]
        group_end = item["end"]
    flush()
    return merged


def parse_operators(operators: Any) -> dict[str, dict[str, Any]]:
    if operators is None:
        operators = {}
    if not isinstance(operators, dict) or len(operators) > 100:
        raise ReviewError("The masking choice is invalid.")
    chosen: dict[str, str] = {DEFAULT_OPERATOR_KEY: "replace"}
    for entity, operator in operators.items():
        if (
            not isinstance(entity, str)
            or not (entity == DEFAULT_OPERATOR_KEY or ENTITY_TYPE_RE.fullmatch(entity))
            or operator not in OPERATORS
        ):
            raise ReviewError("Choose replace, mask, or redact for each type.")
        chosen[entity] = operator
    default = chosen.pop(DEFAULT_OPERATOR_KEY)
    # Presidio's DEFAULT applies to every type without its own entry. The
    # replace placeholder names the entity, so give each type its own entry.
    anonymizers = {entity: OPERATORS[operator](entity) for entity, operator in chosen.items()}
    anonymizers[DEFAULT_OPERATOR_KEY] = OPERATORS[default]("PII")
    if default == "replace":
        anonymizers.pop(DEFAULT_OPERATOR_KEY)  # Presidio's own default is <ENTITY_TYPE>
    return anonymizers


def analysis_pieces(text: str) -> list[tuple[int, str]]:
    """(offset, piece) covering the text; pieces overlap by ANALYZE_OVERLAP_CHARS.

    Each piece is at most ANALYZE_CHUNK_BYTES of UTF-8 and ends at whitespace
    when there is some in its second half.
    """
    if len(text.encode("utf-8")) <= ANALYZE_CHUNK_BYTES:
        return [(0, text)]
    pieces: list[tuple[int, str]] = []
    start, length = 0, len(text)
    while start < length:
        # A character takes at most 4 bytes, so each step stays within the budget.
        end = min(length, start + ANALYZE_CHUNK_BYTES // 4)
        size = len(text[start:end].encode("utf-8"))
        while end < length and (ANALYZE_CHUNK_BYTES - size) // 4 >= 64:
            following = min(length, end + (ANALYZE_CHUNK_BYTES - size) // 4)
            size += len(text[end:following].encode("utf-8"))
            end = following
        if end < length:
            middle = start + (end - start) // 2
            cut = max(text.rfind(" ", middle, end), text.rfind("\n", middle, end))
            end = cut if cut > start else end
        pieces.append((start, text[start:end]))
        if end >= length:
            break
        start = max(start + 1, end - ANALYZE_OVERLAP_CHARS)
    return pieces


def anonymize_segments(text: str, results: list[dict[str, Any]]) -> list[tuple[int, int, list[dict[str, Any]]]]:
    """Group non-overlapping results into (start, end, results) segments of the text.

    A segment runs from its first result's start to its last result's end, so
    every result stays whole, and spans at most ANONYMIZE_SEGMENT_CHARS unless
    one result alone is longer. Text between segments needs no masking and is
    kept as it is.
    """
    segments: list[tuple[int, int, list[dict[str, Any]]]] = []
    batch: list[dict[str, Any]] = []
    for item in sorted(results, key=lambda item: item["start"]):
        if batch and item["end"] - batch[0]["start"] > ANONYMIZE_SEGMENT_CHARS:
            segments.append((batch[0]["start"], batch[-1]["end"], batch))
            batch = []
        batch.append(item)
    if batch:
        segments.append((batch[0]["start"], batch[-1]["end"], batch))
    return segments


class Presidio:
    def __init__(self, settings: Settings, transport: Transport = urllib_transport) -> None:
        self.settings = settings
        self.transport = transport

    def _analyze_piece(self, offset: int, piece: str, language: str) -> list[dict[str, Any]]:
        payload = json.dumps({"text": piece, "language": language}).encode("utf-8")
        results = _post_json(self.transport, f"{self.settings.analyzer_url}/analyze", payload, 120, "analyzer")
        return [
            {**item, "start": item["start"] + offset, "end": item["end"] + offset}
            for item in parse_analyzer_results(results, piece)
        ]

    def analyze(self, text: str, language: str | None = None) -> list[dict[str, Any]]:
        """Analyse all of the text in pieces of at most ANALYZE_CHUNK_BYTES.

        Up to `analyze_parallel` pieces are in flight at once, one per analyzer
        worker; more would only queue there.
        """
        language = language or self.settings.language
        pieces = analysis_pieces(text)
        with ThreadPoolExecutor(max_workers=max(1, min(self.settings.analyze_parallel, len(pieces)))) as pool:
            answers = pool.map(lambda job: self._analyze_piece(job[0], job[1], language), pieces)
            seen: set[tuple[int, int, str]] = set()
            detections: list[dict[str, Any]] = []
            for found in answers:
                for item in found:
                    key = (item["start"], item["end"], item["entity_type"])
                    if key in seen:
                        continue
                    seen.add(key)
                    detections.append(item)
                if len(detections) > MAX_SELECTIONS:
                    raise ReviewError("The text has too many detections to review at once. Split it.", 413)
        detections.sort(key=lambda item: (item["start"], -item["end"], item["entity_type"]))
        for index, item in enumerate(detections):
            item["id"] = index
        return detections

    def _anonymize_segment(
        self, text: str, results: list[dict[str, Any]], anonymizers: dict[str, dict[str, Any]]
    ) -> tuple[str, dict[str, int]]:
        payload = json.dumps({"text": text, "anonymizers": anonymizers, "analyzer_results": results}).encode("utf-8")
        response = _post_json(self.transport, f"{self.settings.anonymizer_url}/anonymize", payload, 60, "anonymizer")
        masked = response.get("text") if isinstance(response, dict) else None
        if not isinstance(masked, str):
            raise UpstreamError("anonymizer returned an unexpected shape")
        counts: dict[str, int] = {}
        items = response.get("items")
        for item in items if isinstance(items, list) else []:
            entity = item.get("entity_type") if isinstance(item, dict) else None
            if isinstance(entity, str) and ENTITY_TYPE_RE.fullmatch(entity):
                counts[entity] = counts.get(entity, 0) + 1
        return masked, counts

    def anonymize(
        self, text: str, results: list[dict[str, Any]], anonymizers: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Mask non-overlapping results (see merge_overlaps), one text segment at a time.

        A whole large text in one request outlasts the anonymizer's 30-second
        worker timeout; segments cut between results give the same output.
        """
        if not results:
            return {"masked_text": text, "counts": {}}
        segments = anonymize_segments(text, results)
        jobs = [
            (text[start:end], [{**item, "start": item["start"] - start, "end": item["end"] - start} for item in batch])
            for start, end, batch in segments
        ]
        with ThreadPoolExecutor(max_workers=max(1, min(self.settings.analyze_parallel, len(jobs)))) as pool:
            masked_parts = list(pool.map(lambda job: self._anonymize_segment(job[0], job[1], anonymizers), jobs))
        parts: list[str] = []
        counts: dict[str, int] = {}
        position = 0
        for (start, end, _batch), (masked, part_counts) in zip(segments, masked_parts):
            parts.append(text[position:start])
            parts.append(masked)
            position = end
            for entity, count in part_counts.items():
                counts[entity] = counts.get(entity, 0) + count
        parts.append(text[position:])
        return {"masked_text": "".join(parts), "counts": counts}


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


def document_type(filename: Any) -> tuple[str, DocumentType | None]:
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise ReviewError("The document needs a file name with an extension.")
    # Only the extension is used; the name itself is never stored or forwarded.
    extension = os.path.splitext(filename.replace("\\", "/").rsplit("/", 1)[-1])[1].lower()
    if extension in TEXT_EXTENSIONS:
        return extension, None
    if extension in DOCUMENT_TYPES:
        return extension, DOCUMENT_TYPES[extension]
    supported = ", ".join(sorted(TEXT_EXTENSIONS | set(DOCUMENT_TYPES)))
    raise ReviewError(f"That file type is not supported. Use one of: {supported}.", status=415)


def decode_text_file(data: bytes) -> str:
    if b"\x00" in data:
        raise ReviewError("The file is not plain text.", status=415)
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ReviewError("Text files must be UTF-8.", status=415) from error


class XbergExtractor:
    """Extract document text with the tool's own Xberg API server (POST /extract).

    The upload is sent as multipart form data, streamed from memory without
    another copy. Only the bytes and a neutral file name with the allowed
    extension are sent; the original file name never leaves this service.
    Xberg runs on a private network with no internet, so it cannot fetch
    anything a document refers to.
    """

    def __init__(self, url: str, transport: Transport = urllib_transport, timeout: float = 1800) -> None:
        self.url = url
        self.transport = transport
        self.timeout = timeout

    @staticmethod
    def _document_text(structured: Any) -> str | None:
        """The extracted text from Xberg's {"results": [{"content": ...}]} answer."""
        if not isinstance(structured, dict):
            return None
        if isinstance(structured.get("content"), str):
            return structured["content"]
        results = structured.get("results")
        if not isinstance(results, list):
            return None
        parts = [
            item["content"]
            for item in results
            if isinstance(item, dict) and isinstance(item.get("content"), str)
        ]
        return "\n\n".join(parts) if parts else None

    def extract(self, data: bytes | bytearray | memoryview, extension: str, kind: DocumentType) -> str:
        boundary = secrets.token_hex(16)
        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="files"; filename="document{extension}"\r\n'
            f"Content-Type: {kind.mime_type}\r\n\r\n"
        ).encode("ascii")
        tail = f"\r\n--{boundary}--\r\n".encode("ascii")
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(head) + len(data) + len(tail)),
            "Accept": "application/json",
        }
        try:
            response = self.transport(
                "POST", f"{self.url}/extract", headers, [head, memoryview(data), tail], self.timeout
            )
        except (OSError, ValueError) as error:
            raise UpstreamError(f"xberg unreachable: {type(error).__name__}") from error
        if response.status == 413:
            raise ReviewError("The document is larger than the extractor accepts.", 413)
        if response.status != 200:
            raise UpstreamError(f"xberg returned HTTP {response.status}")
        try:
            answer = json.loads(response.body)
        except ValueError as error:
            raise UpstreamError("xberg returned invalid JSON") from error
        text = self._document_text(answer)
        if text is None:
            errors = answer.get("errors") if isinstance(answer, dict) else None
            if errors:
                # Xberg's error text can quote the document; only fixed messages are shown.
                if any("Security limit exceeded" in str(error.get("message", "")) for error in errors if isinstance(error, dict)):
                    raise ReviewError(
                        "The document contains an embedded file larger than the extractor's "
                        "safety limit (100 MiB unpacked). Save it without that attachment, "
                        "or in smaller parts.",
                        422,
                    )
                raise ReviewError(
                    "The document could not be read. Check that it is not damaged or encrypted.", 422
                )
            raise UpstreamError("xberg returned no document text")
        return text


def extract_document(
    filename: Any,
    data: bytes | bytearray,
    max_file_bytes: int,
    extractor: XbergExtractor | None,
) -> str:
    if not data:
        raise ReviewError("The document is empty.")
    if len(data) > max_file_bytes:
        raise ReviewError(
            f"The document is {len(data) // 1024} KiB; the limit is {max_file_bytes // 1024} KiB.",
            status=413,
        )
    extension, kind = document_type(filename)
    if kind is None:
        return decode_text_file(bytes(data))
    if kind.magic and not any(data.startswith(magic) for magic in kind.magic):
        raise ReviewError(f"The file content does not match its {extension} extension.", status=415)
    if kind.text_like and b"\x00" in data[:8192]:
        raise ReviewError(f"The file content does not match its {extension} extension.", status=415)
    if extractor is None:
        raise ReviewError(
            "Document extraction is not available here. Paste the text instead.", status=503
        )
    return extractor.extract(data, extension, kind)


# ---------------------------------------------------------------------------
# Local pii-assist model (through a LiteLLM gateway)
# ---------------------------------------------------------------------------


def _load_assist_prompt() -> dict[str, Any]:
    """The prompt and answer schema for the local model (pii_assist_prompt.json)."""
    return json.loads(Path(__file__).with_name("pii_assist_prompt.json").read_text(encoding="utf-8"))


ASSIST_PROMPT = _load_assist_prompt()
ASSIST_LANGUAGES: tuple[str, ...] = tuple(ASSIST_PROMPT["languages"])
ASSIST_ITEM_TYPES: tuple[str, ...] = tuple(ASSIST_PROMPT["item_types"])
ASSIST_PLACEHOLDER_TYPES: dict[str, str] = ASSIST_PROMPT["placeholder_types"]
ASSIST_CHUNK_CHARS = 4000
ASSIST_RECOGNIZER = "local model"
# The model gives no confidence; this places its finds below certain pattern
# matches and alongside NER results in the list.
ASSIST_SCORE = 0.8


def assist_response_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "language": {"type": "string", "enum": [*ASSIST_LANGUAGES, "other"]},
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "type": {"type": "string", "enum": list(ASSIST_ITEM_TYPES)},
                    },
                    "required": ["text", "type"],
                },
            },
        },
        "required": ["language", "items"],
    }


def assist_chunks(text: str, size: int = ASSIST_CHUNK_CHARS) -> list[tuple[int, str]]:
    """(offset, piece) of at most `size` characters, split at whitespace when possible."""
    chunks: list[tuple[int, str]] = []
    offset = 0
    while len(text) - offset > size:
        cut = text.rfind(" ", offset + size // 2, offset + size)
        cut = offset + size if cut <= offset else cut
        chunks.append((offset, text[offset:cut]))
        offset = cut
    if text[offset:].strip():
        chunks.append((offset, text[offset:]))
    return chunks


def parse_assist_answer(content: Any, source: str) -> tuple[str | None, list[tuple[str, str]]]:
    """A known language and the items that occur verbatim in `source`."""
    try:
        answer = json.loads(content) if isinstance(content, str) else None
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        return None, []
    language = answer.get("language") if answer.get("language") in ASSIST_LANGUAGES else None
    items: list[tuple[str, str]] = []
    raw = answer.get("items")
    for item in raw[:200] if isinstance(raw, list) else []:
        if not isinstance(item, dict) or item.get("type") not in ASSIST_ITEM_TYPES:
            continue
        value = item.get("text")
        if isinstance(value, str):
            value = value.strip()
            if 2 <= len(value) <= 200 and value in source and re.search(r"\w", value):
                items.append((value, item["type"]))
    return language, items


def assist_detections(
    text: str, items: list[tuple[str, str]], taken: set[tuple[int, int, str]]
) -> list[dict[str, Any]]:
    """Every occurrence of the model's items, never inside a longer word.

    A span Presidio already reports with the same type is skipped; with another
    type both are listed, so the user sees both readings.
    """
    detections: list[dict[str, Any]] = []
    for value, kind in dict.fromkeys(items):
        before = r"(?<!\w)" if re.match(r"\w", value) else ""
        after = r"(?!\w)" if re.search(r"\w$", value) else ""
        entity = ASSIST_PLACEHOLDER_TYPES.get(kind, kind)
        for match in re.finditer(before + re.escape(value) + after, text):
            key = (match.start(), match.end(), entity)
            if key in taken:
                continue
            taken.add(key)
            detections.append(
                {
                    "entity_type": entity,
                    "start": key[0],
                    "end": key[1],
                    "score": ASSIST_SCORE,
                    "recognizer": ASSIST_RECOGNIZER,
                }
            )
            if len(detections) >= MAX_SELECTIONS:
                return detections
    return detections


class AssistClient:
    """Ask a local model for the text's language and the personal data in it.

    Any OpenAI-compatible endpoint works: a LiteLLM gateway's pii-assist model
    (https://gateway/v1, with a key limited to that model) or Ollama itself
    (http://host.docker.internal:11434/v1). The text is sent unmasked, so the
    model must run on this host or a private network. Any failure falls back to
    Presidio alone: the assist only adds detections and picks the language.
    """

    def __init__(self, settings: Settings, transport: Transport = urllib_transport) -> None:
        self.settings = settings
        self.transport = transport

    def _ask(self, piece: str) -> tuple[str | None, list[tuple[str, str]]]:
        body = json.dumps(
            {
                "model": self.settings.assist_model,
                "messages": [
                    {"role": "system", "content": ASSIST_PROMPT["system_prompt"]},
                    {"role": "user", "content": piece},
                ],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": "personal_data", "schema": assist_response_schema()},
                },
                "reasoning_effort": "none",
                "temperature": 0,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.settings.assist_key:
            headers["Authorization"] = f"Bearer {self.settings.assist_key}"
        try:
            response = self.transport(
                "POST", f"{self.settings.assist_url}/chat/completions", headers, body, 120
            )
        except (OSError, ValueError) as error:
            raise UpstreamError(f"assist model unreachable: {type(error).__name__}") from error
        if response.status != 200:
            raise UpstreamError(f"assist model returned HTTP {response.status}")
        try:
            content = json.loads(response.body)["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise UpstreamError("assist model returned an unexpected shape") from None
        return parse_assist_answer(content, piece)

    def detect(self, text: str) -> dict[str, Any]:
        """Language of the first piece, items from up to assist_max_calls pieces."""
        pieces = assist_chunks(text)
        language: str | None = None
        items: list[tuple[str, str]] = []
        checked = 0
        for index, (offset, piece) in enumerate(pieces[: self.settings.assist_max_calls]):
            piece_language, piece_items = self._ask(piece)
            if index == 0:
                language = piece_language
            items.extend(piece_items)
            checked = offset + len(piece)
        return {"language": language, "items": items, "checked_chars": checked}


@dataclass
class Reviewer:
    """The operations behind the page's API calls."""

    settings: Settings
    presidio: Presidio
    extractor: XbergExtractor | None
    assist: AssistClient | None = None
    _extraction_slots: threading.BoundedSemaphore = field(
        default_factory=lambda: threading.BoundedSemaphore(2)
    )

    def analyze(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Analyse pasted text (POST /api/analyze)."""
        return self._analyze_text(payload.get("text"), "text")

    def analyze_document(self, filename: Any, data: bytes | bytearray) -> dict[str, Any]:
        """Extract and analyse an uploaded file (POST /api/analyze-document)."""
        if not self._extraction_slots.acquire(blocking=False):
            raise ReviewError("Other documents are being read. Try again in a moment.", status=503)
        try:
            text = extract_document(filename, data, self.settings.max_file_bytes, self.extractor)
        finally:
            self._extraction_slots.release()
        if not text.strip():
            raise ReviewError("No text was found in the document. Scanned pages without OCR text cannot be analysed.", 422)
        return self._analyze_text(text, "document")

    def _analyze_text(self, text: Any, source: str) -> dict[str, Any]:
        text = require_text(text, self.settings.max_text_bytes)
        assist: dict[str, Any] = {"used": False, "checked_chars": 0, "total_chars": len(text)}
        language = self.settings.language
        items: list[tuple[str, str]] = []
        if self.assist is not None:
            try:
                found = self.assist.detect(text)
            except UpstreamError as error:
                LOG.warning("assist skipped: %s", error)
            else:
                assist.update(used=True, checked_chars=found["checked_chars"])
                language = found["language"] or language
                items = found["items"]
        detections = self.presidio.analyze(text, language)
        taken = {(item["start"], item["end"], item["entity_type"]) for item in detections}
        detections.extend(assist_detections(text, items, taken))
        detections.sort(key=lambda item: (item["start"], -item["end"], item["entity_type"]))
        for index, item in enumerate(detections):
            item["id"] = index
        return {
            "source": source,
            "text": text,
            "language": language,
            "assist": assist,
            "detections": detections,
        }

    def mask(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        text = require_text(payload.get("text"), self.settings.max_text_bytes)
        results = parse_selections(text, payload.get("selections", []))
        results.extend(find_custom_terms(text, payload.get("custom_terms")))
        if len(results) > MAX_SELECTIONS:
            raise ReviewError("Too many items are selected.")
        anonymizers = parse_operators(payload.get("operators"))
        return self.presidio.anonymize(text, merge_overlaps(results), anonymizers)
