from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from pii_review import languages, review, server  # noqa: E402
from pii_review.review import (  # noqa: E402
    HttpResponse,
    KeyValidator,
    Presidio,
    RateLimiter,
    Reviewer,
    ReviewError,
    Settings,
    XbergExtractor,
)

SAMPLE = "Zelda Quartermaine wrote to zq@example.test from Berlin."
VALID_KEY = "sk-valid-test-key"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def analyzer_results(text: str) -> list[dict[str, Any]]:
    results = []
    for value, entity, score in (
        ("Zelda Quartermaine", "PERSON", 0.85),
        ("zq@example.test", "EMAIL_ADDRESS", 1.0),
        ("Berlin", "LOCATION", 0.85),
    ):
        start = text.find(value)
        while start >= 0:
            results.append(
                {
                    "entity_type": entity,
                    "start": start,
                    "end": start + len(value),
                    "score": score,
                    "recognition_metadata": {"recognizer_name": "TestRecognizer"},
                }
            )
            start = text.find(value, start + 1)
    return results


class FakeUpstreams:
    """Stands in for the gateways, Presidio, and Xberg."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []
        self.gateway_status = 200

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> HttpResponse:
        self.calls.append((method, url, dict(headers), body))
        if url.endswith("/v1/models"):
            ok = headers.get("Authorization") == f"Bearer {VALID_KEY}"
            return HttpResponse(self.gateway_status if ok else 401, {}, b"{}")
        payload = json.loads(body or b"{}")
        if url.endswith("/analyze"):
            return HttpResponse(200, {}, json.dumps(analyzer_results(payload["text"])).encode())
        if url.endswith("/anonymize"):
            text = payload["text"]
            items = []
            for result in sorted(payload["analyzer_results"], key=lambda r: -r["start"]):
                operator = payload["anonymizers"].get(result["entity_type"]) or payload["anonymizers"].get(
                    "DEFAULT", {"type": "replace", "new_value": f"<{result['entity_type']}>"}
                )
                replacement = {
                    "replace": operator.get("new_value", f"<{result['entity_type']}>"),
                    "mask": "*" * (result["end"] - result["start"]),
                    "redact": "",
                }[operator["type"]]
                text = text[: result["start"]] + replacement + text[result["end"] :]
                items.append({"entity_type": result["entity_type"], "operator": operator["type"]})
            return HttpResponse(200, {}, json.dumps({"text": text, "items": items}).encode())
        raise AssertionError(f"unexpected call {method} {url}")


def settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {"gateways": ("http://gateway:4000",), "xberg_url": "", "port": 0}
    values.update(overrides)
    return Settings(**values)


class SettingsTests(unittest.TestCase):
    def test_requires_gateways(self) -> None:
        with self.assertRaisesRegex(ValueError, "PII_REVIEW_GATEWAYS"):
            review.settings_from_environment({})

    def test_rejects_urls_with_credentials_or_other_schemes(self) -> None:
        for value in ("ftp://gateway", "http://user:pass@gateway:4000", "gateway:4000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.settings_from_environment({"PII_REVIEW_GATEWAYS": value})

    def test_caps_text_and_file_limits(self) -> None:
        with self.assertRaisesRegex(ValueError, "PII_REVIEW_MAX_TEXT_BYTES"):
            review.settings_from_environment(
                {"PII_REVIEW_GATEWAYS": "http://g:4000", "PII_REVIEW_MAX_TEXT_BYTES": "300000000"}
            )
        with self.assertRaisesRegex(ValueError, "PII_REVIEW_MAX_FILE_BYTES"):
            review.settings_from_environment(
                {"PII_REVIEW_GATEWAYS": "http://g:4000", "PII_REVIEW_MAX_FILE_BYTES": "300000000"}
            )

    def test_defaults(self) -> None:
        loaded = review.settings_from_environment(
            {"PII_REVIEW_GATEWAYS": "http://litellm-prod:4000/, http://litellm-dev:4000"}
        )
        self.assertEqual(loaded.gateways, ("http://litellm-prod:4000", "http://litellm-dev:4000"))
        self.assertEqual(loaded.max_text_bytes, 250_000_000)
        self.assertEqual(loaded.xberg_url, "http://xberg:8000")
        self.assertEqual(loaded.max_file_bytes, 200 * 1024 * 1024)
        self.assertEqual(loaded.assist_url, "")
        # The largest upload plus multipart framing fits Xberg's 250 MiB limit.
        self.assertLess(review.MAX_FILE_BYTES_LIMIT + 4096, 262_144_000)

    def test_https_gateways_and_assist_settings(self) -> None:
        loaded = review.settings_from_environment(
            {
                "PII_REVIEW_GATEWAYS": "https://litellm.example.test",
                "PII_REVIEW_ASSIST_URL": "http://host.docker.internal:11434/v1/",
                "PII_REVIEW_ASSIST_MODEL": "qwen3.5:4b",
            }
        )
        self.assertEqual(loaded.gateways, ("https://litellm.example.test",))
        self.assertEqual(loaded.assist_url, "http://host.docker.internal:11434/v1")
        self.assertEqual(loaded.assist_model, "qwen3.5:4b")
        for bad in ("bad model", "-x", ""):
            if bad:
                with self.subTest(model=bad), self.assertRaises(ValueError):
                    review.settings_from_environment({"PII_REVIEW_GATEWAYS": "http://g", "PII_REVIEW_ASSIST_MODEL": bad})

    def test_empty_xberg_url_disables_documents(self) -> None:
        loaded = review.settings_from_environment(
            {"PII_REVIEW_GATEWAYS": "http://g:4000", "PII_REVIEW_XBERG_URL": ""}
        )
        self.assertEqual(loaded.xberg_url, "")


class KeyValidatorTests(unittest.TestCase):
    def test_accepts_and_caches_a_key_one_gateway_accepts(self) -> None:
        upstream = FakeUpstreams()
        clock = Clock()
        validator = KeyValidator(("http://a:4000", "http://b:4000"), upstream, ttl_seconds=60, clock=clock)
        self.assertTrue(validator.check(VALID_KEY))
        self.assertTrue(validator.check(VALID_KEY))
        self.assertEqual(len(upstream.calls), 1)
        clock.now += 61
        self.assertTrue(validator.check(VALID_KEY))
        self.assertEqual(len(upstream.calls), 2)

    def test_refused_keys_are_not_cached(self) -> None:
        upstream = FakeUpstreams()
        validator = KeyValidator(("http://a:4000", "http://b:4000"), upstream)
        self.assertFalse(validator.check("sk-wrong-key-123"))
        self.assertFalse(validator.check("sk-wrong-key-123"))
        self.assertEqual(len(upstream.calls), 4)

    def test_tries_the_next_gateway_when_one_is_down(self) -> None:
        def transport(method: str, url: str, *rest: Any) -> HttpResponse:
            if "down" in url:
                raise OSError("connection refused")
            return HttpResponse(200, {}, b"{}")

        validator = KeyValidator(("http://down:4000", "http://up:4000"), transport)
        self.assertTrue(validator.check(VALID_KEY))

    def test_reports_unknown_when_no_gateway_answers(self) -> None:
        def transport(*_args: Any) -> HttpResponse:
            raise OSError("down")

        self.assertIsNone(KeyValidator(("http://a:4000",), transport).check(VALID_KEY))

    def test_rejects_malformed_keys_without_calling_a_gateway(self) -> None:
        upstream = FakeUpstreams()
        validator = KeyValidator(("http://a:4000",), upstream)
        for key in ("short", "sk-has space", "sk-line\r\nX-Injected: 1", "x" * 5000):
            with self.subTest(key=key[:20]):
                self.assertFalse(validator.check(key))
        self.assertEqual(upstream.calls, [])


class RateLimiterTests(unittest.TestCase):
    def test_fixed_window(self) -> None:
        clock = Clock()
        limiter = RateLimiter(2, clock)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.exceeded("a"))
        self.assertTrue(limiter.allow("b"))
        clock.now += 60
        self.assertFalse(limiter.exceeded("a"))
        self.assertTrue(limiter.allow("a"))

    def test_bounded_memory(self) -> None:
        clock = Clock()
        limiter = RateLimiter(5, clock, max_keys=2)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        self.assertFalse(limiter.allow("c"))
        clock.now += 61
        self.assertTrue(limiter.allow("c"))


class ParsingTests(unittest.TestCase):
    def test_analyzer_results_are_validated_sorted_and_numbered(self) -> None:
        text = "abcdefghij"
        parsed = review.parse_analyzer_results(
            [
                {"entity_type": "PERSON", "start": 5, "end": 8, "score": 0.5},
                {"entity_type": "PERSON", "start": 0, "end": 2, "score": 1.7},
                {"entity_type": "bad type", "start": 0, "end": 1, "score": 1},
                {"entity_type": "PERSON", "start": 4, "end": 40, "score": 1},
                {"entity_type": "PERSON", "start": True, "end": 2, "score": 1},
                "junk",
            ],
            text,
        )
        self.assertEqual([(d["id"], d["start"], d["score"]) for d in parsed], [(0, 0, 1.0), (1, 5, 0.5)])

    def test_custom_terms_are_literal_and_case_insensitive(self) -> None:
        text = "Project (Falcon) and project (falcon); a.b and axb"
        found = review.find_custom_terms(text, ["project (falcon)", "a.b", "  ", "A.B"])
        spans = [text[r["start"] : r["end"]] for r in found]
        self.assertEqual(spans, ["Project (Falcon)", "project (falcon)", "a.b"])
        self.assertTrue(all(r["entity_type"] == "CUSTOM_TERM" for r in found))

    def test_custom_term_limits(self) -> None:
        with self.assertRaises(ReviewError):
            review.find_custom_terms("x", ["t"] * (review.MAX_CUSTOM_TERMS + 1))
        with self.assertRaises(ReviewError):
            review.find_custom_terms("x", ["t" * 201])
        with self.assertRaises(ReviewError):
            review.find_custom_terms("x", "not a list")

    def test_custom_term_wildcards_cover_the_rest_of_the_word(self) -> None:
        text = "Mail anna@corp.example, bob@CORP.example or eve@other.example about Project Falcon-2 and projects."
        found = review.find_custom_terms(text, ["*@corp.example", "Project *", "falc*"])
        spans = [text[r["start"] : r["end"]] for r in found]
        # Sorted by position. A leading * reaches back only, so the comma
        # after the first address stays; "projects." has no space after "project".
        self.assertEqual(spans, ["anna@corp.example", "bob@CORP.example", "Project Falcon-2", "Falcon-2"])

    def test_custom_term_wildcards_are_bounded(self) -> None:
        for bad in ["*", "**", "*a", "a*b", "a**"]:
            with self.subTest(term=bad), self.assertRaises(ReviewError):
                review.find_custom_terms("abc", [bad])
        # A * reaches at most MAX_WILDCARD_CHARS characters, so a long run of
        # text without spaces cannot make matching slow.
        text = "x" * 100_000 + "@corp.example"
        [found] = review.find_custom_terms(text, ["*@corp.example"])
        self.assertEqual(found["end"] - found["start"], review.MAX_WILDCARD_CHARS + len("@corp.example"))
        found = review.find_custom_terms("ab" * 50_000, ["*ab*"])
        self.assertTrue(found)

    def test_selections_must_fit_the_text(self) -> None:
        self.assertEqual(
            review.parse_selections("abcdef", [{"entity_type": "PERSON", "start": 1, "end": 3, "score": 0}]),
            [{"entity_type": "PERSON", "start": 1, "end": 3, "score": 0.0}],
        )
        for bad in (
            [{"entity_type": "PERSON", "start": 3, "end": 3}],
            [{"entity_type": "PERSON", "start": 0, "end": 7}],
            [{"entity_type": "<script>", "start": 0, "end": 1}],
            [{"entity_type": "PERSON", "start": "0", "end": 1}],
            "x",
        ):
            with self.subTest(bad=bad), self.assertRaises(ReviewError):
                review.parse_selections("abcdef", bad)

    def test_overlapping_selections_are_masked_as_one_span(self) -> None:
        results = review.merge_overlaps(
            [
                {"entity_type": "LOCATION", "start": 10, "end": 22, "score": 0.85},
                {"entity_type": "LOCATION", "start": 10, "end": 25, "score": 0.8},
                {"entity_type": "ORGANIZATION", "start": 30, "end": 50, "score": 0.85},
                {"entity_type": "EMAIL_ADDRESS", "start": 30, "end": 50, "score": 1.0},
                {"entity_type": "URL", "start": 40, "end": 50, "score": 0.5},
                {"entity_type": "PERSON", "start": 60, "end": 70, "score": 0.85},
            ]
        )
        self.assertEqual(
            [(r["entity_type"], r["start"], r["end"]) for r in results],
            [("LOCATION", 10, 25), ("EMAIL_ADDRESS", 30, 50), ("PERSON", 60, 70)],
        )
        self.assertEqual(review.merge_overlaps([]), [])

    def test_selection_scores_are_bounded(self) -> None:
        parsed = review.parse_selections(
            "abcdef",
            [
                {"entity_type": "PERSON", "start": 0, "end": 1, "score": 7},
                {"entity_type": "PERSON", "start": 1, "end": 2, "score": "high"},
                {"entity_type": "PERSON", "start": 2, "end": 3, "score": True},
                {"entity_type": "PERSON", "start": 3, "end": 4, "score": 0.4},
            ],
        )
        self.assertEqual([p["score"] for p in parsed], [1.0, 1.0, 1.0, 0.4])

    def test_operators(self) -> None:
        self.assertEqual(review.parse_operators(None), {})
        chosen = review.parse_operators({"DEFAULT": "mask", "PERSON": "replace", "LOCATION": "redact"})
        self.assertEqual(chosen["PERSON"], {"type": "replace", "new_value": "<PERSON>"})
        self.assertEqual(chosen["LOCATION"], {"type": "redact"})
        self.assertEqual(chosen["DEFAULT"]["type"], "mask")
        for bad in ({"PERSON": "hash"}, {"lower": "mask"}, ["mask"]):
            with self.subTest(bad=bad), self.assertRaises(ReviewError):
                review.parse_operators(bad)

    def test_text_size_limit(self) -> None:
        with self.assertRaises(ReviewError) as caught:
            review.require_text("é" * 600, 1000)
        self.assertEqual(caught.exception.status, 413)
        with self.assertRaises(ReviewError):
            review.require_text("   ", 1000)


class DocumentTests(unittest.TestCase):
    def test_text_files_are_decoded_locally(self) -> None:
        self.assertEqual(
            review.extract_document("notes.TXT", b"\xef\xbb\xbfhello", 1024, None), review.Extraction("hello")
        )
        with self.assertRaises(ReviewError):
            review.extract_document("notes.txt", b"\xff\xfe", 1024, None)
        with self.assertRaises(ReviewError):
            review.extract_document("notes.txt", b"a\x00b", 1024, None)

    def test_only_the_extension_of_the_name_matters(self) -> None:
        self.assertEqual(review.document_type("../../etc/passwd.md")[0], ".md")
        self.assertEqual(review.document_type("C:\\tmp\\x.PDF")[0], ".pdf")
        for name in ("archive.zip", "noextension", "", None, "x" * 300 + ".txt"):
            with self.subTest(name=str(name)[:20]), self.assertRaises(ReviewError):
                review.document_type(name)

    def test_binary_documents_need_matching_content_and_an_extractor(self) -> None:
        with self.assertRaises(ReviewError) as caught:
            review.extract_document("a.pdf", b"PK\x03\x04", 1024, None)
        self.assertEqual(caught.exception.status, 415)
        with self.assertRaises(ReviewError) as caught:
            review.extract_document("a.pdf", b"%PDF-1.7", 1024, None)
        self.assertEqual(caught.exception.status, 503)
        with self.assertRaises(ReviewError) as caught:
            review.extract_document("a.pdf", b"%PDF-" + b"x" * 2000, 1024, None)
        self.assertEqual(caught.exception.status, 413)

    def test_images_need_their_signature(self) -> None:
        good = {
            "scan.PNG": b"\x89PNG\r\n\x1a\n" + b"\x00" * 16,
            "photo.jpg": b"\xff\xd8\xff\xe0" + b"\x00" * 16,
            "photo.jpeg": b"\xff\xd8\xff\xe1" + b"\x00" * 16,
            "fax.tif": b"II*\x00" + b"\x00" * 16,
            "fax.tiff": b"MM\x00*" + b"\x00" * 16,
            "scan.bmp": b"BM" + b"\x00" * 16,
            "scan.gif": b"GIF89a" + b"\x00" * 16,
            "scan.webp": b"RIFF\x10\x00\x00\x00WEBPVP8 " + b"\x00" * 8,
        }
        for name, data in good.items():
            with self.subTest(name=name), self.assertRaises(ReviewError) as caught:
                review.extract_document(name, data, 1024, None)
            self.assertEqual(caught.exception.status, 503)  # accepted, but no extractor here
            self.assertTrue(review.document_type(name)[1].image)
        for name, data in {
            "scan.png": b"\xff\xd8\xff\xe0",
            "photo.jpg": b"\x89PNG\r\n\x1a\n",
            "scan.webp": b"RIFF\x10\x00\x00\x00WAVEfmt ",
            "scan.gif": b"GIF8",
        }.items():
            with self.subTest(name=name), self.assertRaises(ReviewError) as caught:
                review.extract_document(name, data, 1024, None)
            self.assertEqual(caught.exception.status, 415)


class XbergTests(unittest.TestCase):
    def capture(self, status: int, answer: Any) -> tuple[Any, list[tuple[str, dict[str, str], bytes]]]:
        calls: list[tuple[str, dict[str, str], bytes]] = []

        def transport(method: str, url: str, headers: Mapping[str, str], body: Any, _t: float) -> HttpResponse:
            sent = b"".join(bytes(part) for part in body)
            calls.append((url, dict(headers), sent))
            return HttpResponse(status, {}, json.dumps(answer).encode() if not isinstance(answer, bytes) else answer)

        return transport, calls

    def test_streams_the_upload_as_multipart(self) -> None:
        answer = {
            "results": [
                {"content": "Page one", "metadata": {"author": "Jane Example"}, "mime_type": "application/pdf"},
                {"content": "Page two"},
            ],
            "summary": {"results": 2},
        }
        transport, calls = self.capture(200, answer)
        data = bytearray(b"%PDF-1.7 \x00\xff binary")
        extraction = XbergExtractor("http://xberg:8000", transport).extract(data, ".pdf", review.DOCUMENT_TYPES[".pdf"])
        self.assertEqual(extraction, review.Extraction("Page one\n\nPage two", ocr=False))
        url, headers, body = calls[0]
        self.assertEqual(url, "http://xberg:8000/extract")
        boundary = headers["Content-Type"].split("boundary=", 1)[1]
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertIn(b'name="files"; filename="document.pdf"', body)
        self.assertIn(bytes(data), body)
        self.assertTrue(body.endswith(f"--{boundary}--\r\n".encode()))

    def test_reports_whether_ocr_was_used(self) -> None:
        pdf, png = review.DOCUMENT_TYPES[".pdf"], review.DOCUMENT_TYPES[".png"]
        for kind, result, expected in (
            (pdf, {"content": "x", "extraction_method": "native", "metadata": {"ocr_used": False}}, False),
            (pdf, {"content": "x", "extraction_method": "mixed", "metadata": {"ocr_used": True}}, True),
            (pdf, {"content": "x", "extraction_method": "ocr"}, True),
            (pdf, {"content": "x", "metadata": {"ocr_used": True}}, True),
            # Images in Office documents are read with OCR but not flagged.
            (pdf, {"content": "x", "extraction_method": "native", "counts": {"images": 2}}, True),
            (pdf, {"content": "x", "counts": {"images": 0}}, False),
            # An image is always read with OCR, whatever the answer says.
            (png, {"content": "x"}, True),
        ):
            with self.subTest(result=result):
                transport, _calls = self.capture(200, {"results": [result]})
                extraction = XbergExtractor("http://xberg:8000", transport).extract(b"x", ".pdf", kind)
                self.assertIs(extraction.ocr, expected)

    def test_unreadable_documents_get_a_fixed_message(self) -> None:
        transport, _calls = self.capture(
            200, {"results": [], "errors": [{"message": "Parsing error near Jane Example"}], "summary": {}}
        )
        with self.assertRaises(ReviewError) as caught:
            XbergExtractor("http://xberg:8000", transport).extract(b"%PDF-", ".pdf", review.DOCUMENT_TYPES[".pdf"])
        self.assertEqual(caught.exception.status, 422)
        self.assertNotIn("Jane", str(caught.exception))

    def test_security_limit_has_its_own_message(self) -> None:
        transport, _calls = self.capture(
            200,
            {"results": [], "errors": [{"message": "Parsing error: Security limit exceeded: File 'word/media/x.bin' uncompressed size 2 bytes"}]},
        )
        with self.assertRaises(ReviewError) as caught:
            XbergExtractor("http://xberg:8000", transport).extract(b"PK\x03\x04", ".docx", review.DOCUMENT_TYPES[".docx"])
        self.assertIn("100 MiB", str(caught.exception))
        self.assertNotIn("word/media", str(caught.exception))

    def test_other_failures(self) -> None:
        for status, answer, error in (
            (500, {}, review.UpstreamError),
            (413, {}, ReviewError),
            (200, b"not json", review.UpstreamError),
            (200, {"summary": {}}, review.UpstreamError),
        ):
            with self.subTest(status=status, answer=answer):
                transport, _calls = self.capture(status, answer)
                with self.assertRaises(error):
                    XbergExtractor("http://xberg:8000", transport).extract(b"%PDF-", ".pdf", review.DOCUMENT_TYPES[".pdf"])


class ChunkedAnalysisTests(unittest.TestCase):
    def test_all_text_is_analysed_in_pieces(self) -> None:
        upstream = FakeUpstreams()
        config = settings()
        filler = "Lorem ipsum dolor sit amet. " * 9000  # about 250 KB
        text = filler + SAMPLE + " " + filler + SAMPLE
        detections = Presidio(config, upstream).analyze(text)
        analyses = [body for _m, url, _h, body in upstream.calls if url.endswith("/analyze")]
        self.assertGreater(len(analyses), 2)
        self.assertTrue(all(len(json.loads(body)["text"].encode()) <= review.ANALYZE_CHUNK_BYTES for body in analyses))
        people = [(d["start"], text[d["start"]:d["end"]]) for d in detections if d["entity_type"] == "PERSON"]
        self.assertEqual([value for _start, value in people], ["Zelda Quartermaine", "Zelda Quartermaine"])
        self.assertEqual(people[1][0], text.rindex("Zelda"))
        self.assertEqual([d["id"] for d in detections], list(range(len(detections))))

    def test_parallel_analysis_gives_the_same_result(self) -> None:
        filler = "Lorem ipsum dolor sit amet. " * 9000
        text = (filler + SAMPLE + " ") * 3
        one = Presidio(settings(analyze_parallel=1), FakeUpstreams()).analyze(text)
        four = Presidio(settings(analyze_parallel=4), FakeUpstreams()).analyze(text)
        self.assertEqual(one, four)

    def test_large_texts_are_masked_in_segments(self) -> None:
        upstream = FakeUpstreams()
        filler = "Lorem ipsum dolor sit amet. " * 2000  # about 56,000 characters
        text = (SAMPLE + " " + filler) * 4
        presidio = Presidio(settings(), upstream)
        detections = presidio.analyze(text)
        masked = presidio.anonymize(text, review.merge_overlaps(detections), {})
        calls = [json.loads(body) for _m, url, _h, body in upstream.calls if url.endswith("/anonymize")]
        self.assertGreater(len(calls), 1)
        self.assertTrue(all(len(call["text"]) <= review.ANONYMIZE_SEGMENT_CHARS for call in calls))
        expected = text.replace("Zelda Quartermaine", "<PERSON>").replace("zq@example.test", "<EMAIL_ADDRESS>").replace("Berlin", "<LOCATION>")
        self.assertEqual(masked["masked_text"], expected)
        self.assertEqual(masked["counts"], {"PERSON": 4, "EMAIL_ADDRESS": 4, "LOCATION": 4})

    def test_segments_never_cut_a_result(self) -> None:
        results = [{"entity_type": "PERSON", "start": s, "end": s + 10, "score": 1.0} for s in range(0, 200_000, 7_000)]
        segments = review.anonymize_segments("x" * 200_010, results)
        covered = [item for _start, _end, batch in segments for item in batch]
        self.assertEqual(covered, results)
        for start, end, batch in segments:
            self.assertTrue(all(start <= item["start"] and item["end"] <= end for item in batch))
        self.assertEqual((segments[0][0], segments[-1][1]), (0, results[-1]["end"]))

    def test_pieces_overlap_and_cover_everything(self) -> None:
        for text in ("word " * 100_000, "ä€😀 " * 60_000, "x" * 300_000):
            pieces = review.analysis_pieces(text)
            self.assertTrue(all(len(piece.encode()) <= review.ANALYZE_CHUNK_BYTES for _o, piece in pieces))
            self.assertEqual(pieces[-1][0] + len(pieces[-1][1]), len(text))
            for (a, piece), (b, _next) in zip(pieces, pieces[1:]):
                self.assertLess(b, a + len(piece))


class AssistTests(unittest.TestCase):
    TEXT = "Bonjour Théophile Lavergne, numéro 1 84 12 75 123 456 78, chez Dupont SARL à Paris."

    def gateway(self, answer: Any, status: int = 200) -> Any:
        calls: list[tuple[str, dict[str, str], bytes | None]] = []

        def transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> HttpResponse:
            calls.append((url, dict(headers), body))
            if url.endswith("/v1/models"):
                return HttpResponse(200, {}, b"{}")
            if url.endswith("/chat/completions"):
                content = json.dumps(answer) if not isinstance(answer, str) else answer
                return HttpResponse(status, {}, json.dumps({"choices": [{"message": {"content": content}}]}).encode())
            payload = json.loads(body or b"{}")
            if url.endswith("/analyze"):
                calls.append(("language", {}, payload["language"].encode()))
                return HttpResponse(200, {}, json.dumps(analyzer_results(payload["text"])).encode())
            raise AssertionError(url)

        return transport, calls

    def reviewer(self, transport: Any, **overrides: Any) -> Reviewer:
        config = settings(assist_url="http://gateway:4000/v1", assist_key="sk-page-assist-key", **overrides)
        return Reviewer(config, Presidio(config, transport), None, review.AssistClient(config, transport))

    def test_language_and_model_items_are_added(self) -> None:
        answer = {
            "language": "fr",
            "items": [
                {"text": "1 84 12 75 123 456 78", "type": "ID_NUMBER"},
                {"text": "Dupont SARL", "type": "ORGANIZATION"},
                {"text": "Paris", "type": "ADDRESS"},
                {"text": "not in the text", "type": "PERSON"},
            ],
        }
        transport, calls = self.gateway(answer)
        result = self.reviewer(transport).analyze({"text": self.TEXT})
        self.assertEqual(result["language"], "fr")
        self.assertEqual(result["assist"], {"used": True, "checked_chars": len(self.TEXT), "total_chars": len(self.TEXT)})
        self.assertIn(("language", {}, b"fr"), calls)
        found = {(d["entity_type"], self.TEXT[d["start"]:d["end"]], d["recognizer"]) for d in result["detections"]}
        self.assertIn(("ID_NUMBER", "1 84 12 75 123 456 78", review.ASSIST_RECOGNIZER), found)
        self.assertIn(("ORGANIZATION", "Dupont SARL", review.ASSIST_RECOGNIZER), found)
        self.assertIn(("LOCATION", "Paris", review.ASSIST_RECOGNIZER), found)
        self.assertEqual([d["id"] for d in result["detections"]], list(range(len(result["detections"]))))
        chat = next(call for call in calls if call[0].endswith("/chat/completions"))
        self.assertEqual(chat[1]["Authorization"], "Bearer sk-page-assist-key")
        self.assertEqual(json.loads(chat[2])["model"], "pii-assist")

    def test_falls_back_to_presidio_alone(self) -> None:
        for answer, status in (({"language": "fr", "items": []}, 403), ("not json", 200)):
            with self.subTest(status=status):
                transport, calls = self.gateway(answer, status)
                result = self.reviewer(transport).analyze({"text": SAMPLE})
                self.assertEqual(result["language"], "en")
                self.assertEqual(
                    [d["entity_type"] for d in result["detections"]], ["PERSON", "EMAIL_ADDRESS", "LOCATION"]
                )

    def test_same_span_and_type_is_not_listed_twice(self) -> None:
        transport, _calls = self.gateway({"language": "en", "items": [{"text": "Berlin", "type": "ADDRESS"}, {"text": "Berlin", "type": "ORGANIZATION"}]})
        result = self.reviewer(transport).analyze({"text": SAMPLE})
        berlin = [d["entity_type"] for d in result["detections"] if SAMPLE[d["start"]:d["end"]] == "Berlin"]
        self.assertEqual(sorted(berlin), ["LOCATION", "ORGANIZATION"])

    def test_call_budget_and_chunks(self) -> None:
        transport, calls = self.gateway({"language": "en", "items": []})
        text = "word " * 4000
        result = self.reviewer(transport, assist_max_calls=2).analyze({"text": text})
        self.assertEqual(sum(1 for call in calls if call[0].endswith("/chat/completions")), 2)
        self.assertLess(result["assist"]["checked_chars"], len(text))
        pieces = review.assist_chunks(text, 4000)
        self.assertEqual("".join(piece for _offset, piece in pieces), text)
        self.assertEqual([offset for offset, _ in pieces][1], len(pieces[0][1]))

    def test_ollama_without_a_key(self) -> None:
        transport, calls = self.gateway({"language": "de", "items": []})
        config = settings(assist_url="http://host.docker.internal:11434/v1", assist_model="qwen3.5:4b")
        reviewer = Reviewer(config, Presidio(config, transport), None, review.AssistClient(config, transport))
        # No common words, so the model's language applies.
        self.assertEqual(reviewer.analyze({"text": "Zelda Quartermaine, zq@example.test, Berlin."})["language"], "de")
        chat = next(call for call in calls if call[0].endswith("/chat/completions"))
        self.assertEqual(chat[0], "http://host.docker.internal:11434/v1/chat/completions")
        self.assertNotIn("Authorization", chat[1])
        self.assertEqual(json.loads(chat[2])["model"], "qwen3.5:4b")

    def test_assist_key_setting(self) -> None:
        loaded = review.settings_from_environment({"PII_REVIEW_GATEWAYS": "http://g:4000", "PII_REVIEW_ASSIST_KEY": "sk-abcdefgh"})
        self.assertEqual(loaded.assist_key, "sk-abcdefgh")
        self.assertNotIn("sk-abcdefgh", repr(loaded))
        with self.assertRaises(ValueError):
            review.settings_from_environment({"PII_REVIEW_GATEWAYS": "http://g:4000", "PII_REVIEW_ASSIST_KEY": "bad key"})


MIXED = (
    "Dear Mr Zelda Quartermaine,\n\n"
    "Your file is with us and we will write to you from Berlin.\n\n"
    "Sehr geehrte Frau Brunhilde Kesselmeyer,\n\n"
    "Ihre Unterlagen liegen in der Lindenstraße 12, 80331 München.\n"
    "IBAN DE89 3704 0044 0532 0130 00\n\n"
    "Telefon 089 1234567\n\n"
    "Bonjour Monsieur Théophile Lavergne,\n\n"
    "Votre dossier est au 3, place de la Comédie, 34000 Montpellier.\n"
)


class LanguageSectionTests(unittest.TestCase):
    def test_paragraphs_need_clear_evidence(self) -> None:
        for paragraph, expected in (
            ("Dear Mr Thornbury,", "en"),
            ("Sehr geehrte Frau Kesselmeyer,", "de"),
            ("Bonjour Monsieur Lavergne,", "fr"),
            ("Meeting am Montag mit dem Team", "de"),
            ("Le rendez-vous est confirmé pour lundi.", "fr"),
            # One common word, none, or no clear majority: no decision.
            ("Telefon 089 1234567", None),
            ("IBAN DE89 3704 0044 0532 0130 00", None),
            ("Zelda Quartermaine, zq@example.test", None),
            ("the and der und", None),
            # Words common in two of the languages do not count.
            ("was an in so on me place plus contact", None),
        ):
            with self.subTest(paragraph=paragraph):
                self.assertEqual(languages.classify(paragraph), expected)
        for word in ("will", "also", "or", "son", "was", "an", "in"):
            with self.subTest(word=word):
                self.assertNotIn(word, languages.VOCABULARY)

    def test_paragraphs_cover_the_text(self) -> None:
        for text in ("", "one", "a\n\nb", "a\n \n\nb\n\n", MIXED):
            with self.subTest(text=text[:20]):
                spans = languages.paragraphs(text)
                self.assertEqual("".join(text[start:end] for start, end in spans), text)

    def test_mixed_text_gets_one_section_per_language(self) -> None:
        sections = languages.language_sections(MIXED, "en")
        self.assertEqual([language for _s, _e, language in sections], ["en", "de", "fr"])
        self.assertEqual((sections[0][0], sections[-1][1]), (0, len(MIXED)))
        self.assertTrue(all(a[1] == b[0] for a, b in zip(sections, sections[1:])))
        german = MIXED[sections[1][0] : sections[1][1]]
        # Unclear paragraphs stay with the section before them.
        self.assertTrue(german.startswith("Sehr geehrte"))
        self.assertIn("Telefon 089 1234567", german)
        self.assertEqual(languages.language_shares(sections)["de"], len(german))

    def test_defaults_and_leading_paragraphs(self) -> None:
        self.assertEqual(languages.language_sections("Zelda, Berlin.", "de"), [(0, 14, "de")])
        self.assertEqual(languages.language_sections("", "en"), [(0, 0, "en")])
        text = "Kesselmeyer\n\nSehr geehrte Frau Kesselmeyer, bitte rufen Sie an."
        self.assertEqual(languages.language_sections(text, "en"), [(0, len(text), "de")])
        # Languages the analyzer does not support are not chosen.
        self.assertEqual(languages.language_sections(text, "en", ("en", "fr")), [(0, len(text), "en")])

    def test_each_section_is_analysed_in_its_language(self) -> None:
        upstream = FakeUpstreams()
        config = settings()
        reviewer = Reviewer(config, Presidio(config, upstream), None)
        result = reviewer.analyze({"text": MIXED})
        sent = [json.loads(body) for _m, url, _h, body in upstream.calls if url.endswith("/analyze")]
        self.assertEqual(sorted(item["language"] for item in sent), ["de", "en", "fr"])
        for item in sent:
            self.assertIn(item["text"], MIXED)
        self.assertEqual(result["language"], "de")
        self.assertEqual(set(result["languages"]), {"en", "de", "fr"})
        self.assertEqual(sum(result["languages"].values()), len(MIXED))
        # Offsets are relative to the whole text.
        for item in result["detections"]:
            self.assertEqual(MIXED[item["start"] : item["end"]], {"PERSON": "Zelda Quartermaine", "LOCATION": "Berlin"}[item["entity_type"]])

    def test_one_language_is_one_section(self) -> None:
        upstream = FakeUpstreams()
        config = settings()
        text = SAMPLE + "\n\nThe file is with us and we will write to you."
        result = Reviewer(config, Presidio(config, upstream), None).analyze({"text": text})
        sent = [json.loads(body) for _m, url, _h, body in upstream.calls if url.endswith("/analyze")]
        self.assertEqual([(item["text"], item["language"]) for item in sent], [(text, "en")])
        self.assertEqual(result["languages"], {"en": len(text)})


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream = FakeUpstreams()
        self.settings = settings(failed_auth_per_minute=3, requests_per_minute=50, max_text_bytes=100_000, max_file_bytes=4096)
        reviewer = Reviewer(self.settings, Presidio(self.settings, self.upstream), None)
        self.service = server.Service(
            self.settings,
            reviewer,
            KeyValidator(self.settings.gateways, self.upstream),
            static_loader=lambda name: f"static {name}".encode(),
        )
        self.httpd = server.make_server(self.service, host="127.0.0.1")
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        key: str | None = VALID_KEY,
        content_type: str = "application/json",
        raw: bytes | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            headers["Content-Type"] = content_type
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        response_headers = {k.lower(): v for k, v in response.getheaders()}
        if response_headers.get("content-type", "").startswith("application/json"):
            return response.status, response_headers, json.loads(payload)
        return response.status, response_headers, payload

    def test_page_and_security_headers(self) -> None:
        status, headers, body = self.request("GET", "/", key=None)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"static index.html")
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertIn("script-src 'self'", headers["content-security-policy"])
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(self.request("GET", "/../review.py", key=None)[0], 404)
        self.assertEqual(self.request("GET", "/health", key=None)[2], {"status": "ok"})
        self.assertFalse(self.request("GET", "/api/config", key=None)[2]["documents"])

    def test_every_served_file_is_in_the_package(self) -> None:
        static = ROOT / "app" / "pii_review" / "static"
        for route, (name, _) in server.STATIC_FILES.items():
            self.assertTrue((static / name).is_file(), route)
        # The page loads nothing that the server does not serve.
        page = (static / "index.html").read_text() + (static / "app.js").read_text()
        for path in ("/app.js", "/app.css", "/codemirror.js", "/preview.css"):
            self.assertIn(path, page)
            self.assertIn(path, server.STATIC_FILES)

    def test_analyze_and_mask_round_trip(self) -> None:
        status, headers, result = self.request("POST", "/api/analyze", {"text": SAMPLE})
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual([d["entity_type"] for d in result["detections"]], ["PERSON", "EMAIL_ADDRESS", "LOCATION"])

        # Keep the location, mask the email with *, and add a term by hand.
        selections = [d for d in result["detections"] if d["entity_type"] != "LOCATION"]
        status, _, masked = self.request(
            "POST",
            "/api/mask",
            {
                "text": SAMPLE,
                "selections": selections,
                "custom_terms": ["wrote"],
                "operators": {"DEFAULT": "replace", "EMAIL_ADDRESS": "mask"},
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(masked["masked_text"], "<PERSON> <CUSTOM_TERM> to *************** from Berlin.")
        self.assertEqual(masked["counts"], {"EMAIL_ADDRESS": 1, "CUSTOM_TERM": 1, "PERSON": 1})

    def test_nothing_selected_returns_the_text_unchanged(self) -> None:
        status, _, masked = self.request("POST", "/api/mask", {"text": SAMPLE, "selections": []})
        self.assertEqual((status, masked["masked_text"]), (200, SAMPLE))
        self.assertFalse(any(url.endswith("/anonymize") for _, url, _, _ in self.upstream.calls))

    def upload(self, data: bytes, name: str = "notes.md", content_type: str = "application/octet-stream",
               key: str | None = VALID_KEY, length: int | None = None) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.putrequest("POST", "/api/analyze-document")
        if key:
            connection.putheader("Authorization", f"Bearer {key}")
        connection.putheader("Content-Type", content_type)
        connection.putheader("X-File-Name", name)
        connection.putheader("Content-Length", str(len(data) if length is None else length))
        connection.endheaders()
        if length is None:
            connection.send(data)
        response = connection.getresponse()
        body = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, body

    def test_text_document_upload(self) -> None:
        status, result = self.upload(SAMPLE.encode())
        self.assertEqual((status, result["source"], result["text"], result["ocr"]), (200, "document", SAMPLE, False))
        self.assertEqual([d["entity_type"] for d in result["detections"]], ["PERSON", "EMAIL_ADDRESS", "LOCATION"])
        # The browser sends the name URL-encoded; only the extension counts.
        self.assertEqual(self.upload(SAMPLE.encode(), name="M%C3%BCller%20notes.TXT")[0], 200)

    def test_upload_validation(self) -> None:
        self.assertEqual(self.upload(SAMPLE.encode(), key=None)[0], 401)
        self.assertEqual(self.upload(SAMPLE.encode(), content_type="application/json")[0], 415)
        self.assertEqual(self.upload(SAMPLE.encode(), name="archive.zip")[0], 415)
        self.assertEqual(self.upload(b"%PDF-1.7", name="a.pdf")[0], 503)  # no extractor configured
        self.assertEqual(self.upload(b"not a pdf", name="a.pdf")[0], 415)
        # Refused from Content-Length alone, before any body is read.
        status, body = self.upload(b"", length=self.settings.max_file_bytes + 1)
        self.assertEqual(status, 413)
        self.assertIn("limit", body["error"])
        self.assertEqual(self.upload(b"   ")[0], 422)

    def test_requires_a_key_the_gateway_accepts(self) -> None:
        status, _, body = self.request("POST", "/api/analyze", {"text": SAMPLE}, key=None)
        self.assertEqual(status, 401)
        status, _, body = self.request("POST", "/api/analyze", {"text": SAMPLE}, key="sk-wrong-key-1")
        self.assertEqual((status, body["error"]), (401, "The key was not accepted."))
        self.assertFalse(any(url.endswith("/analyze") for _, url, _, _ in self.upstream.calls))

    def test_rejected_keys_are_throttled_per_client(self) -> None:
        for _ in range(3):
            self.assertEqual(self.request("POST", "/api/mask", {}, key="sk-wrong-key-1")[0], 401)
        self.assertEqual(self.request("POST", "/api/mask", {}, key="sk-wrong-key-1")[0], 429)
        # A valid key from the same address is also held until the window ends.
        self.assertEqual(self.request("POST", "/api/mask", {}, key=VALID_KEY)[0], 429)

    def test_requests_per_key_are_limited(self) -> None:
        self.service.key_limiter = RateLimiter(1)
        self.assertEqual(self.request("POST", "/api/mask", {"text": "x", "selections": []})[0], 200)
        self.assertEqual(self.request("POST", "/api/mask", {"text": "x", "selections": []})[0], 429)

    def test_gateway_outage_is_not_an_authentication_failure(self) -> None:
        def down(*_args: Any) -> HttpResponse:
            raise OSError("down")

        self.service.validator = KeyValidator(self.settings.gateways, down)
        self.assertEqual(self.request("POST", "/api/analyze", {"text": SAMPLE})[0], 503)

    def test_request_validation(self) -> None:
        self.assertEqual(self.request("POST", "/api/analyze", raw=b"text=1", content_type="text/plain")[0], 415)
        self.assertEqual(self.request("POST", "/api/analyze", raw=b"{bad")[0], 400)
        self.assertEqual(self.request("POST", "/api/analyze", raw=b"[1]")[0], 400)
        self.assertEqual(self.request("POST", "/api/analyze", {"text": "x" * 100_001})[0], 413)
        # Refused from the Content-Length header alone, before the body is read.
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.putrequest("POST", "/api/analyze")
        connection.putheader("Authorization", f"Bearer {VALID_KEY}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(self.settings.max_body_bytes + 1))
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 413)
        connection.close()
        self.assertEqual(self.request("POST", "/api/other", {})[0], 404)
        self.assertEqual(self.request("PUT", "/api/analyze", {})[0], 405)

    def test_upstream_failures_are_generic(self) -> None:
        def broken(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> HttpResponse:
            if url.endswith("/v1/models"):
                return HttpResponse(200, {}, b"{}")
            return HttpResponse(500, {}, b"Traceback: " + (body or b""))

        self.service.reviewer.presidio.transport = broken
        status, _, body = self.request("POST", "/api/analyze", {"text": SAMPLE})
        self.assertEqual(status, 502)
        self.assertNotIn("Zelda", json.dumps(body))

    def test_logs_never_contain_content_or_keys(self) -> None:
        with self.assertLogs("pii_review", level="INFO") as captured:
            self.request("POST", "/api/analyze", {"text": SAMPLE})
            self.request("POST", "/api/mask", {"text": SAMPLE, "selections": [], "custom_terms": ["Berlin"]})
            self.request("POST", "/api/analyze", {"text": SAMPLE}, key="sk-wrong-key-1")
        output = "\n".join(captured.output)
        for secret in ("Zelda", "zq@example", "Berlin", VALID_KEY, "sk-wrong-key-1"):
            self.assertNotIn(secret, output)
        self.assertIn("POST /api/analyze 200", output)


if __name__ == "__main__":
    unittest.main()
