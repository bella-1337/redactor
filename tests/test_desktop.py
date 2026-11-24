"""Tests for the desktop entry point (app/pii_review/desktop.py).

Presidio itself is not installed for these tests: InProcessPresidio is checked
with stand-ins, and the local-token mode through the real HTTP server.
"""

from __future__ import annotations

import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from pii_review import desktop, review, server  # noqa: E402
from pii_review.review import LocalTokenValidator  # noqa: E402

TOKEN = "t" * 43


class FakeResult:
    def __init__(self, entity_type: str, start: int, end: int, score: float) -> None:
        self.entity_type, self.start, self.end, self.score = entity_type, start, end, score

    def to_dict(self) -> dict[str, Any]:
        return {"entity_type": self.entity_type, "start": self.start, "end": self.end, "score": self.score}


class FakeAnalyzer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def analyze(self, text: str, language: str) -> list[FakeResult]:
        self.calls.append((text, language))
        start = text.find("Alice")
        return [FakeResult("PERSON", start, start + 5, 0.85)] if start >= 0 else []


class FailingAnalyzer:
    def analyze(self, text: str, language: str) -> list[FakeResult]:
        raise RuntimeError("model failure that quotes " + text)


class SettingsFileTests(unittest.TestCase):
    def write(self, content: str) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False, encoding="utf-8")
        with handle:
            handle.write(content)
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_reads_known_keys_and_ignores_others(self) -> None:
        path = self.write(
            "# comment\nPII_REVIEW_LANGUAGE=de\nPII_REVIEW_ANALYZER_URL=http://evil\n"
            "PII_REVIEW_ASSIST_MODEL='qwen3.5:4b'\nnot a setting\n"
        )
        values = desktop.read_settings_file(path)
        self.assertEqual(values, {"PII_REVIEW_LANGUAGE": "de", "PII_REVIEW_ASSIST_MODEL": "qwen3.5:4b"})

    def test_missing_file_is_empty(self) -> None:
        self.assertEqual(desktop.read_settings_file(Path("/nonexistent/settings.env")), {})
        self.assertEqual(desktop.read_settings_file(None), {})

    def test_desktop_settings_use_local_auth_and_own_services(self) -> None:
        path = self.write("PII_REVIEW_LANGUAGE=fr\n")
        settings = desktop.desktop_settings(path, "http://127.0.0.1:5555", environ={})
        self.assertEqual(settings.auth, "local")
        self.assertEqual(settings.gateways, ())
        self.assertEqual(settings.language, "fr")
        self.assertEqual(settings.port, 0)
        self.assertEqual(settings.analyze_parallel, 1)
        self.assertEqual(settings.analyzer_url, desktop.ANALYZER_URL)
        self.assertEqual(settings.anonymizer_url, desktop.ANONYMIZER_URL)
        self.assertEqual(settings.xberg_url, "http://127.0.0.1:5555")

    def test_service_urls_cannot_be_overridden(self) -> None:
        environ = {"PII_REVIEW_ANALYZER_URL": "http://elsewhere:3000", "PII_REVIEW_AUTH": "gateway"}
        settings = desktop.desktop_settings(None, "http://127.0.0.1:5555", environ=environ)
        self.assertEqual(settings.analyzer_url, desktop.ANALYZER_URL)
        self.assertEqual(settings.auth, "local")

    def test_gateways_switch_to_key_sign_in(self) -> None:
        environ = {"PII_REVIEW_GATEWAYS": "https://litellm.example.test"}
        settings = desktop.desktop_settings(None, "http://127.0.0.1:5555", environ=environ)
        self.assertEqual(settings.auth, "gateway")
        self.assertEqual(settings.gateways, ("https://litellm.example.test",))

    def test_invalid_setting_is_refused(self) -> None:
        path = self.write("PII_REVIEW_LANGUAGE=english\n")
        with self.assertRaises(ValueError):
            desktop.desktop_settings(path, "http://127.0.0.1:5555", environ={})


class AuthSettingTests(unittest.TestCase):
    def test_local_auth_needs_no_gateway(self) -> None:
        loaded = review.settings_from_environment({"PII_REVIEW_AUTH": "local"})
        self.assertEqual(loaded.auth, "local")

    def test_gateway_auth_still_needs_a_gateway(self) -> None:
        with self.assertRaises(ValueError):
            review.settings_from_environment({"PII_REVIEW_AUTH": "gateway"})

    def test_unknown_auth_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            review.settings_from_environment({"PII_REVIEW_AUTH": "none", "PII_REVIEW_GATEWAYS": "http://g"})

    def test_server_refuses_local_auth(self) -> None:
        from unittest import mock

        with mock.patch.dict("os.environ", {"PII_REVIEW_AUTH": "local"}, clear=True):
            self.assertEqual(server.main(), 2)


class LocalTokenValidatorTests(unittest.TestCase):
    def test_accepts_only_the_token(self) -> None:
        validator = LocalTokenValidator(TOKEN)
        self.assertTrue(validator.check(TOKEN))
        self.assertFalse(validator.check(TOKEN[:-1]))
        self.assertFalse(validator.check(TOKEN + "x"))
        self.assertFalse(validator.check("é" * 43))

    def test_fingerprint_hides_the_token(self) -> None:
        validator = LocalTokenValidator(TOKEN)
        self.assertNotIn(TOKEN, validator.fingerprint(TOKEN))
        self.assertEqual(validator.fingerprint(TOKEN), validator.fingerprint(TOKEN))

    def test_short_token_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            LocalTokenValidator("short")


class InProcessPresidioTests(unittest.TestCase):
    def test_analyze_answers_rest_json(self) -> None:
        analyzer = FakeAnalyzer()
        transport = desktop.InProcessPresidio(analyzer, anonymizer=None)
        body = json.dumps({"text": "Hi Alice", "language": "de"}).encode()
        response = transport("POST", f"{desktop.ANALYZER_URL}/analyze", {}, body, 10)
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body), [{"end": 8, "entity_type": "PERSON", "score": 0.85, "start": 3}])
        self.assertEqual(analyzer.calls, [("Hi Alice", "de")])

    def test_other_urls_are_refused(self) -> None:
        transport = desktop.InProcessPresidio(FakeAnalyzer(), anonymizer=None)
        body = json.dumps({"text": "x", "language": "en"}).encode()
        self.assertEqual(transport("POST", "http://example.test/analyze", {}, body, 10).status, 404)
        self.assertEqual(transport("GET", f"{desktop.ANALYZER_URL}/analyze", {}, None, 10).status, 405)

    def test_failure_is_an_upstream_error_without_content(self) -> None:
        transport = desktop.InProcessPresidio(FailingAnalyzer(), anonymizer=None)
        body = json.dumps({"text": "secret text", "language": "en"}).encode()
        with self.assertLogs("pii_review.desktop", "ERROR") as logs:
            response = transport("POST", f"{desktop.ANALYZER_URL}/analyze", {}, body, 10)
        self.assertEqual(response.status, 500)
        self.assertNotIn("secret", "".join(logs.output))
        presidio = review.Presidio(review.Settings(gateways=(), analyzer_url=desktop.ANALYZER_URL), transport)
        with self.assertRaises(review.UpstreamError):
            presidio.analyze("secret text", "en")


class XbergProcessTests(unittest.TestCase):
    def test_never_starts_after_stop(self) -> None:
        with tempfile.TemporaryDirectory() as resources:
            xberg = desktop.XbergProcess(Path(resources))
            xberg.stop()
            with self.assertRaises(desktop.Stopping):
                xberg.start()
            self.assertIsNone(xberg.process)
            self.assertFalse(xberg.scratch.exists())

    def test_environment_keeps_caches_in_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as resources:
            xberg = desktop.XbergProcess(Path(resources))
            self.addCleanup(xberg.stop)
            environment = xberg.environment()
            self.assertEqual(environment["TESSDATA_PREFIX"], str(Path(resources) / "tessdata"))
            for key in ("XBERG_CACHE_DIR", "HF_HOME", "HOME", "TMPDIR"):
                self.assertTrue(environment[key].startswith(str(xberg.scratch)), key)
            self.assertTrue(xberg.url.startswith("http://127.0.0.1:"))


class LocalAuthServerTests(unittest.TestCase):
    def setUp(self) -> None:
        settings = desktop.desktop_settings(None, "http://127.0.0.1:9", environ={})
        transport = desktop.InProcessPresidio(FakeAnalyzer(), anonymizer=None)
        self.service = desktop.build_desktop_service(settings, transport, TOKEN)
        self.httpd = server.make_server(self.service, "127.0.0.1")
        self.port = self.httpd.server_address[1]
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def request(self, method: str, path: str, body: bytes | None = None, token: str | None = None) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload

    def test_listens_on_loopback_only(self) -> None:
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")

    def test_config_reports_local_auth(self) -> None:
        status, config = self.request("GET", "/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(config["auth"], "local")

    def test_analyze_with_the_token(self) -> None:
        body = json.dumps({"text": "Hello Alice, how are you?"}).encode()
        status, result = self.request("POST", "/api/analyze", body, TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual([item["entity_type"] for item in result["detections"]], ["PERSON"])

    def test_analyze_without_or_with_a_wrong_token(self) -> None:
        body = json.dumps({"text": "Hello Alice"}).encode()
        for token in (None, "x" * 43):
            status, result = self.request("POST", "/api/analyze", body, token)
            self.assertEqual(status, 401)
            self.assertIn("Restart PII Review", result["error"])


if __name__ == "__main__":
    unittest.main()
