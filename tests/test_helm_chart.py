"""Tests for the Helm chart in deploy/helm/pii-review.

They render the chart with `helm template` (helm on PATH, or HELM=/path/helm)
and check the parts that keep the deployment as isolated and hardened as
compose.yml. They need PyYAML, a test-only dependency
(tests/requirements-chart.txt), and are skipped without it or helm:

    uv run --no-project --python 3.12 --with-requirements tests/requirements-chart.txt \
        python -m unittest tests/test_helm_chart.py
"""

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # the service itself has no third-party dependencies
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy" / "helm" / "pii-review"
HELM = os.environ.get("HELM") or shutil.which("helm")

GATEWAY = ["--set", "web.gateways={https://litellm.example.test}"]
INGRESS_FROM = [
    "--set-json",
    'networkPolicy.web.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}}}]',
]


def render(*args: str) -> list[dict]:
    """The chart's objects for these helm arguments."""
    result = subprocess.run(
        [HELM, "template", "pii-review", str(CHART), "--namespace", "pii", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RenderError(result.stderr)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


class RenderError(Exception):
    pass


def by_kind(objects: list[dict], kind: str) -> dict[str, dict]:
    return {o["metadata"]["name"]: o for o in objects if o["kind"] == kind}


def env(container: dict) -> dict[str, object]:
    return {item["name"]: item.get("value", item.get("valueFrom")) for item in container.get("env", [])}


@unittest.skipUnless(HELM and yaml, "needs helm and PyYAML")
class ChartTests(unittest.TestCase):
    def test_gateways_are_required(self):
        with self.assertRaises(RenderError) as caught:
            render()
        self.assertIn("gateways", str(caught.exception))

    def test_renders_the_four_services(self):
        objects = render(*GATEWAY)
        deployments = by_kind(objects, "Deployment")
        self.assertEqual(
            sorted(deployments),
            ["pii-review-analyzer", "pii-review-anonymizer", "pii-review-web", "pii-review-xberg"],
        )
        self.assertEqual(
            sorted(by_kind(objects, "Service")),
            ["pii-review-analyzer", "pii-review-anonymizer", "pii-review-web", "pii-review-xberg"],
        )

    def test_every_pod_is_hardened(self):
        for name, deployment in by_kind(render(*GATEWAY), "Deployment").items():
            with self.subTest(name):
                pod = deployment["spec"]["template"]["spec"]
                self.assertIs(pod["automountServiceAccountToken"], False)
                # A Service named pii-review would otherwise inject
                # PII_REVIEW_PORT=tcp://… into the page's environment.
                self.assertIs(pod["enableServiceLinks"], False)
                self.assertIs(pod["securityContext"]["runAsNonRoot"], True)
                self.assertNotEqual(pod["securityContext"]["runAsUser"], 0)
                self.assertEqual(pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
                for container in pod["containers"]:
                    context = container["securityContext"]
                    self.assertIs(context["readOnlyRootFilesystem"], True)
                    self.assertIs(context["allowPrivilegeEscalation"], False)
                    self.assertEqual(context["capabilities"]["drop"], ["ALL"])
                    self.assertIn("memory", container["resources"]["limits"])
                    self.assertNotIn("hostPath", json.dumps(pod.get("volumes", [])))

    def test_backends_have_no_dns(self):
        # A lookup the network policy drops takes 20 seconds; Presidio's email
        # recognizer makes one (tldextract), past gunicorn's worker timeout.
        deployments = by_kind(render(*GATEWAY), "Deployment")
        for name in ("pii-review-analyzer", "pii-review-anonymizer", "pii-review-xberg"):
            with self.subTest(name):
                pod = deployments[name]["spec"]["template"]["spec"]
                self.assertEqual(pod["dnsPolicy"], "None")
                self.assertEqual(pod["dnsConfig"]["nameservers"], ["127.0.0.1"])
        self.assertNotIn("dnsPolicy", deployments["pii-review-web"]["spec"]["template"]["spec"])

    def test_page_reaches_the_backends_by_release_name(self):
        web = by_kind(render(*GATEWAY), "Deployment")["pii-review-web"]
        values = env(web["spec"]["template"]["spec"]["containers"][0])
        self.assertEqual(values["PII_REVIEW_ANALYZER_URL"], "http://pii-review-analyzer:3000")
        self.assertEqual(values["PII_REVIEW_ANONYMIZER_URL"], "http://pii-review-anonymizer:3000")
        self.assertEqual(values["PII_REVIEW_XBERG_URL"], "http://pii-review-xberg:8000")
        self.assertEqual(values["PII_REVIEW_GATEWAYS"], "https://litellm.example.test")
        self.assertEqual(values["PII_REVIEW_MAX_FILE_BYTES"], "209715200")
        self.assertEqual(values["PII_REVIEW_ANALYZE_PARALLEL"], "2")
        self.assertNotIn("PII_REVIEW_ASSIST_KEY", values)

    def test_backends_accept_only_the_page_and_reach_nothing(self):
        policies = by_kind(render(*GATEWAY), "NetworkPolicy")
        deny = policies["pii-review-default-deny"]["spec"]
        self.assertEqual(deny["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", deny)
        self.assertNotIn("egress", deny)
        for name in ("pii-review-analyzer", "pii-review-anonymizer", "pii-review-xberg"):
            with self.subTest(name):
                spec = policies[name]["spec"]
                self.assertEqual(spec["egress"], [])
                (rule,) = spec["ingress"]
                (peer,) = rule["from"]
                self.assertEqual(peer["podSelector"]["matchLabels"]["app.kubernetes.io/component"], "web")
        self.assertEqual(policies["pii-review-web"]["spec"]["ingress"], [])

    def test_public_route_needs_the_proxy_selected(self):
        with self.assertRaises(RenderError) as caught:
            render(*GATEWAY, "--set", "web.ingress.enabled=true", "--set", "web.ingress.hosts={pii.example.test}")
        self.assertIn("ingressFrom", str(caught.exception))
        objects = render(
            *GATEWAY, *INGRESS_FROM, "--set", "web.ingress.enabled=true", "--set", "web.ingress.hosts={pii.example.test}"
        )
        ingress = by_kind(objects, "Ingress")["pii-review-web"]
        self.assertEqual(ingress["metadata"]["annotations"]["nginx.ingress.kubernetes.io/proxy-body-size"], "250m")
        (rule,) = by_kind(objects, "NetworkPolicy")["pii-review-web"]["spec"]["ingress"]
        self.assertEqual(rule["ports"], [{"port": 8080, "protocol": "TCP"}])

    def test_assist_key_goes_through_a_secret(self):
        objects = render(*GATEWAY, "--set", "web.assist.url=http://ollama:11434/v1", "--set", "web.assist.key=sk-test")
        self.assertIn("pii-review-web", by_kind(objects, "Secret"))
        web = by_kind(objects, "Deployment")["pii-review-web"]["spec"]["template"]
        self.assertIn("checksum/secret", web["metadata"]["annotations"])
        key = env(web["spec"]["containers"][0])["PII_REVIEW_ASSIST_KEY"]
        self.assertEqual(key["secretKeyRef"], {"name": "pii-review-web", "key": "assist-key"})
        with self.assertRaises(RenderError):
            render(*GATEWAY, "--set", "web.assist.key=sk-test", "--set", "web.assist.existingSecret=mine")

    def test_gpu_mode(self):
        objects = render(*GATEWAY, "--set", "analyzer.gpu.enabled=true", "--set", "analyzer.replicas=2")
        analyzer = by_kind(objects, "Deployment")["pii-review-analyzer"]
        container = analyzer["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["image"], "pii-review-presidio-analyzer:2.2.362-2-gpu")
        self.assertEqual(container["resources"]["limits"]["nvidia.com/gpu"], 1)
        values = env(container)
        self.assertEqual(values["PRESIDIO_DEVICE"], "cuda")
        self.assertEqual(values["WORKERS"], "1")
        self.assertNotIn("--preload", values["GUNICORN_CMD_ARGS"])
        self.assertEqual(analyzer["spec"]["strategy"], {"type": "Recreate"})
        web = by_kind(objects, "Deployment")["pii-review-web"]
        self.assertEqual(env(web["spec"]["template"]["spec"]["containers"][0])["PII_REVIEW_ANALYZE_PARALLEL"], "2")
        self.assertIn("pii-review-analyzer", by_kind(objects, "PodDisruptionBudget"))

    def test_registry_and_digest(self):
        digest = "sha256:" + "a" * 64
        objects = render(*GATEWAY, "--set", "global.imageRegistry=ghcr.io/example", "--set", f"web.image.digest={digest}")
        images = {
            name: d["spec"]["template"]["spec"]["containers"][0]["image"]
            for name, d in by_kind(objects, "Deployment").items()
        }
        self.assertEqual(images["pii-review-web"], f"ghcr.io/example/pii-review:0.4.0@{digest}")
        self.assertEqual(images["pii-review-xberg"], "ghcr.io/example/pii-review-xberg:1.3.10-1")
        self.assertTrue(images["pii-review-anonymizer"].startswith("mcr.microsoft.com/presidio-anonymizer:2.2.362@sha256:"))

    def test_schema_rejects_bad_values(self):
        for args in (
            ["--set", "web.gateways={ftp://x}"],
            [*GATEWAY, "--set", "web.language=it"],
            [*GATEWAY, "--set", "web.maxFileBytes=300000000"],
            [*GATEWAY, "--set", "web.unknownSetting=1"],
        ):
            with self.subTest(args), self.assertRaises(RenderError):
                render(*args)


if __name__ == "__main__":
    sys.exit(unittest.main())
