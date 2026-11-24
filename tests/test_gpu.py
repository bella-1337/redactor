"""Tests for the desktop app's GPU support (app/pii_review/gpu.py).

No GPU, CuPy, or network is needed: the checks run stand-in scripts in a
separate interpreter, as the real ones do, and the GPU pack is downloaded
from a stand-in for PyPI.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from pii_review import desktop, gpu  # noqa: E402

GIB = 1024**3


def answer(name: str = "NVIDIA RTX 4000", free: int = 8 * GIB) -> str:
    """A stand-in GPU check that succeeds."""
    return f"import json; print(json.dumps({{'name': {name!r}, 'free': {free}, 'total': {free}}}))"


class DeviceSettingTests(unittest.TestCase):
    def test_default_is_auto(self) -> None:
        self.assertEqual(gpu.device_setting({}), "auto")
        self.assertEqual(gpu.device_setting({"PII_REVIEW_DEVICE": " CPU "}), "cpu")

    def test_unknown_value_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "auto or cpu"):
            gpu.device_setting({"PII_REVIEW_DEVICE": "cuda"})

    def test_settings_file_may_set_it(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.env"
            path.write_text("PII_REVIEW_DEVICE=cpu\n", encoding="utf-8")
            self.assertEqual(gpu.device_setting(desktop.user_values(path, environ={})), "cpu")


class ChooseDeviceTests(unittest.TestCase):
    def test_cpu_setting_never_checks(self) -> None:
        device = gpu.choose_device("cpu", bundled=True, probe="raise SystemExit('ran')")
        self.assertEqual(device, gpu.Device(None, "PII_REVIEW_DEVICE=cpu"))

    def test_without_cupy_there_is_nothing_to_check(self) -> None:
        device = gpu.choose_device("auto", bundled=False, probe="raise SystemExit('ran')")
        self.assertIsNone(device.gpu)
        self.assertIn("no GPU support", device.note)

    def test_working_gpu_is_used(self) -> None:
        device = gpu.choose_device("auto", bundled=True, probe=answer())
        self.assertEqual(device.gpu, "NVIDIA RTX 4000")
        self.assertEqual(device.describe(), "GPU (NVIDIA RTX 4000)")

    def test_gpu_without_room_for_the_models_is_not_used(self) -> None:
        device = gpu.choose_device("auto", bundled=True, probe=answer(free=2 * GIB))
        self.assertIsNone(device.gpu)
        self.assertIn("2.0 GiB free", device.note)

    def test_failed_check_names_the_error_only(self) -> None:
        probe = "import sys; sys.stderr.write('Traceback...\\nValueError: No GPU devices detected\\n'); sys.exit(1)"
        device = gpu.choose_device("auto", bundled=True, probe=probe)
        self.assertIsNone(device.gpu)
        self.assertEqual(device.note, "no usable NVIDIA GPU: ValueError: No GPU devices detected")

    def test_crashing_check_means_cpu(self) -> None:
        probe = "import os; os.abort()"
        self.assertIsNone(gpu.choose_device("auto", bundled=True, probe=probe).gpu)

    def test_hanging_check_is_stopped(self) -> None:
        processes: list[Any] = []
        device = gpu.choose_device(
            "auto", bundled=True, probe="import time; time.sleep(60)", timeout=0.5, started=processes.append
        )
        self.assertIsNone(device.gpu)
        self.assertIn("took over", device.note)
        self.assertIsNotNone(processes[0].poll())

    def test_unreadable_answer_means_cpu(self) -> None:
        self.assertEqual(gpu.choose_device("auto", bundled=True, probe="print('hello')").note, "the GPU check gave no answer")

    def test_pack_folder_is_given_to_the_check(self) -> None:
        probe = "import sys, json; print(json.dumps({'name': sys.argv[1], 'free': 2**40}))"
        device = gpu.choose_device("auto", pack_site=Path("/pack/site"), probe=probe)
        self.assertEqual(device.gpu, str(Path("/pack/site")))


class DriverCheckTests(unittest.TestCase):
    def test_cuda_12_driver_is_enough(self) -> None:
        self.assertEqual(gpu.nvidia_gpu_present(check="print(1, 12080)"), (True, ""))

    def test_old_driver_is_not(self) -> None:
        present, reason = gpu.nvidia_gpu_present(check="print(1, 11080)")
        self.assertFalse(present)
        self.assertIn("CUDA 11.8", reason)

    def test_no_driver(self) -> None:
        present, reason = gpu.nvidia_gpu_present(check="raise OSError('libcuda.so.1: cannot open shared object file')")
        self.assertFalse(present)
        self.assertIn("libcuda.so.1", reason)


class BlockCupyTests(unittest.TestCase):
    def test_import_fails_after_blocking(self) -> None:
        saved = {name: sys.modules.pop(name) for name in ("cupy", "cupyx", "cupy_backends") if name in sys.modules}
        self.addCleanup(lambda: [sys.modules.pop(name, None) for name in ("cupy", "cupyx", "cupy_backends")])
        self.addCleanup(sys.modules.update, saved)
        gpu.block_cupy()
        with self.assertRaises(ImportError):
            import cupy  # noqa: F401


# ---------------------------------------------------------------------------
# The GPU pack
# ---------------------------------------------------------------------------


def make_wheel(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class FakePyPI:
    """Serves wheels by URL for urllib.request.urlopen."""

    def __init__(self, wheels: dict[str, bytes]) -> None:
        self.wheels = wheels
        self.requested: list[str] = []

    def urlopen(self, request: Any, timeout: float, context: Any) -> io.BytesIO:
        self.requested.append(request.full_url)
        return io.BytesIO(self.wheels[request.full_url])


class GpuPackTests(unittest.TestCase):
    TARGET = "x86_64-unknown-linux-gnu"

    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.root = self.folder / "gpu"
        self.contents = {
            "fakecupy-1.0-cp312-cp312-manylinux_x86_64.whl": make_wheel(
                {"fakecupy/__init__.py": b"VALUE = 1\n", "fakecupy-1.0.dist-info/METADATA": b"Name: fakecupy\n"}
            ),
            "fakenvidia-1.0-py3-none-manylinux_x86_64.whl": make_wheel(
                {
                    "nvidia/cublas/lib/libcublas.so.12": b"\x7fELF",
                    "fakenvidia-1.0.data/platlib/nvidia/extra.txt": b"platlib",
                    "fakenvidia-1.0.data/scripts/tool": b"#!/bin/sh\n",
                }
            ),
        }

    def manifest(self, contents: dict[str, bytes] | None = None, **change: Any) -> Path:
        contents = self.contents if contents is None else contents
        wheels = [
            {
                "name": name,
                "url": f"https://files.pythonhosted.org/packages/ab/{name}",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                **change,
            }
            for name, data in contents.items()
        ]
        path = self.folder / "gpu-pack.json"
        path.write_text(json.dumps({"targets": {self.TARGET: wheels}}), encoding="utf-8")
        return path

    def pypi(self, contents: dict[str, bytes] | None = None) -> FakePyPI:
        contents = self.contents if contents is None else contents
        return FakePyPI({f"https://files.pythonhosted.org/packages/ab/{name}": data for name, data in contents.items()})

    def test_install_unpacks_and_marks_the_pack(self) -> None:
        pack = gpu.GpuPack(self.manifest(), self.root, target=self.TARGET)
        self.assertTrue(pack.available)
        self.assertFalse(pack.installed())
        (self.root / "pack-0123456789abcdef").mkdir(parents=True)  # an older pin's pack
        progress: list[tuple[int, int]] = []
        with mock.patch.object(gpu.urllib.request, "urlopen", self.pypi().urlopen):
            pack.install(lambda done, total: progress.append((done, total)))
        self.assertTrue(pack.installed())
        self.assertEqual((pack.site / "fakecupy" / "__init__.py").read_bytes(), b"VALUE = 1\n")
        self.assertTrue((pack.site / "nvidia" / "cublas" / "lib" / "libcublas.so.12").is_file())
        self.assertEqual((pack.site / "nvidia" / "extra.txt").read_bytes(), b"platlib")
        self.assertFalse((pack.site / "tool").exists())
        self.assertEqual([path.name for path in self.root.iterdir()], [pack.name])
        self.assertEqual(progress[-1], (pack.download_bytes, pack.download_bytes))

    def test_wrong_hash_leaves_nothing_usable(self) -> None:
        pack = gpu.GpuPack(self.manifest(), self.root, target=self.TARGET)
        tampered = dict(self.contents)
        tampered["fakecupy-1.0-cp312-cp312-manylinux_x86_64.whl"] = make_wheel({"fakecupy/__init__.py": b"EVIL\n"})
        with mock.patch.object(gpu.urllib.request, "urlopen", self.pypi(tampered).urlopen):
            with self.assertRaisesRegex(gpu.PackError, "SHA-256|larger"):
                pack.install()
        self.assertFalse(pack.installed())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unsafe_paths_are_refused(self) -> None:
        for name in ("../escape.py", "/abs.py", "a/../../escape.py", "C:/x.py"):
            with self.subTest(name=name):
                contents = {"bad-1.0-py3-none-any.whl": make_wheel({name: b"x"})}
                pack = gpu.GpuPack(self.manifest(contents), self.root, target=self.TARGET)
                with mock.patch.object(gpu.urllib.request, "urlopen", self.pypi(contents).urlopen):
                    with self.assertRaisesRegex(gpu.PackError, "unsafe path"):
                        pack.install()
                self.assertFalse((self.folder / "escape.py").exists())
                self.assertFalse(pack.installed())

    def test_only_pypi_over_https(self) -> None:
        with self.assertRaisesRegex(ValueError, "PyPI over https"):
            gpu.GpuPack(self.manifest(url="http://example.test/x.whl"), self.root, target=self.TARGET)

    def test_no_pack_without_a_folder_or_for_other_platforms(self) -> None:
        self.assertFalse(gpu.GpuPack(self.manifest(), None, target=self.TARGET).available)
        self.assertFalse(gpu.GpuPack(self.manifest(), self.root, target="aarch64-apple-darwin").available)

    def test_the_shipped_manifest_is_valid(self) -> None:
        manifest = ROOT / "desktop" / "runtime" / "gpu-pack.json"
        for target in ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"):
            pack = gpu.GpuPack(manifest, self.root, target=target)
            names = " ".join(wheel["name"] for wheel in pack.wheels)
            self.assertIn("cupy_cuda12x", names)
            self.assertIn("nvidia_cublas_cu12", names)
        self.assertFalse(gpu.GpuPack(manifest, self.root, target="aarch64-apple-darwin").available)


class PickDeviceTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        manifest = Path(folder.name) / "gpu-pack.json"
        wheel = {"name": "x-1-py3-none-any.whl", "url": "https://files.pythonhosted.org/x-1-py3-none-any.whl",
                 "sha256": "0" * 64, "size": 1}
        manifest.write_text(json.dumps({"targets": {"t": [wheel]}}), encoding="utf-8")
        self.pack = gpu.GpuPack(manifest, Path(folder.name) / "gpu", target="t")
        emit = mock.patch.object(desktop, "emit")
        emit.start()
        self.addCleanup(emit.stop)

    def test_cpu_setting_downloads_nothing(self) -> None:
        with mock.patch.object(desktop, "nvidia_gpu_present") as present:
            device, download = desktop.pick_device("cpu", self.pack, lambda process: None)
        present.assert_not_called()
        self.assertEqual((device.gpu, download), (None, False))

    def test_nvidia_gpu_without_pack_starts_the_download(self) -> None:
        with mock.patch.object(desktop, "nvidia_gpu_present", return_value=(True, "")):
            device, download = desktop.pick_device("auto", self.pack, lambda process: None)
        self.assertEqual((device.gpu, download), (None, True))

    def test_no_nvidia_gpu_downloads_nothing(self) -> None:
        with mock.patch.object(desktop, "nvidia_gpu_present", return_value=(False, "no NVIDIA GPU")):
            device, download = desktop.pick_device("auto", self.pack, lambda process: None)
        self.assertEqual((device, download), (gpu.Device(None, "no NVIDIA GPU"), False))


class InProcessPresidioDeviceTests(unittest.TestCase):
    def test_each_request_thread_uses_the_models_device(self) -> None:
        threads: list[str] = []

        class Analyzer:
            def analyze(self, text: str, language: str) -> list[Any]:
                return []

        transport = desktop.InProcessPresidio(Analyzer(), None, lambda: threads.append(threading.current_thread().name))
        body = json.dumps({"text": "x", "language": "en"}).encode()
        worker = threading.Thread(
            target=transport, args=("POST", f"{desktop.ANALYZER_URL}/analyze", {}, body, 5), name="request-1"
        )
        worker.start()
        worker.join()
        self.assertEqual(threads, ["request-1"])


if __name__ == "__main__":
    unittest.main()
