"""NVIDIA GPU support for the desktop app's spaCy pipelines.

The installers bundle no CUDA code: CuPy and the CUDA libraries take 1.5 GB,
which would push them past NSIS's, MSI's, and GitHub releases' 2 GB limits.
Instead, on Windows and Linux x64:

1. On a start without the GPU pack, `nvidia_gpu_present` asks the NVIDIA driver
   whether there is a CUDA 12 capable GPU. If so, `GpuPack.install` downloads
   the pack (CuPy and the CUDA wheels pinned in gpu-pack.json, about 850 MB)
   in the background, checks each wheel's SHA-256, and unpacks it into the
   app's local data folder. This start runs on the CPU.
2. On later starts, the pack's folder is added to sys.path, and `choose_device`
   checks in a separate interpreter that the GPU runs thinc's operations
   correctly and has room for the pipelines. If anything fails, the pipelines
   run on the CPU, exactly as without the pack (`block_cupy`).

PII_REVIEW_DEVICE=cpu skips all of it: no driver check, download, or GPU.
"""

from __future__ import annotations

import gc
import hashlib
import importlib.util
import json
import logging
import os
import platform
import shutil
import ssl
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

LOG = logging.getLogger("pii_review.gpu")

# PII_REVIEW_DEVICE: "auto" runs the spaCy pipelines on an NVIDIA GPU when one
# works, "cpu" never uses or downloads anything for one.
DEVICE_SETTINGS = ("auto", "cpu")

GPU_PROBE_SECONDS = 90
DRIVER_CHECK_SECONDS = 30
# The three pipelines take about 2 GiB of GPU memory, their vectors most of it;
# one 100 KB piece of text needs little more.
GPU_MIN_FREE_BYTES = 3 * 1024**3
# CUDA 12 needs driver API version 12.0 or later (driver 525 or later).
MIN_DRIVER_VERSION = 12000
# Downloaded wheels plus their unpacked files, with room to spare.
PACK_MIN_FREE_DISK_BYTES = 4 * 1024**3
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
DOWNLOAD_HOST = "files.pythonhosted.org"

# Asks the driver through its own library, without CuPy. Run in a separate
# interpreter, like the GPU check: a broken driver cannot crash the engine.
DRIVER_CHECK = r"""
import ctypes
import sys

if sys.platform == "win32":
    cuda = ctypes.WinDLL("nvcuda.dll")
else:
    cuda = ctypes.CDLL("libcuda.so.1")
if cuda.cuInit(0) != 0:
    raise SystemExit("cuInit failed")
count, version = ctypes.c_int(0), ctypes.c_int(0)
if cuda.cuDeviceGetCount(ctypes.byref(count)) != 0 or count.value < 1:
    raise SystemExit("no CUDA device")
if cuda.cuDriverGetVersion(ctypes.byref(version)) != 0:
    raise SystemExit("no driver version")
print(count.value, version.value)
"""

# Does what the pipelines will: thinc on CuPy, cuBLAS, and thinc's kernels
# compiled with NVRTC, checked against the CPU's results. Its argument, if
# any, is the GPU pack's folder.
GPU_PROBE = r"""
import json
import sys

if len(sys.argv) > 1:
    sys.path.append(sys.argv[1])

import cupy
import numpy
from thinc.api import NumpyOps, get_current_ops, require_gpu

require_gpu(0)
ops = get_current_ops()
cpu = NumpyOps()
x = numpy.arange(48, dtype="float32").reshape(6, 8) / 48
x_gpu = ops.asarray2f(x)
checks = {
    "cuBLAS": (cpu.gemm(x, x, trans2=True), ops.gemm(x_gpu, x_gpu, trans2=True)),
    "NVRTC": (cpu.seq2col(x, 1), ops.seq2col(x_gpu, 1)),
}
for name, (want, got) in checks.items():
    if not numpy.allclose(want, ops.to_numpy(got), atol=1e-5):
        raise SystemExit(f"{name} gives wrong results on the GPU")
free, total = cupy.cuda.runtime.memGetInfo()
name = cupy.cuda.runtime.getDeviceProperties(0)["name"]
if isinstance(name, bytes):
    name = name.decode("utf-8", "replace")
print(json.dumps({"name": name, "free": int(free), "total": int(total)}))
"""

Started = Callable[["subprocess.Popen[bytes]"], None]


@dataclass(frozen=True)
class Device:
    """Where the spaCy pipelines run."""

    gpu: str | None  # the NVIDIA GPU's name, or None for the CPU
    note: str  # why, for the log

    def describe(self) -> str:
        return f"GPU ({self.gpu})" if self.gpu else f"CPU ({self.note})"


def device_setting(values: Mapping[str, str]) -> str:
    setting = values.get("PII_REVIEW_DEVICE", "").strip().lower() or "auto"
    if setting not in DEVICE_SETTINGS:
        raise ValueError("PII_REVIEW_DEVICE must be auto or cpu")
    return setting


def runtime_target() -> str | None:
    """The target triple build_runtime.py uses for this computer, if it has GPU support."""
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        if sys.platform.startswith("linux"):
            return "x86_64-unknown-linux-gnu"
        if sys.platform == "win32":
            return "x86_64-pc-windows-msvc"
    return None


def _no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _run_check(
    code: str, args: list[str], timeout: float, python: str, started: Started
) -> tuple[int | None, str, str]:
    """Run `code` in a separate, isolated interpreter: (exit code or None on timeout, stdout, last stderr line)."""
    try:
        process = subprocess.Popen(
            [python, "-I", "-c", code, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_no_window(),
        )
    except OSError as error:
        return 1, "", f"could not run: {type(error).__name__}"
    started(process)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return None, "", ""
    # The last line names the error (for example cudaErrorNoDevice); it holds no content.
    lines = stderr.decode("utf-8", "replace").strip().splitlines()
    detail = lines[-1][:200] if lines else f"exit code {process.returncode}"
    return process.returncode, stdout.decode("utf-8", "replace"), detail


def nvidia_gpu_present(
    *,
    python: str = sys.executable,
    check: str = DRIVER_CHECK,
    timeout: float = DRIVER_CHECK_SECONDS,
    started: Started = lambda process: None,
) -> tuple[bool, str]:
    """Whether the NVIDIA driver reports a GPU it can run CUDA 12 on, and why not."""
    code, stdout, detail = _run_check(check, [], timeout, python, started)
    if code is None:
        return False, "the NVIDIA driver did not answer"
    if code != 0:
        return False, f"no NVIDIA GPU: {detail}"
    try:
        _, version = (int(part) for part in stdout.split())
    except ValueError:
        return False, "the NVIDIA driver gave no answer"
    if version < MIN_DRIVER_VERSION:
        return False, f"the NVIDIA driver supports CUDA {version // 1000}.{version % 1000 // 10}, the app needs 12"
    return True, ""


def choose_device(
    setting: str,
    *,
    pack_site: Path | None = None,
    bundled: bool | None = None,
    python: str = sys.executable,
    probe: str = GPU_PROBE,
    timeout: float = GPU_PROBE_SECONDS,
    started: Started = lambda process: None,
) -> Device:
    """Use the first NVIDIA GPU if it runs thinc's operations correctly and has room
    for the pipelines; otherwise the CPU. Never raises: any failure means the CPU.

    `pack_site` is the installed GPU pack's folder; `started` receives the check's
    process, so quitting the app can stop it.
    """
    if setting == "cpu":
        return Device(None, "PII_REVIEW_DEVICE=cpu")
    if bundled is None:
        bundled = pack_site is not None or importlib.util.find_spec("cupy") is not None
    if not bundled:
        return Device(None, "no GPU support installed")
    args = [str(pack_site)] if pack_site is not None else []
    code, stdout, detail = _run_check(probe, args, timeout, python, started)
    if code is None:
        return Device(None, f"the GPU check took over {timeout:g} seconds")
    if code != 0:
        return Device(None, f"no usable NVIDIA GPU: {detail}")
    try:
        found = json.loads(stdout.strip().splitlines()[-1])
        name, free = str(found["name"])[:100], int(found["free"])
    except (ValueError, KeyError, IndexError, TypeError):
        return Device(None, "the GPU check gave no answer")
    if free < GPU_MIN_FREE_BYTES:
        return Device(None, f"{name} has {free / 1024**3:.1f} GiB free, the models need 3")
    return Device(name, "")


def block_cupy() -> None:
    """Hide CuPy from thinc and spaCy, so they run on the CPU exactly as without it,
    and never touch a CUDA installation that failed the check."""
    for name in ("cupy", "cupyx", "cupy_backends"):
        if name not in sys.modules:
            sys.modules[name] = None  # type: ignore[assignment]  # makes `import cupy` raise ImportError


def free_gpu_memory() -> None:
    gc.collect()
    try:
        import cupy

        cupy.get_default_memory_pool().free_all_blocks()
    except Exception:  # best effort: the CPU fallback works without it
        pass


# ---------------------------------------------------------------------------
# The GPU pack
# ---------------------------------------------------------------------------


class PackError(Exception):
    """The GPU pack could not be downloaded or unpacked."""


class GpuPack:
    """CuPy and the CUDA wheels pinned in gpu-pack.json, unpacked under `root`.

    Each pinned set unpacks into its own folder, named after its hash, with a
    marker written last: a folder without one (an interrupted download) is
    never used, and a new app version's pins never mix with old files.
    """

    def __init__(self, manifest: Path, root: Path | None, target: str | None = None) -> None:
        self.root = root
        self.wheels: list[dict[str, Any]] = []
        target = target if target is not None else runtime_target()
        if root is not None and target is not None and manifest.is_file():
            pinned = json.loads(manifest.read_text(encoding="utf-8")).get("targets", {}).get(target, [])
            self.wheels = [self._checked(wheel) for wheel in pinned]
        digest = hashlib.sha256(json.dumps(self.wheels, sort_keys=True).encode("utf-8")).hexdigest()
        self.name = f"pack-{digest[:16]}"

    @staticmethod
    def _checked(wheel: Mapping[str, Any]) -> dict[str, Any]:
        url, name, sha256 = str(wheel["url"]), str(wheel["name"]), str(wheel["sha256"]).lower()
        if not url.startswith(f"https://{DOWNLOAD_HOST}/") or not url.endswith("/" + name):
            raise ValueError("gpu-pack.json: wheels come from PyPI over https only")
        if "/" in name or "\\" in name or not name.endswith(".whl") or len(sha256) != 64:
            raise ValueError("gpu-pack.json: invalid wheel entry")
        return {"name": name, "url": url, "sha256": sha256, "size": int(wheel["size"])}

    @property
    def available(self) -> bool:
        """This computer's build has a GPU pack, and there is a folder for it."""
        return bool(self.wheels) and self.root is not None

    @property
    def folder(self) -> Path:
        assert self.root is not None
        return self.root / self.name

    @property
    def site(self) -> Path:
        return self.folder / "site-packages"

    @property
    def download_bytes(self) -> int:
        return sum(wheel["size"] for wheel in self.wheels)

    def installed(self) -> bool:
        if not self.available:
            return False
        try:
            return (self.folder / "installed.json").read_text(encoding="utf-8").strip() == self.name
        except OSError:
            return False

    def install(self, progress: Callable[[int, int], None] = lambda done, total: None) -> None:
        """Download, check, and unpack every wheel, then mark the pack as installed.
        Raises PackError; leaves no partial pack behind that could be used."""
        if not self.available:
            raise PackError("no GPU pack for this computer")
        assert self.root is not None
        self.root.mkdir(parents=True, exist_ok=True)
        self._remove_others()
        if shutil.disk_usage(self.root).free < PACK_MIN_FREE_DISK_BYTES:
            raise PackError("not enough free disk space (4 GB needed)")
        staging = self.root / f"{self.name}.partial-{os.getpid()}"
        shutil.rmtree(staging, ignore_errors=True)
        site = staging / "site-packages"
        site.mkdir(parents=True)
        done, total = 0, self.download_bytes
        context = _tls_context()
        try:
            for wheel in self.wheels:
                path = staging / wheel["name"]
                before = done
                done += _download(wheel, path, context, lambda count, before=before: progress(before + count, total))
                _unpack_wheel(path, site)
                path.unlink()
            (staging / "installed.json").write_text(self.name, encoding="utf-8")
            shutil.rmtree(self.folder, ignore_errors=True)
            os.replace(staging, self.folder)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        self._remove_others()

    def _remove_others(self) -> None:
        """Older pins' packs and interrupted downloads."""
        assert self.root is not None
        for path in self.root.iterdir():
            if path.name != self.name and path.name.startswith("pack-") and path.is_dir():
                shutil.rmtree(path, ignore_errors=True)


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    try:  # the bundled interpreter may not find the system's certificates
        import certifi

        context.load_verify_locations(certifi.where())
    except (ImportError, OSError):
        pass
    return context


def _download(wheel: Mapping[str, Any], path: Path, context: ssl.SSLContext, progress: Callable[[int], None]) -> int:
    """Download one wheel to `path`, checking its size and SHA-256. Returns its size."""
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(wheel["url"], headers={"User-Agent": "pii-review-desktop"})
    try:
        with urllib.request.urlopen(request, timeout=60, context=context) as response, path.open("wb") as out:
            while chunk := response.read(DOWNLOAD_CHUNK_BYTES):
                size += len(chunk)
                if size > wheel["size"]:
                    raise PackError(f"{wheel['name']} is larger than pinned")
                digest.update(chunk)
                out.write(chunk)
                progress(size)
    except OSError as error:
        raise PackError(f"downloading {wheel['name']} failed: {type(error).__name__}") from error
    if size != wheel["size"] or digest.hexdigest() != wheel["sha256"]:
        raise PackError(f"{wheel['name']} does not match its pinned SHA-256")
    return size


def _unpack_wheel(wheel: Path, site: Path) -> None:
    """Unpack a wheel's library files into `site`, as an installer would.

    Only paths inside `site` are written; a wheel's .data scripts and headers
    are skipped, its purelib and platlib files go to `site`.
    """
    root = site.resolve()
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            parts = PurePosixPath(member.filename).parts
            if not parts or member.filename.startswith(("/", "\\")) or any(
                part in {"", ".", ".."} or ":" in part or "\\" in part for part in parts
            ):
                raise PackError(f"{wheel.name} has an unsafe path")
            if parts[0].endswith(".data"):
                if len(parts) < 3 or parts[1] not in {"purelib", "platlib"}:
                    continue
                parts = parts[2:]
            target = root.joinpath(*parts)
            if not target.resolve().is_relative_to(root):
                raise PackError(f"{wheel.name} has an unsafe path")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as out:
                shutil.copyfileobj(source, out, DOWNLOAD_CHUNK_BYTES)
