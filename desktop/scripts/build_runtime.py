"""Stage everything the desktop app bundles in desktop/build/resources.

    uv run --no-project --python 3.12 desktop/scripts/build_runtime.py

Builds for the machine it runs on (CI runs it once per platform):

  resources/python/     standalone CPython (uv's python-build-standalone build)
                        with Presidio, spaCy, the en/de/fr pipelines, and the
                        pii_review package in its site-packages
  resources/xberg/      the Xberg CLI (document extraction, Tesseract built in)
  resources/tessdata/   Tesseract's English, German, and French data
  resources/config/     the Presidio and Xberg configuration from this repository

Every download is checked: Python packages against the hashes in
runtime/requirements.txt, Xberg and the Tesseract data against runtime/pins.json,
and the interpreter against uv's own checksums. Set APPLE_SIGNING_IDENTITY to
sign the bundled executables for notarization on macOS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

DESKTOP = Path(__file__).resolve().parents[1]
REPO = DESKTOP.parent
# The container images' configuration, shared with the desktop app.
IMAGES = REPO / "images"
RUNTIME = DESKTOP / "runtime"
PINS = json.loads((RUNTIME / "pins.json").read_text(encoding="utf-8"))

# Parts of the standard library the app never uses.
STDLIB_UNUSED = ("test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "pydoc_data")


def host_target() -> str:
    machine = platform.machine().lower()
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}.get(machine)
    if arch is None:
        raise SystemExit(f"unsupported CPU architecture: {machine}")
    if sys.platform == "darwin":
        if arch != "aarch64":
            # cryptography (Presidio's anonymizer) has no macOS x86_64 wheels.
            raise SystemExit("macOS builds are for Apple silicon only")
        return f"{arch}-apple-darwin"
    if sys.platform.startswith("linux"):
        return f"{arch}-unknown-linux-gnu"
    if sys.platform == "win32" and arch == "x86_64":
        return "x86_64-pc-windows-msvc"
    raise SystemExit(f"unsupported platform: {sys.platform} {arch}")


def run(*command: str | Path, **kwargs) -> None:
    print("+", " ".join(str(part) for part in command), flush=True)
    subprocess.run([str(part) for part in command], check=True, **kwargs)


def download(url: str, sha256: str, destination: Path) -> Path:
    """Download over HTTPS (certificates verified) and refuse a file whose hash differs."""
    if not url.startswith("https://"):
        raise SystemExit(f"refusing a non-https download: {url}")
    if destination.exists() and _sha256(destination) == sha256:
        return destination
    print(f"downloading {url}", flush=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as out:
        shutil.copyfileobj(response, out, length=1 << 20)
    actual = _sha256(partial)
    if actual != sha256:
        partial.unlink()
        raise SystemExit(f"checksum mismatch for {url}: expected {sha256}, got {actual}")
    partial.replace(destination)
    return destination


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def extract(archive: Path, destination: Path) -> None:
    """Unpack an archive, refusing members that would land outside `destination`."""
    destination.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".zip"):
        root = destination.resolve()
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                target = (destination / member.filename).resolve()
                if not target.is_relative_to(root):
                    raise SystemExit(f"unsafe path in {archive.name}: {member.filename}")
            bundle.extractall(destination)
    else:
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter="data")


# ---------------------------------------------------------------------------


def stage_python(target: str, out: Path, cache: Path) -> Path:
    """Install the pinned standalone CPython and the locked packages into out/python."""
    version = PINS["python"]
    installs = cache / "python-installs"
    run("uv", "python", "install", "--install-dir", installs, "--no-bin", version)
    candidates = sorted(installs.glob(f"cpython-{version}-*"))
    candidates = [path for path in candidates if path.is_dir() and not path.is_symlink()]
    if len(candidates) != 1:
        raise SystemExit(f"expected one CPython {version} install in {installs}, found {candidates}")
    python_dir = out / "python"
    shutil.copytree(candidates[0], python_dir, symlinks=True)

    if target.endswith("windows-msvc"):
        interpreter = python_dir / "python.exe"
        stdlib = python_dir / "Lib"
        site_packages = stdlib / "site-packages"
    else:
        short = ".".join(version.split(".")[:2])
        interpreter = python_dir / "bin" / f"python{short}"
        stdlib = python_dir / "lib" / f"python{short}"
        site_packages = stdlib / "site-packages"
    (stdlib / "EXTERNALLY-MANAGED").unlink(missing_ok=True)
    for name in STDLIB_UNUSED:
        shutil.rmtree(stdlib / name, ignore_errors=True)
    # Tcl/Tk, for the tkinter module removed above.
    tcl_root = python_dir / ("tcl" if target.endswith("windows-msvc") else "lib")
    for pattern in ("itcl*", "libtcl*", "libtk*", "tcl*", "tk*", "thread*"):
        for path in tcl_root.glob(pattern):
            shutil.rmtree(path) if path.is_dir() else path.unlink()
    for path in [*stdlib.glob("lib-dynload/_tkinter*"), *(python_dir / "DLLs").glob("_tkinter*"),
                 *(python_dir / "DLLs").glob("tcl*.dll"), *(python_dir / "DLLs").glob("tk*.dll")]:
        path.unlink()

    run(
        "uv", "pip", "install",
        "--python", interpreter,
        "--target", site_packages,
        "--require-hashes", "--only-binary", ":all:", "--no-deps",
        "-r", RUNTIME / "requirements.txt",
    )
    stage_app(site_packages)
    # Console scripts point at the build machine's paths; the app never uses
    # them, nor pip. It runs one interpreter: drop the other names for it.
    shutil.rmtree(site_packages / "bin", ignore_errors=True)
    for path in site_packages.glob("pip*"):
        shutil.rmtree(path, ignore_errors=True)
    if not target.endswith("windows-msvc"):
        for path in (python_dir / "bin").iterdir():
            if path.name != interpreter.name:
                path.unlink()
    else:
        shutil.rmtree(python_dir / "Scripts", ignore_errors=True)

    _replace_symlinks(python_dir)
    # The app is installed read-only, so compile now for a faster start.
    run(interpreter, "-I", "-m", "compileall", "-q", "-j", "0", stdlib, stdout=subprocess.DEVNULL)
    run(interpreter, "-I", "-c", "import presidio_analyzer, presidio_anonymizer, spacy, pii_review.desktop")
    return interpreter


def stage_app(site_packages: Path) -> None:
    """The page and the engine, app/pii_review: standard library only."""
    shutil.rmtree(site_packages / "pii_review", ignore_errors=True)
    shutil.copytree(
        REPO / "app" / "pii_review",
        site_packages / "pii_review",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def site_packages_of(target: str, out: Path) -> Path:
    if target.endswith("windows-msvc"):
        return out / "python" / "Lib" / "site-packages"
    short = ".".join(PINS["python"].split(".")[:2])
    return out / "python" / "lib" / f"python{short}" / "site-packages"


def _replace_symlinks(root: Path) -> None:
    """Installers copy files, not links: replace each link to a file with a copy, drop the rest."""
    for path in sorted(root.rglob("*"), reverse=True):
        if not path.is_symlink():
            continue
        resolved = path.resolve()
        path.unlink()
        if resolved.is_file() and resolved.is_relative_to(root.resolve()):
            shutil.copy2(resolved, path)


def stage_xberg(target: str, out: Path, cache: Path) -> None:
    pin = PINS["xberg"]
    asset = pin["assets"][target]
    url = pin["url"].format(version=pin["version"], asset=asset["asset"])
    archive = download(url, asset["sha256"], cache / asset["asset"])
    unpacked = cache / f"xberg-{pin['version']}-{target}"
    shutil.rmtree(unpacked, ignore_errors=True)
    extract(archive, unpacked)
    # The archive holds one directory with the binary, its libraries, and licences.
    inner = [path for path in unpacked.iterdir() if path.is_dir()]
    source = inner[0] if len(inner) == 1 else unpacked
    shutil.copytree(source, out / "xberg")
    binary = out / "xberg" / ("xberg.exe" if target.endswith("windows-msvc") else "xberg")
    if not binary.is_file():
        raise SystemExit(f"the Xberg archive has no {binary.name}")
    binary.chmod(0o755)
    run(binary, "--version")


def stage_tessdata(out: Path, cache: Path) -> None:
    pin = PINS["tessdata"]
    (out / "tessdata").mkdir()
    for name, sha256 in pin["files"].items():
        source = download(pin["url"].format(name=name), sha256, cache / name)
        shutil.copy2(source, out / "tessdata" / name)


def stage_config(out: Path) -> None:
    config = out / "config"
    (config / "presidio").mkdir(parents=True)
    for name in ("analyzer.yaml", "analyzer-engine.yaml", "recognizers.yaml"):
        shutil.copy2(IMAGES / "presidio-analyzer" / "conf" / name, config / "presidio" / name)
    shutil.copy2(IMAGES / "xberg" / "xberg.toml", config / "xberg.toml")
    # Pins of the GPU pack the app downloads on computers with an NVIDIA GPU.
    shutil.copy2(RUNTIME / "gpu-pack.json", config / "gpu-pack.json")


def sign_macos(out: Path, identity: str) -> None:
    """Sign every Mach-O file with the hardened runtime, as notarization requires."""
    entitlements = DESKTOP / "src-tauri" / "entitlements-runtime.plist"
    for path in sorted(out.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as handle:
            magic = handle.read(4)
        if magic not in {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
            continue
        command = ["codesign", "--force", "--timestamp", "--options", "runtime", "--sign", identity]
        if os.access(path, os.X_OK) and path.suffix not in {".so", ".dylib"}:
            command += ["--entitlements", str(entitlements)]
        subprocess.run([*command, str(path)], check=True, stdout=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=DESKTOP / "build" / "resources")
    parser.add_argument("--cache", type=Path, default=DESKTOP / "build" / "cache")
    parser.add_argument(
        "--app-only",
        action="store_true",
        help="refresh only what comes from this repository (app/pii_review and the configuration) "
        "in a runtime staged before, for `npm run dev`; downloads nothing",
    )
    args = parser.parse_args()

    target = host_target()
    if args.app_only:
        site_packages = site_packages_of(target, args.out)
        if not site_packages.is_dir():
            raise SystemExit(f"no staged runtime in {args.out}: run `npm run runtime` first")
        stage_app(site_packages)
        shutil.rmtree(args.out / "config", ignore_errors=True)
        stage_config(args.out)
        print(f"refreshed app/pii_review and the configuration in {args.out}", flush=True)
        return 0
    print(f"staging the desktop runtime for {target}", flush=True)
    out: Path = args.out
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    args.cache.mkdir(parents=True, exist_ok=True)

    stage_config(out)
    stage_tessdata(out, args.cache)
    stage_xberg(target, out, args.cache)
    stage_python(target, out, args.cache)

    identity = os.environ.get("APPLE_SIGNING_IDENTITY", "").strip()
    if sys.platform == "darwin" and identity:
        sign_macos(out, identity)

    size = sum(path.stat().st_size for path in out.rglob("*") if path.is_file() and not path.is_symlink())
    print(f"staged {size / 1e9:.2f} GB in {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
