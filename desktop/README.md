# PII Review desktop app

The compose deployment as one installable app for macOS, Windows, and Linux.
Everything it needs is inside the installer: no Docker, Python, Tesseract, or
internet connection is required on the computer that runs it.

| Platform | Installers | Built on |
| --- | --- | --- |
| macOS 11+ (Apple silicon, Intel) | `.dmg` | `macos-14`, `macos-15-intel` |
| Windows 10/11 x64 | `.exe` (per-user NSIS) and `.msi` | `windows-2022` |
| Linux x64 and arm64 | `.deb`, `.rpm`, `.AppImage` | `ubuntu-22.04`, `ubuntu-22.04-arm` |

## How it works

```
Tauri shell (src-tauri, Rust)                 one window, system web view
  └─ python -I -m pii_review.desktop          the page and its API on 127.0.0.1:<random port>
       ├─ Presidio analyzer + anonymizer      in the same process, en/de/fr spaCy pipelines
       └─ xberg serve                         documents and OCR on 127.0.0.1:<random port>
```

| Compose service | In the app | Bundled from |
| --- | --- | --- |
| `pii-review` | `app/pii_review`, unchanged apart from the desktop entry point | this repository |
| `presidio-analyzer` | in-process `AnalyzerEngine` with `presidio/*.yaml` | Presidio 2.2.362, spaCy 3.8, `en_core_web_lg`, `de_core_news_lg`, `fr_core_news_lg` 3.8.0 |
| `presidio-anonymizer` | in-process `AnonymizerEngine` | Presidio 2.2.362 |
| `xberg` | the Xberg CLI's `serve`, with `xberg/xberg-config.toml` | Xberg 1.3.10 release binary, Tesseract `tessdata_fast` eng/deu/fra |

Every download is pinned and checked: Python packages by hash in
[`runtime/requirements.txt`](runtime/requirements.txt), Xberg and the
Tesseract data by SHA-256 in [`runtime/pins.json`](runtime/pins.json), and
CPython (python-build-standalone 3.12.14) by uv's own checksums.

Startup takes about 6 seconds on an M-series Mac once the models are in the
disk cache, and about 35 seconds on a cold start or when run straight from the
`.dmg`, while the system reads 1.7 GB of models. A splash screen shows progress.

### Differences from the compose deployment

- **No LiteLLM key.** The app makes a random token at each start and gives it
  only to its own window (in the page URL's fragment, which is never sent over
  the network). Other programs and web pages on the computer cannot use the
  API. To require LiteLLM keys anyway, set `PII_REVIEW_GATEWAYS` in the
  settings file.
- **One analysis piece at a time.** The compose analyzer runs two gunicorn
  workers; the app runs Presidio in one process (gunicorn does not run on
  Windows, and separate workers would each load 2.4 GiB of models). Small and
  medium texts are unaffected; a 10 MB text takes roughly twice as long.
- **Xberg is not network-isolated.** In compose it sits on an internal Docker
  network without internet. In the app it listens on 127.0.0.1 only and its
  configuration still refuses local paths and `file://` URIs, but the process
  itself can reach the network. Presidio's email recognizer uses its bundled
  public-suffix list instead of downloading one.
- **No container limits.** Memory and CPU are the computer's. Peak use is about
  2.5 GiB for the models plus what a document needs (see the main README).

## Settings

On first start the app writes a commented settings file:

| Platform | File |
| --- | --- |
| macOS | `~/Library/Application Support/io.github.bella-1337.pii-review/settings.env` |
| Windows | `%APPDATA%\io.github.bella-1337.pii-review\settings.env` |
| Linux | `~/.config/io.github.bella-1337.pii-review/settings.env` |

It takes the same `KEY=VALUE` lines as `.env.example`: language, limits, the
optional local model (for example Ollama on `http://127.0.0.1:11434/v1`), and
`PII_REVIEW_GATEWAYS`. Service URLs and the port are the app's own. Restart the
app after a change.

The engine's log (no content, file names, or keys) is `engine.log` in
`~/Library/Logs/io.github.bella-1337.pii-review/` on macOS, and in the app's
log folder (`%LOCALAPPDATA%\…\logs`, `~/.local/share/…/logs`) elsewhere.

## Build

Needs [uv](https://docs.astral.sh/uv/), Node.js 22, Rust (stable), and on
Linux the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).
Installers are built on the platform they are for.

```sh
cd desktop
npm ci
npm run runtime     # stage build/resources: ~1.5 GB download the first time, 2.1 GB on disk
npm run build       # all installers for this platform, in src-tauri/target/release/bundle/
```

`npx tauri build --bundles dmg` (or `nsis`, `msi`, `deb`, `rpm`, `appimage`)
builds one kind. `npm run dev` runs the app from source with the staged
runtime.

CI: [`.github/workflows/desktop.yml`](../.github/workflows/desktop.yml) runs
the tests, builds every installer on its own runner, and uploads them as
workflow artifacts; a `v*` tag also attaches them to a draft GitHub release.

To update a component, change its pin in `runtime/requirements.in` (then
`uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes --no-header -o requirements.txt`)
or `runtime/pins.json`, and keep the versions in step with `compose.yml`.

## Signing

The installers are not signed yet, so:

- **macOS** shows "PII Review can't be opened" for a downloaded `.dmg`.
  Right-click the app and choose Open, or run
  `xattr -dr com.apple.quarantine "/Applications/PII Review.app"`.
- **Windows** SmartScreen warns about an unknown publisher.

To sign: on macOS, set `APPLE_SIGNING_IDENTITY` before `npm run runtime`
(signs the bundled Python and Xberg with
[`src-tauri/entitlements-runtime.plist`](src-tauri/entitlements-runtime.plist))
and before `npm run build`, plus the notarization variables in Tauri's
[macOS signing guide](https://v2.tauri.app/distribute/sign/macos/). On
Windows, see Tauri's [Windows signing guide](https://v2.tauri.app/distribute/sign/windows/).

## Size

About 2.1 GB installed. Most of it is the three spaCy pipelines (1.65 GB);
Xberg is 120 MB and CPython with the other packages about 150 MB.

## Licences

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), which the installers
include. Note that `fr_core_news_lg` is under LGPL-LR: review its obligations
before distributing the installers outside your organisation.
