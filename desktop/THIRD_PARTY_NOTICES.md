# Third-party components in the PII Review desktop app

PII Review's own code is under the MIT licence. The app bundles these
components, each under its own licence. Their licence files are installed with
them, under `resources/` in the app's folder.

| Component | Version | Licence | Where in the app |
| --- | --- | --- | --- |
| CPython (python-build-standalone) | 3.12.14 | PSF-2.0, with the licences of its bundled libraries (OpenSSL, SQLite, zlib, and others) | `resources/python/` |
| Microsoft Presidio analyzer and anonymizer | 2.2.362 | MIT | `resources/python/…/site-packages/` |
| spaCy, thinc, and their dependencies | see `desktop/runtime/requirements.txt` | MIT, BSD, Apache-2.0 (see each package's `*.dist-info`) | `resources/python/…/site-packages/` |
| spaCy `en_core_web_lg` 3.8.0 | 3.8.0 | MIT | `resources/python/…/site-packages/` |
| spaCy `de_core_news_lg` 3.8.0 | 3.8.0 | MIT | `resources/python/…/site-packages/` |
| spaCy `fr_core_news_lg` 3.8.0 | 3.8.0 | **LGPL-LR** (Lesser General Public License for Linguistic Resources) | `resources/python/…/site-packages/` |
| Xberg CLI, with Tesseract and its image libraries built in | 1.3.10 | see `resources/xberg/LICENSE` and `resources/xberg/THIRD_PARTY_LICENSES.md` | `resources/xberg/` |
| Tesseract `tessdata_fast` English, German, French | commit `8741641` | Apache-2.0 | `resources/tessdata/` |
| Tauri and its Rust dependencies | 2.x | MIT or Apache-2.0 | the app binary |
| Microsoft Edge WebView2 runtime installer (Windows installers only) | | Microsoft software licence | run by the installer when WebView2 is missing |

`fr_core_news_lg` is under LGPL-LR. Its obligations apply when the installers
are distributed outside your organisation; review them before doing so.
