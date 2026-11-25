# PII review

A self-service page where people check the personal data in a text, document,
scan, or image before they share it, choose what to mask, and copy the masked
result.

1. Sign in with your LiteLLM virtual key.
2. Paste text, or upload a document of up to 200 MiB (PDF, Word, Excel,
   PowerPoint, OpenDocument, RTF, HTML, email, or plain text) or an image (PNG,
   JPEG, TIFF, WebP, BMP, GIF). Images, scanned PDF pages, and images in Office
   documents are read with OCR.
3. See everything that was found, grouped by type, with its score, context, and
   a highlighted preview: names, organisations, addresses, email addresses,
   phone numbers, IBANs, card numbers, UK NHS and National Insurance numbers,
   and more, in English, German, and French.
4. Choose what to mask: whole types or single items, how each type is masked
   (replaced with its type, masked with `*`, or removed), and terms the
   detection missed.
5. Copy or download the masked text.

Nothing is stored, nothing is sent to a cloud model, and the services log no
content, file names, or keys.

## How it works

| Service | Image | Purpose |
| --- | --- | --- |
| `pii-review` | local build (`images/pii-review`, package in `app/pii_review`), Python standard library only | The page and its API. Checks keys, sends documents to Xberg, text to Presidio and the local model, and masks the selection. |
| `presidio-analyzer` | local build (`images/presidio-analyzer`) on `mcr.microsoft.com/presidio-analyzer:2.2.362` | Detection in English, German, and French, with organisation names, UK formats, and German and French street addresses. |
| `presidio-anonymizer` | `mcr.microsoft.com/presidio-anonymizer:2.2.362` | Masks the selected items. |
| `xberg` | local build (`images/xberg`) on `ghcr.io/xberg-io/xberg:1.3.10-core` | Reads documents (`xberg serve`, upload API, 250 MiB limit), with OCR by the Tesseract engine in the image. |

Networks: only `pii-review` is published (on `127.0.0.1` by default) and can
reach outside the host. Presidio sits on the internal `backend` network, and
Xberg alone with the page on the internal `extract` network, without internet
access, so it cannot fetch anything a document links to.

Two optional connections leave the host:

- **Key check (required).** A key any LiteLLM gateway in `PII_REVIEW_GATEWAYS`
  accepts (`GET /v1/models`) may use the page. Expired, blocked, and deleted
  keys are refused; an accepted key is remembered for 60 seconds. The page
  never calls a model with the user's key.
- **Local model (optional).** With `PII_REVIEW_ASSIST_URL` set, a local model
  detects a text's language and personal data Presidio's recognizers miss;
  its finds are marked "local model". Any OpenAI-compatible API works:
  - a LiteLLM gateway's `pii-assist` model, with a key limited to that model:
    `PII_REVIEW_ASSIST_URL=https://<gateway>/v1`, `PII_REVIEW_ASSIST_KEY=sk-…`;
  - Ollama on the Docker host: `PII_REVIEW_ASSIST_URL=http://host.docker.internal:11434/v1`,
    `PII_REVIEW_ASSIST_MODEL=qwen3.5:4b`, no key.

  The text is sent to that model **unmasked**: use one on this host or a
  private network, never a cloud API. It checks the first
  `PII_REVIEW_ASSIST_MAX_CALLS` × 4000 characters of each text (32,000 by
  default) and takes about 3 seconds per call with `qwen3.5:4b`. If it fails,
  the page continues with Presidio alone, in `PII_REVIEW_LANGUAGE`.

## Run it

```sh
cp .env.example .env          # set PII_REVIEW_GATEWAYS, optionally the assist model
docker compose up -d --build
curl --fail http://127.0.0.1:8080/health
```

Open `http://127.0.0.1:8080/`. To offer the page to other people, put a TLS
reverse proxy in front of it and keep `PII_REVIEW_BIND=127.0.0.1`.

The first build downloads the German and French spaCy pipelines (about
1.1 GB). See `.env.example` for every setting.

### NVIDIA GPU (optional)

On an x86_64 host with the NVIDIA driver and the
[NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/),
the analyzer can run its spaCy pipelines on a GPU:

```sh
docker compose -f compose.yml -f compose.gpu.yml up -d --build
```

[`compose.gpu.yml`](compose.gpu.yml) builds the analyzer with CuPy and the
CUDA 12 libraries ([`images/presidio-analyzer/gpu-requirements.txt`](images/presidio-analyzer/gpu-requirements.txt),
pinned by hash; the image grows from 2.2 to 3.8 GB), reserves one GPU, and
sets `PRESIDIO_DEVICE=cuda`. The models are not preloaded in this mode (CUDA
does not survive gunicorn's fork), so each analyzer worker loads its own
pipelines, about 2 GiB of GPU memory each; `PRESIDIO_ANALYZER_WORKERS`
defaults to 1 here. If the GPU cannot be used, the analyzer logs
`Failed to enable GPU (cuda), falling back to CPU` and runs on the CPU.

## Kubernetes (Helm)

The chart in [`deploy/helm/pii-review`](deploy/helm/pii-review) runs the same
four services with the same images, limits, and isolation:

- **Network policies** replace the internal networks: everything is denied,
  then the page may reach Presidio, Xberg, DNS, and the addresses in
  `networkPolicy.web.egress` (by default any address on port 443, for the
  gateways; narrow it to yours). Presidio and Xberg accept only the page and
  reach nothing; they have no DNS either. The cluster's network plugin must
  enforce NetworkPolicy (Calico, Cilium, kind's kindnet; not plain flannel).
- **Pods** meet the Pod Security "restricted" level: non-root, read-only root
  file system, no capabilities, default seccomp profile, no service account
  token, memory-backed `/tmp`.
- **Exposure** through an Ingress (`web.ingress`) or a Gateway API route
  (`web.httpRoute`), with `networkPolicy.web.ingressFrom` selecting the
  controller's pods. The proxy must accept 250 MiB bodies, keep requests open
  for 30 minutes, and set `X-Real-Ip` to the client's address, replacing any
  value the client sent (the page limits rejected keys per `X-Real-Ip`).
- **GPU** with `analyzer.gpu.enabled=true`: the `-gpu` analyzer image, one
  `nvidia.com/gpu`, and one worker, as `compose.gpu.yml`.
- **The local model's key** from a Secret (`web.assist.existingSecret`).

The images must be in a registry the cluster can pull from
(`global.imageRegistry`); this repository does not publish them yet. To try
the chart on a local [kind](https://kind.sigs.k8s.io/) cluster instead:

```sh
docker compose build
kind load docker-image pii-review:0.4.0 pii-review-presidio-analyzer:2.2.362-2 pii-review-xberg:1.3.10-1
helm install pii-review deploy/helm/pii-review --namespace pii-review --create-namespace \
  --set 'web.gateways={https://litellm.example.test}'
kubectl --namespace pii-review port-forward service/pii-review-web 8080:8080
```

Rate limits and the accepted-key cache are kept in each page pod's memory, so
with several `web.replicas` a key may make that many times
`web.requestsPerMinute` requests. Every setting is described in
[`values.yaml`](deploy/helm/pii-review/values.yaml) and checked by
[`values.schema.json`](deploy/helm/pii-review/values.schema.json).

## Desktop app

The same tool also ships as a desktop app for macOS, Windows, and Linux, with
installers that bring everything along (Python, Presidio and its models, Xberg,
Tesseract data) and need no Docker or internet connection. It runs for the
person using the computer, without a LiteLLM key. On Windows and Linux x64
computers with an NVIDIA GPU, it downloads GPU support once and runs the
language models on the GPU. See [desktop/README.md](desktop/README.md).

## OCR

Xberg reads images, the scanned pages of a PDF, and images embedded in Office
documents with [Tesseract](https://github.com/tesseract-ocr/tesseract) 5
(Apache-2.0), which ships in the pinned Xberg image with English, German, and
French language data. Pages with a text layer keep their own text, so a PDF
that mixes typed and scanned pages is read page by page. Settings in
`images/xberg/xberg.toml`:

- `language = "eng+deu+fra"`: all three languages at once, so accents, umlauts,
  and `ß` are recognised in any document.
- `psm = 3` and `enable_table_detection = false`: automatic page layout.
  Xberg's defaults for whole images (sparse text) and its table detection mix
  up the lines of ordinary letters.
- `use_cache = false`, twice: no extraction or OCR results are cached.

When a document was read with OCR or contains images, the page says so: OCR
can misread or split names and numbers (`QQ` became `98` in one test) so that
they are not detected, and the user should compare the preview with the
original. A file whose content does not match its image extension is refused,
and an image without readable text gets a message instead of an empty result.

Measured on two CPUs: a one-page image in 2 to 6 seconds including analysis,
30 scanned pages in 18 seconds; Xberg peaked at about 330 MiB.

## Sizing and limits

| Item | Default | Notes |
| --- | --- | --- |
| Upload | 200 MiB (`PII_REVIEW_MAX_FILE_BYTES`, at most 250,000,000 bytes) | The browser sends the file as the raw request body. The page holds one copy in memory while Xberg reads it; two documents are read at a time. A 190 MiB DOCX took 19 seconds. Xberg refuses an Office file with a single embedded file over 100 MiB unpacked (its zip-bomb protection). |
| Text analysed | all of it, up to 250,000,000 bytes (`PII_REVIEW_MAX_TEXT_BYTES`) | Analysed in 100 KB pieces that overlap by 200 characters, `PII_REVIEW_ANALYZE_PARALLEL` at a time (default: the analyzer's worker count). Measured with two workers: 9.8 MB of text in under 5 minutes (534,380 detections), masked in 25 seconds. More workers analyse faster; each adds about 0.1 GiB. The browser keeps the request open meanwhile. |
| Preview | first 1,000,000 characters | The list shows the first 200 items of each type. Selection and masking always cover everything. |
| Memory | page 3g, analyzer 4g, Xberg 4g, anonymizer 1g | Measured peaks: page 511 MiB and analyzer 3.3 GiB for the 9.8 MB text; page 210 MiB for the 190 MiB upload. The analyzer preloads its English, German, and French pipelines, shared by its workers. Raise the page's limit for texts much larger than 10 MB. |
| Requests | 30 per key per minute; 10 rejected keys per address per minute; 8 at once | |

## Mixed languages

Presidio analyses a text in one language, and its language-specific recognizers
(German and French street addresses, the spaCy name models) only work in that
language. So the page finds the language of each paragraph and analyses each
section in its own language (`app/pii_review/languages.py`):

- A paragraph is English, German, or French when it contains at least two
  common words of that language (such as "the", "und", "vous", or salutations
  like "Dear", "Sehr geehrte", "Bonjour") and at least twice as many as of any
  other. Words common in two of the languages, such as "in" or "was", do not
  count.
- A paragraph without that evidence, such as a phone number or an IBAN on its
  own line, belongs to the section before it.
- A text without any clear paragraph is analysed in the language the local
  model detects, or `PII_REVIEW_LANGUAGE`.

A text in one language stays one section, so it is analysed as before. For a
mixed text, the page lists the share of each language. The check takes about
half a second for 10 MB of text. Measured on a PDF with an English, a German,
and a French letter: their street addresses are now all masked, where the
German and French ones were missed when the whole PDF was analysed in English.

## Data protection

- No storage: uploads, text, detections, and results exist only in memory for
  the duration of a request. The page and Xberg have read-only file systems
  and no volumes, and Xberg's extraction and OCR caches are off.
- No content in logs: the page logs the method, route, status, and duration of
  each request and that a key was rejected. Xberg logs at `warn` by default.
- The original file name never leaves the page: Xberg gets `document.<ext>`.
- The key stays in the browser tab's memory, never in cookies or storage.
- Strict Content Security Policy, `no-referrer`, `no-store`, no framing, no
  cross-origin requests; user content is rendered as text, never as HTML.
- Masking is pseudonymisation, not anonymisation. Detection misses some
  personal data and flags some harmless text: read the result before sharing
  it.

## Detection details

- `images/presidio-analyzer/conf/analyzer.yaml`: spaCy model per language and label mapping
  (people, organisations, places, dates, nationalities).
- `images/presidio-analyzer/conf/recognizers.yaml`: Presidio's default recognizers for English,
  German, and French; credit cards in all three; UK National Insurance numbers,
  passports, and postcodes switched on (vehicle registrations stay off); and
  German and French street-address recognizers that mask the whole address.
  `tests/test_presidio_recognizers.py` lists what must and must not match.
- `app/pii_review/pii_assist_prompt.json`: the local model's prompt and answer
  schema. Only items that occur verbatim in the text are used.

## Development

```text
app/pii_review/      the service (also the desktop app's backend)
images/              one folder per container image, with its configuration
  pii-review/          the page (built from the repository root)
  presidio-analyzer/   Presidio with the spaCy models; conf/ is built in
  xberg/               Xberg; xberg.toml is built in
deploy/helm/         the Helm chart
compose.yml          Docker Compose (compose.gpu.yml for an NVIDIA GPU)
desktop/             the desktop app (Tauri)
tests/
```

The configuration is built into the images, so Compose and Kubernetes run the
same files, and the desktop build copies them from `images/`.

```sh
python3 -m unittest discover -s tests
```

The service has no third-party Python dependencies. The chart tests need Helm
and PyYAML; without them they are skipped:

```sh
uv run --no-project --python 3.12 --with-requirements tests/requirements-chart.txt \
  python -m unittest tests/test_helm_chart.py
```

## Licences

This repository's code is under the MIT licence ([LICENSE](LICENSE)).

The upstream images and models keep their own licences: Presidio (MIT), Xberg
(see its image), Tesseract and its language data in the Xberg image
(Apache-2.0), spaCy `en_core_web_lg` and `de_core_news_lg` (MIT), and
`fr_core_news_lg` (LGPL-LR, the Lesser General Public License for Linguistic
Resources). LGPL-LR obligations apply when the analyzer image is distributed
outside your organisation; review them before doing so. The GPU analyzer
image (`compose.gpu.yml`) also contains CuPy (MIT) and NVIDIA's CUDA runtime,
NVRTC, cuBLAS, and cuRAND libraries (NVIDIA CUDA Toolkit EULA).
