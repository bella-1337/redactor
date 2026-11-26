# Presidio analyzer with the tool's configuration (conf/*.yaml) built in, so
# Compose and Kubernetes run the same files without mounts. NLP_ENGINE picks
# Presidio's NLP engine, and what is installed for it:
#
#   spacy (default)  English, German, and French spaCy pipelines, added to the
#                    upstream image's English one.
#   transformers     Presidio's Transformers engine: small spaCy pipelines split
#                    the text, a multilingual Hugging Face NER model (HF_MODEL)
#                    finds names, organisations, and places. PyTorch (CPU) and
#                    the model are built in; the analyzer needs no internet.
#
# Compose builds one image per engine (profiles `spacy` and `transformers`).
FROM mcr.microsoft.com/presidio-analyzer:2.2.362@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9

ARG NLP_ENGINE=spacy
# GPU=true (compose.gpu.yml, or the chart's GPU image) adds CuPy and the CUDA
# libraries, so the spaCy pipelines can run on an NVIDIA GPU. x86_64 and the
# spaCy engine only.
ARG GPU=false
# The transformers engine's NER model, and the commit of it to build in: a
# branch or tag resolves to the commit it points at when the image is built
# (printed, and kept in /app/models/ner/REVISION). Pin a 40-character commit
# for builds that give the same model every time.
ARG HF_MODEL=Davlan/xlm-roberta-base-ner-hrl
ARG HF_MODEL_REVISION=main

USER 0
COPY spacy-models.txt gpu-requirements.txt transformers-requirements.txt transformers-spacy-models.txt /tmp/
# The wheels have no dependencies beyond the ones listed with them and the
# image's own spaCy 3.8 and numpy.
RUN set -eu; \
    case "$NLP_ENGINE" in spacy|transformers) ;; \
      *) echo "NLP_ENGINE must be spacy or transformers, not $NLP_ENGINE" >&2; exit 1 ;; esac; \
    if [ "$NLP_ENGINE" = spacy ]; then \
      pip install --no-cache-dir --no-deps --require-hashes -r /tmp/spacy-models.txt; \
    else \
      pip install --no-cache-dir --no-deps --require-hashes -r /tmp/transformers-requirements.txt; \
      pip install --no-cache-dir --no-deps --require-hashes -r /tmp/transformers-spacy-models.txt; \
      python -c "import torch, transformers, spacy_huggingface_pipelines"; \
    fi; \
    if [ "$GPU" = "true" ]; then \
      if [ "$NLP_ENGINE" != spacy ]; then echo "GPU=true is for the spacy engine" >&2; exit 1; fi; \
      pip install --no-cache-dir --no-deps --require-hashes -r /tmp/gpu-requirements.txt; \
      python -c "import cupy, cupy.cublas, cupyx"; \
    fi; \
    rm /tmp/*.txt

# The NER model of the transformers engine, at the commit HF_MODEL_REVISION
# names: the weights in one format (safetensors where the model has them), the
# configuration, and the tokenizer; no TensorFlow, Flax, or ONNX copies.
RUN set -eu; \
    if [ "$NLP_ENGINE" = transformers ]; then \
      HF_HUB_DISABLE_TELEMETRY=1 python -c "\
import os; \
from huggingface_hub import HfApi, snapshot_download; \
repo, wanted = os.environ['HF_MODEL'], os.environ['HF_MODEL_REVISION']; \
info = HfApi().model_info(repo, revision=wanted, files_metadata=False); \
names = [file.rfilename for file in info.siblings]; \
weights = ['*.safetensors'] if any(name.endswith('.safetensors') for name in names) else ['pytorch_model.bin']; \
patterns = weights + ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'vocab.txt', 'vocab.json', 'merges.txt', '*.model']; \
snapshot_download(repo, revision=info.sha, local_dir='/app/models/ner', allow_patterns=patterns); \
open('/app/models/ner/REVISION', 'w').write(f'{repo} {info.sha}\n'); \
print(f'Hugging Face model {repo} at commit {info.sha}')"; \
      rm -rf /app/models/ner/.cache; \
      chmod -R a+rX,go-w /app/models; \
    fi

COPY conf/ /tmp/conf/
# Owned by root and read-only for the service user.
RUN set -eu; \
    if [ "$NLP_ENGINE" = transformers ]; then nlp=analyzer-transformers.yaml; else nlp=analyzer.yaml; fi; \
    install -m 0444 "/tmp/conf/$nlp" /app/presidio_analyzer/conf/tool-analyzer.yaml; \
    install -m 0444 /tmp/conf/analyzer-engine.yaml /app/presidio_analyzer/conf/tool-analyzer-engine.yaml; \
    install -m 0444 /tmp/conf/recognizers.yaml /app/presidio_analyzer/conf/tool-recognizers.yaml; \
    rm -r /tmp/conf

ENV PRESIDIO_NLP_ENGINE=${NLP_ENGINE} \
    NLP_CONF_FILE=/app/presidio_analyzer/conf/tool-analyzer.yaml \
    ANALYZER_CONF_FILE=/app/presidio_analyzer/conf/tool-analyzer-engine.yaml \
    RECOGNIZER_REGISTRY_CONF_FILE=/app/presidio_analyzer/conf/tool-recognizers.yaml \
    TLDEXTRACT_CACHE_TIMEOUT=2 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1

# Presidio's email recognizer uses tldextract, which downloads the Public
# Suffix List on a worker's first email address and falls back to its bundled
# copy when that fails. The analyzer has no internet, so the download must fail
# fast: TLDEXTRACT_CACHE_TIMEOUT bounds each of its two attempts (it cannot
# cache on the read-only file system), and the deployments give it no DNS.
# The HF_* and TRANSFORMERS_* variables keep the transformers engine to the
# model built in, without trying the internet.

USER 1001:1001
