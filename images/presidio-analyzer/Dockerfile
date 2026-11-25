# Presidio analyzer with German and French spaCy pipelines added to the
# upstream image's English one, and the tool's configuration (conf/*.yaml)
# built in, so Compose and Kubernetes run the same files without mounts.
FROM mcr.microsoft.com/presidio-analyzer:2.2.362@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9

# GPU=true (compose.gpu.yml, or the chart's GPU image) adds CuPy and the CUDA
# libraries, so the spaCy pipelines can run on an NVIDIA GPU. x86_64 only.
ARG GPU=false

USER 0
COPY spacy-models.txt gpu-requirements.txt /tmp/
# The wheels have no dependencies beyond the image's own spaCy 3.8 and numpy.
RUN pip install --no-cache-dir --no-deps --require-hashes -r /tmp/spacy-models.txt \
    && if [ "$GPU" = "true" ]; then \
         pip install --no-cache-dir --no-deps --require-hashes -r /tmp/gpu-requirements.txt \
         && python -c "import cupy, cupy.cublas, cupyx"; \
       fi \
    && rm /tmp/spacy-models.txt /tmp/gpu-requirements.txt

# Owned by root and read-only for the service user.
COPY --chmod=0444 conf/analyzer.yaml /app/presidio_analyzer/conf/tool-analyzer.yaml
COPY --chmod=0444 conf/analyzer-engine.yaml /app/presidio_analyzer/conf/tool-analyzer-engine.yaml
COPY --chmod=0444 conf/recognizers.yaml /app/presidio_analyzer/conf/tool-recognizers.yaml
ENV PRESIDIO_NLP_ENGINE=spacy \
    NLP_CONF_FILE=/app/presidio_analyzer/conf/tool-analyzer.yaml \
    ANALYZER_CONF_FILE=/app/presidio_analyzer/conf/tool-analyzer-engine.yaml \
    RECOGNIZER_REGISTRY_CONF_FILE=/app/presidio_analyzer/conf/tool-recognizers.yaml \
    TLDEXTRACT_CACHE_TIMEOUT=2

# Presidio's email recognizer uses tldextract, which downloads the Public
# Suffix List on a worker's first email address and falls back to its bundled
# copy when that fails. The analyzer has no internet, so the download must fail
# fast: TLDEXTRACT_CACHE_TIMEOUT bounds each of its two attempts (it cannot
# cache on the read-only file system), and the deployments give it no DNS.

USER 1001:1001
