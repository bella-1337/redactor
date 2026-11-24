# Presidio analyzer with German and French spaCy pipelines added to the
# upstream image's English one. Its configuration stays in mounted files
# (analyzer.yaml, analyzer-engine.yaml, recognizers.yaml).
FROM mcr.microsoft.com/presidio-analyzer:2.2.362@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9

# GPU=true (compose.gpu.yml) adds CuPy and the CUDA libraries, so the spaCy
# pipelines can run on an NVIDIA GPU. x86_64 only.
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
USER 1001:1001
