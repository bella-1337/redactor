# The page and its API. Built from the repository root (the package in
# app/pii_review is shared with the desktop app); Dockerfile.dockerignore next
# to this file limits the build context to that package.
FROM ghcr.io/astral-sh/uv:0.9.30-python3.13-bookworm-slim@sha256:531f855bda2c73cd6ef67d56b733b357cea384185b3022bd09f05e002cd144ca

ENV HOME=/tmp/home \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Debian removes superseded package versions from its mirrors, so the base
# image's packages are upgraded at build time.
RUN apt-get update \
    && apt-get upgrade --yes --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# The service uses only the Python standard library: no third-party packages.
COPY app/pii_review /app/pii_review

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "pii_review"]
