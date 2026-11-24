# Xberg document extraction with the tool's configuration (xberg.toml) built
# in, so Compose and Kubernetes run the same file without mounts.
FROM ghcr.io/xberg-io/xberg:1.3.10-core@sha256:f0a66d39f7322c273bb4ba2b53f5ca00dee9f2f1b3ebbec26a283017e07a865b

# Owned by root and read-only for the service user.
COPY --chmod=0444 xberg.toml /etc/xberg/xberg.toml

# The upstream user "xberg", by number, so Kubernetes can check it is not root.
USER 999:999
EXPOSE 8000
# The entrypoint stays the upstream one: tini, then xberg.
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", "--config", "/etc/xberg/xberg.toml"]
