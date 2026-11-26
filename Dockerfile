# syntax=docker/dockerfile:1.7

# =============================================================================
# FerrisCD Control Plane (Controller + REST API Server + CLI)
# Hardened minimal multi-stage container image (ADR-005, Finding C6, T16.5):
#   - Minimal Debian-slim runtime with ONLY ca-certificates + openssh-client
#     so `gix` supports both HTTPS and SSH Git transports cleanly.
#   - Pinned, SHA-256 verified Helm (v4.x) and Kustomize (v5.x) binaries.
#   - Non-root UID/GID 65532 (with /etc/passwd entry required by OpenSSH).
#   - Compatible with Kubernetes `restricted` PodSecurityStandard and
#     `readOnlyRootFilesystem: true` (all runtime writes stay under `/tmp`).
# =============================================================================

ARG RUST_VERSION=1.100
ARG DEBIAN_SUITE=bookworm

# Pinned external renderer versions and official SHA-256 release digests
ARG HELM_VERSION=v4.3.2
ARG HELM_SHA256_AMD64=d1c0278d46beab79582d7e50f5b3dc206944ba8e577cde618513fd07daa53983
ARG HELM_SHA256_ARM64=df31cb61680ef728f82c770e5280dd565617bee6b039d37e85c677288be4bbb0

ARG KUSTOMIZE_VERSION=v5.8.3
ARG KUSTOMIZE_SHA256_AMD64=cb9e31198d3f63b44848bd0afc4c8efc56e6cfef9c93a4a39a211940e6decd61
ARG KUSTOMIZE_SHA256_ARM64=9867b76482cfc6d25b546abc1d2b5a32bd137505aba640649b4b378f64f6d68f

# -----------------------------------------------------------------------------
# Stage 1: Rust workspace builder (cached dependency layer + release binary)
# -----------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-${DEBIAN_SUITE} AS builder

# Native C/CMake toolchain required by `aws-lc-sys` and `ring` during compile
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy manifests first to cache third-party dependency compilation
COPY Cargo.toml Cargo.lock ./
COPY crates/ferriscd-crd/Cargo.toml crates/ferriscd-crd/Cargo.toml
COPY crates/ferriscd-engine/Cargo.toml crates/ferriscd-engine/Cargo.toml
COPY crates/ferriscd-controller/Cargo.toml crates/ferriscd-controller/Cargo.toml
COPY crates/ferriscd-server/Cargo.toml crates/ferriscd-server/Cargo.toml
COPY crates/ferriscd-cli/Cargo.toml crates/ferriscd-cli/Cargo.toml

# Create minimal stub targets matching workspace lints so `cargo build` caches deps,
# then clean only the workspace crate artifacts (leaving all third-party deps cached).
RUN set -eux; \
    for crate in ferriscd-crd ferriscd-engine ferriscd-controller ferriscd-server; do \
        mkdir -p "crates/${crate}/src"; \
        : > "crates/${crate}/src/lib.rs"; \
    done; \
    mkdir -p crates/ferriscd-cli/src; \
    printf 'fn main() {}\n' > crates/ferriscd-cli/src/main.rs; \
    cargo build --release --locked -p ferriscd-cli; \
    cargo clean --release \
        -p ferriscd-crd \
        -p ferriscd-engine \
        -p ferriscd-controller \
        -p ferriscd-server \
        -p ferriscd-cli; \
    rm -rf crates/*/src

# Build the real workspace sources into a stripped release binary
COPY crates ./crates

RUN set -eux; \
    cargo build --release --locked -p ferriscd-cli; \
    strip /src/target/release/ferriscd; \
    /src/target/release/ferriscd --version | grep -Eq '^ferriscd '

# -----------------------------------------------------------------------------
# Stage 2: Fetch & SHA-256 verify pinned Helm + Kustomize release binaries
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_SUITE}-slim AS tools

ARG TARGETARCH
ARG HELM_VERSION
ARG HELM_SHA256_AMD64
ARG HELM_SHA256_ARM64
ARG KUSTOMIZE_VERSION
ARG KUSTOMIZE_SHA256_AMD64
ARG KUSTOMIZE_SHA256_ARM64

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gzip \
        tar \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) \
            HELM_SHA256="${HELM_SHA256_AMD64}"; \
            KUSTOMIZE_SHA256="${KUSTOMIZE_SHA256_AMD64}"; \
            ;; \
        arm64) \
            HELM_SHA256="${HELM_SHA256_ARM64}"; \
            KUSTOMIZE_SHA256="${KUSTOMIZE_SHA256_ARM64}"; \
            ;; \
        *) \
            echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; \
            exit 1; \
            ;; \
    esac; \
    mkdir -p /out /tmp/tools; \
    cd /tmp/tools; \
    # Helm
    HELM_TARBALL="helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    curl -fsSL --retry 3 --retry-delay 2 \
        "https://get.helm.sh/${HELM_TARBALL}" \
        -o "${HELM_TARBALL}"; \
    printf '%s  %s\n' "${HELM_SHA256}" "${HELM_TARBALL}" | sha256sum -c -; \
    tar -xzf "${HELM_TARBALL}" "linux-${TARGETARCH}/helm"; \
    install -m 0755 "linux-${TARGETARCH}/helm" /out/helm; \
    /out/helm version; \
    # Kustomize
    KUSTOMIZE_TARBALL="kustomize_${KUSTOMIZE_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSL --retry 3 --retry-delay 2 \
        "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${KUSTOMIZE_VERSION}/${KUSTOMIZE_TARBALL}" \
        -o "${KUSTOMIZE_TARBALL}"; \
    printf '%s  %s\n' "${KUSTOMIZE_SHA256}" "${KUSTOMIZE_TARBALL}" | sha256sum -c -; \
    tar -xzf "${KUSTOMIZE_TARBALL}" kustomize; \
    install -m 0755 kustomize /out/kustomize; \
    /out/kustomize version; \
    rm -rf /tmp/tools

# -----------------------------------------------------------------------------
# Stage 3: Minimal hardened Debian-slim runtime image
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_SUITE}-slim AS runtime

LABEL org.opencontainers.image.title="FerrisCD Control Plane" \
      org.opencontainers.image.description="Hardened minimal FerrisCD GitOps controller, REST API server, and CLI with OpenSSH, Helm, and Kustomize" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tuantran0910/ferris-cd"

# Install ONLY CA roots (HTTPS Git + K8s TLS) and OpenSSH client (`gix` SSH transport)
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        openssh-client \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /usr/share/doc/* /usr/share/man/*

# Create non-root UID/GID 65532 with /etc/passwd entry (required by OpenSSH `getpwuid`)
# and home pointing at `/tmp` so zero writes occur outside the writable `/tmp` emptyDir.
RUN groupadd --gid 65532 --system ferriscd \
    && useradd --uid 65532 --gid 65532 --system \
       --home-dir /tmp --no-create-home --shell /usr/sbin/nologin ferriscd \
    && mkdir -p /tmp \
    && chmod 1777 /tmp

# Copy binaries owned by root:root (read-only/executable by non-root user 65532)
COPY --from=builder --chown=0:0 --chmod=0755 /src/target/release/ferriscd /usr/local/bin/ferriscd
COPY --from=tools --chown=0:0 --chmod=0755 /out/helm /usr/local/bin/helm
COPY --from=tools --chown=0:0 --chmod=0755 /out/kustomize /usr/local/bin/kustomize

# Standard PATH (matches `SandboxedCommand` parent PATH lookup) + `/tmp`-only state paths
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME="/tmp" \
    TMPDIR="/tmp" \
    XDG_CACHE_HOME="/tmp/.cache" \
    XDG_CONFIG_HOME="/tmp/.config" \
    XDG_DATA_HOME="/tmp/.local/share" \
    HELM_CACHE_HOME="/tmp/helm/cache" \
    HELM_CONFIG_HOME="/tmp/helm/config" \
    HELM_DATA_HOME="/tmp/helm/data"

USER 65532:65532
WORKDIR /tmp

# Verify UID 65532 passwd resolution (Finding C6) and every required runtime binary on PATH
RUN id -un | grep -qx ferriscd \
    && getent passwd 65532 \
    && ssh -V \
    && helm version \
    && kustomize version \
    && ferriscd --version | grep -Eq '^ferriscd '

# 8080: REST API + /healthz + /readyz + webhooks; 9090: internal Prometheus /metrics
EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/ferriscd"]
CMD ["server", "--api-addr", "0.0.0.0:8080", "--metrics-addr", "0.0.0.0:9090", "--work-root", "/tmp/ferriscd-repos"]
