# syntax=docker/dockerfile:1.7

# =============================================================================
# FerrisCD Web Dashboard (React 19 + TypeScript + Vite + Tailwind + React Flow)
# Hardened static SPA container image (T16.5):
#   - Multi-stage build: node:24-alpine -> nginx/nginx-unprivileged:1.30-alpine
#   - Non-root UID/GID 65532 listening on unprivileged port 8080
#   - Compatible with `readOnlyRootFilesystem: true` + writable `/tmp` emptyDir
#   - Build context: `apps/ferriscd-web` (e.g. `docker build apps/ferriscd-web`)
# =============================================================================

ARG NODE_VERSION=24-alpine
ARG NGINX_VERSION=1.30-alpine

# -----------------------------------------------------------------------------
# Stage 1: Build static SPA bundle
# -----------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src

RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Minimal unprivileged Nginx static server
# -----------------------------------------------------------------------------
FROM nginx/nginx-unprivileged:${NGINX_VERSION} AS runtime

LABEL org.opencontainers.image.title="FerrisCD Web Dashboard" \
      org.opencontainers.image.description="Hardened non-root static SPA image for the FerrisCD GitOps Web UI" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/tuantran0910/ferris-cd"

USER 0

# Create non-root UID/GID 65532, remove default conf.d files, and prepare
# read-only config/static dirs plus `/tmp/nginx` for build-time config testing.
RUN addgroup -g 65532 -S ferriscd \
    && adduser -u 65532 -G ferriscd -S -H -h /tmp -s /sbin/nologin ferriscd \
    && rm -rf /etc/nginx/conf.d/* /usr/share/nginx/html/* \
    && mkdir -p /tmp/nginx \
    && chown -R 65532:65532 /tmp/nginx \
    && chmod 0755 /etc/nginx /usr/share/nginx/html

COPY --chown=0:0 --chmod=0644 nginx.conf /etc/nginx/nginx.conf
COPY --from=builder --chown=0:0 /app/dist /usr/share/nginx/html

# Ensure all served assets are readable (never writable) by UID 65532
RUN find /usr/share/nginx/html -type d -exec chmod 0755 {} + \
    && find /usr/share/nginx/html -type f -exec chmod 0644 {} +

USER 65532:65532
WORKDIR /tmp

# Validate Nginx configuration as UID 65532
RUN nginx -e /dev/stderr -t -c /etc/nginx/nginx.conf

EXPOSE 8080

# Ensure `/tmp/nginx` exists even when Kubernetes mounts a fresh `emptyDir` at `/tmp`,
# then `exec` nginx directly as PID 1 so signals (SIGTERM/SIGQUIT) are handled cleanly.
ENTRYPOINT ["/bin/sh", "-c", "mkdir -p /tmp/nginx && exec nginx -e /dev/stderr -c /etc/nginx/nginx.conf -g 'daemon off;'"]
