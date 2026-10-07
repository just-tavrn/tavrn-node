# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-only
#
# A single image: tavrn-node (with the embedded web client) + livekit-server + a minimal ffmpeg.
# TLS is always terminated by a reverse proxy in front (nginx, Caddy, Nginx Proxy Manager, Traefik).
#
# The web client comes from the tavrn-web repository, built in this file (TAVRN_WEB_SOURCE=git, the default)
# at TAVRN_WEB_REF (branch, tag or commit), or from a prebuilt bundle in web/dist of the build context
# (TAVRN_WEB_SOURCE=local, for local builds). While the repositories are private, the build needs a GitHub
# token with read access to the just-tavrn repositories (tavrn-crypto and its protocol submodule for cargo,
# tavrn-web and its git dependencies for the web stage), passed as a build secret, never as an argument:
#
#   GH_TOKEN=$(gh auth token) docker build -f deploy/Dockerfile -t tavrn-node:dev \
#     --secret id=read_token,env=GH_TOKEN .                                       # web client from tavrn-web@main
#   ... --build-arg TAVRN_WEB_SOURCE=local .                                      # web client from ./web/dist
#
# `read_token` is the secret the organization's docker-publish workflow passes (TAVRN_READ_PAT);
# `TAVRN_WEB_TOKEN`, if given, is used for the web stage instead. README.md "Container image" has the details.

ARG TAVRN_WEB_SOURCE=git

# ---- Web client from the tavrn-web repository ------------------------------------
FROM node:26-alpine AS web-git
RUN apk add --no-cache git
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=true
RUN corepack enable
ARG TAVRN_WEB_REPO=https://github.com/just-tavrn/tavrn-web
ARG TAVRN_WEB_REF=main
# How tavrn-web builds its bundle and where the bundle ends up (relative to the repository root).
ARG TAVRN_WEB_BUILD="pnpm install --frozen-lockfile && pnpm --filter @tavrn/web build"
ARG TAVRN_WEB_DIST=web/dist
WORKDIR /src
# The token reaches git only through environment variables of this one RUN (git's GIT_CONFIG_* entries), so
# it is neither stored in a layer nor in the image's git configuration; pnpm's git dependencies use it too.
RUN --mount=type=secret,id=TAVRN_WEB_TOKEN --mount=type=secret,id=read_token \
    set -eu; \
    token="$(cat /run/secrets/TAVRN_WEB_TOKEN 2>/dev/null || cat /run/secrets/read_token 2>/dev/null || true)"; \
    if [ -n "$token" ]; then \
      export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.https://x-access-token:${token}@github.com/just-tavrn/.insteadOf" \
             GIT_CONFIG_VALUE_0="https://github.com/just-tavrn/"; \
    fi; \
    git init -q . && git remote add origin "$TAVRN_WEB_REPO" \
    && git fetch -q --depth 1 origin "$TAVRN_WEB_REF" && git checkout -q FETCH_HEAD \
    && if [ -f .gitmodules ]; then git submodule update -q --init --depth 1; fi \
    && echo "tavrn-web $TAVRN_WEB_REF = $(git rev-parse HEAD)" \
    && sh -c "$TAVRN_WEB_BUILD" \
    && test -f "$TAVRN_WEB_DIST/index.html" \
    && mkdir /dist && cp -r "$TAVRN_WEB_DIST/." /dist/

# ---- Web client from a prebuilt bundle in the build context (web/dist) -------------
FROM scratch AS web-local
COPY web/dist/ /dist/

FROM web-${TAVRN_WEB_SOURCE} AS web

# ---- Build the server -----------------------------------------------------------
FROM rust:1-bookworm AS server
WORKDIR /src
# cargo fetches the private git dependency tavrn-crypto (and its protocol submodule) with the git CLI.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
# Parallel compile jobs (empty: one per CPU); lower it on machines with little memory.
ARG BUILD_JOBS=
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src src
COPY migrations migrations
COPY templates templates
# The perf load generator is a workspace member; cargo needs its manifest even when it is not built.
COPY perf/loadgen perf/loadgen
# Embed the web build (rust-embed).
COPY --from=web /dist web/dist
RUN test -f web/dist/index.html || { echo "no web client bundle (web/dist/index.html missing)" >&2; exit 1; }
RUN --mount=type=secret,id=read_token --mount=type=secret,id=TAVRN_WEB_TOKEN \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    set -eu; \
    token="$(cat /run/secrets/read_token 2>/dev/null || cat /run/secrets/TAVRN_WEB_TOKEN 2>/dev/null || true)"; \
    if [ -n "$token" ]; then \
      export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.https://x-access-token:${token}@github.com/just-tavrn/.insteadOf" \
             GIT_CONFIG_VALUE_0="https://github.com/just-tavrn/"; \
    fi; \
    cargo build --release --locked -p tavrn-node ${BUILD_JOBS:+--jobs "$BUILD_JOBS"} && cp target/release/tavrn-node /tavrn-node

# ---- Static ffmpeg for the media pipeline (src/media.rs) ------------------------------
# Only what the pipeline needs: image and short-video decoders, WebP encoding, file/pipe I/O. No network
# protocols, no devices, no other muxers: a small static binary instead of Debian's ffmpeg with its
# ~100 shared libraries. Keep the versions in sync with `just ffmpeg-install` (tests, development).
FROM debian:bookworm-slim AS ffmpeg
ARG FFMPEG_VERSION=8.0
ARG FFMPEG_SHA256=b2751fccb6cc4c77708113cd78b561059b6fa904b24162fa0be2d60273d27b8e
ARG LIBWEBP_VERSION=1.6.0
ARG LIBWEBP_SHA256=e4ab7009bf0629fd11982d4c2aa83964cf244cffba7347ecd39019a9e38c4564
RUN apt-get update && apt-get install -y --no-install-recommends build-essential nasm pkg-config ca-certificates curl xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSLo webp.tar.gz "https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${LIBWEBP_VERSION}.tar.gz" \
    && echo "${LIBWEBP_SHA256}  webp.tar.gz" | sha256sum -c - \
    && tar xzf webp.tar.gz && cd "libwebp-${LIBWEBP_VERSION}" \
    && ./configure --prefix=/opt/deps --disable-shared --enable-static --disable-png --disable-jpeg --disable-tiff --disable-gif --disable-wic --disable-gl --disable-sdl \
    && make -j"$(nproc)" && make install
RUN curl -fsSLo ffmpeg.tar.xz "https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz" \
    && echo "${FFMPEG_SHA256}  ffmpeg.tar.xz" | sha256sum -c - \
    && tar xJf ffmpeg.tar.xz && cd "ffmpeg-${FFMPEG_VERSION}" \
    && PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig ./configure --prefix=/opt/ffmpeg \
       --pkg-config-flags=--static --extra-ldflags=-static --enable-static --disable-shared \
       --disable-everything --disable-autodetect --disable-network --disable-doc --disable-debug \
       --disable-ffplay --disable-ffprobe --disable-avdevice --enable-small \
       --enable-zlib --enable-libwebp \
       --enable-protocol=file,pipe \
       --enable-demuxer=gif,apng,image_png_pipe,image_jpeg_pipe,image_webp_pipe,mov,matroska,rawvideo \
       --enable-decoder=gif,png,apng,mjpeg,webp,h264,hevc,vp8,vp9,mpeg4,rawvideo \
       --enable-parser=h264,hevc,vp8,vp9,mpeg4video,png,gif,mjpeg,webp \
       --enable-encoder=libwebp,libwebp_anim \
       --enable-muxer=webp,null \
       --enable-filter=scale,crop,fps,format,null,setsar \
    && make -j"$(nproc)" && make install && strip /opt/ffmpeg/bin/ffmpeg \
    && /opt/ffmpeg/bin/ffmpeg -hide_banner -encoders | grep -q libwebp_anim

# ---- LiveKit binary ---------------------------------------------------------
# Pinned; keep in sync with livekit_version in the justfile and LIVEKIT_VERSION in .github/workflows/ci.yml.
FROM livekit/livekit-server:v1.13.7 AS livekit

# ---- Runtime image ---------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data tavrn && mkdir -p /data && chown tavrn:tavrn /data
COPY --from=server /tavrn-node /usr/local/bin/tavrn-node
COPY --from=livekit /livekit-server /usr/local/bin/livekit-server
# Media pipeline (TAVRN_MEDIA_FFMPEG=auto finds it in PATH).
COPY --from=ffmpeg /opt/ffmpeg/bin/ffmpeg /usr/local/bin/ffmpeg
USER tavrn
VOLUME ["/data"]
# 8080: HTTP for the reverse proxy (API, web client, /rtc signaling). The UDP range carries voice and
# video and must be published 1:1 (same ports outside and inside, TAVRN_RTC_UDP_PORT_RANGE). LiveKit's own
# signaling port (7880) stays on 127.0.0.1 inside the container and is never published.
EXPOSE 8080 7881 61000-61100/udp
ENV TAVRN_DATA_DIR=/data
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["tavrn-node", "check-config"]
ENTRYPOINT ["tini", "--", "tavrn-node"]
CMD ["serve"]
