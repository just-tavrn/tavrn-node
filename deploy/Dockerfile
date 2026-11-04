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
#
# Several architectures (linux/amd64, linux/arm64): every stage that compiles runs on the build machine
# ($BUILDPLATFORM) and cross-compiles for the target ($TARGETPLATFORM), so an arm64 image builds on an amd64 host
# without emulating the compilers; only the small runtime stage (apt-get) runs emulated (QEMU via binfmt):
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f deploy/Dockerfile --secret id=read_token,env=GH_TOKEN .
#
# A plain `docker build` builds for the host's own architecture exactly as before (no cross toolchain involved).

ARG TAVRN_WEB_SOURCE=git

# Every base image is pinned by digest (Dependabot keeps tag and digest current); the tag says which release it is.

# ---- Web client from the tavrn-web repository ------------------------------------
# The bundle is the same for every architecture: built once, on the build machine.
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS web-git
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
# Runs on the build machine. Two layers: the dependencies, compiled from cargo-chef's recipe (the manifests and
# Cargo.lock only), then the node itself. A change under src/ reuses the dependency layer: from the local build cache,
# and in GitHub-hosted runs from the Actions cache, which exports layers (the docker-publish workflow's cache-to), not
# BuildKit cache mounts. The dependency layer holds the compiled crates and the crates.io sources, never a token: the
# private git dependency is fetched into a cache mount (the token reaches git only through GIT_CONFIG_* variables of
# the RUN), so no layer carries its checkout.
FROM --platform=$BUILDPLATFORM rust:1-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS chef
WORKDIR /src
# cargo fetches the private git dependency tavrn-crypto (and its protocol submodule) with the git CLI.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ARG CARGO_CHEF_VERSION=0.1.78
RUN cargo install --locked "cargo-chef@${CARGO_CHEF_VERSION}" \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# The recipe: what the dependency build needs (manifests, Cargo.lock, the layout of the targets), without the code.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src src
# The perf load generator is a workspace member; cargo needs its manifest even when it is not built.
COPY perf/loadgen perf/loadgen
RUN cargo chef prepare --recipe-path recipe.json

# For another target architecture the server stage installs Debian's cross gcc and the Rust target and writes
# /cross.env (cargo's target, linker and the C compiler of the -sys crates: ring, the bundled SQLite, the vendored
# OpenSSL); for the host's own architecture there is no /cross.env and cargo builds natively.
FROM chef AS server
ARG BUILDARCH
ARG TARGETARCH
# Parallel compile jobs (empty: one per CPU); lower it on machines with little memory.
ARG BUILD_JOBS=
COPY rust-toolchain.toml ./
RUN set -eu; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      case "$TARGETARCH" in \
        amd64) arch=x86_64; machine=x86-64 ;; \
        arm64) arch=aarch64; machine="ARM aarch64" ;; \
        *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
      esac; \
      gnu="$arch-linux-gnu"; triple="$arch-unknown-linux-gnu"; var="$(echo "$triple" | tr a-z- A-Z_)"; pkg="$(echo "$gnu" | tr _ -)"; \
      apt-get update && apt-get install -y --no-install-recommends "gcc-$pkg" "g++-$pkg" "libc6-dev-$TARGETARCH-cross" \
      && rm -rf /var/lib/apt/lists/*; \
      rustup toolchain install && rustup target add "$triple"; \
      { echo "export CARGO_BUILD_TARGET=$triple"; \
        echo "export CARGO_TARGET_${var}_LINKER=$gnu-gcc"; \
        echo "export CC_$(echo "$triple" | tr - _)=$gnu-gcc CXX_$(echo "$triple" | tr - _)=$gnu-g++ AR_$(echo "$triple" | tr - _)=$gnu-ar"; \
        echo "ELF_MACHINE='$machine'"; } > /cross.env; \
      cat /cross.env; \
    fi
# The dependencies (cached until Cargo.toml or Cargo.lock change). cook gets the target explicitly: it removes the
# placeholder build of the workspace's own crates from that target's directory afterwards.
COPY --from=planner /src/recipe.json recipe.json
RUN --mount=type=secret,id=read_token --mount=type=secret,id=TAVRN_WEB_TOKEN \
    --mount=type=cache,target=/usr/local/cargo/git,id=tavrn-node-cargo-git \
    set -eu; \
    token="$(cat /run/secrets/read_token 2>/dev/null || cat /run/secrets/TAVRN_WEB_TOKEN 2>/dev/null || true)"; \
    if [ -n "$token" ]; then \
      export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.https://x-access-token:${token}@github.com/just-tavrn/.insteadOf" \
             GIT_CONFIG_VALUE_0="https://github.com/just-tavrn/"; \
    fi; \
    if [ -f /cross.env ]; then . /cross.env; fi; \
    if [ -n "$BUILD_JOBS" ]; then export CARGO_BUILD_JOBS="$BUILD_JOBS"; fi; \
    cargo chef cook --release --locked -p tavrn-node --recipe-path recipe.json ${CARGO_BUILD_TARGET:+--target "$CARGO_BUILD_TARGET"}
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY migrations migrations
COPY templates templates
COPY perf/loadgen perf/loadgen
# Embed the web build (rust-embed).
COPY --from=web /dist web/dist
RUN test -f web/dist/index.html || { echo "no web client bundle (web/dist/index.html missing)" >&2; exit 1; }
# The node itself. The touch makes cargo rebuild the workspace's crates whatever the files' times are (COPY keeps the
# build context's modification times, which can be older than the dependency layer).
RUN --mount=type=secret,id=read_token --mount=type=secret,id=TAVRN_WEB_TOKEN \
    --mount=type=cache,target=/usr/local/cargo/git,id=tavrn-node-cargo-git \
    set -eu; \
    token="$(cat /run/secrets/read_token 2>/dev/null || cat /run/secrets/TAVRN_WEB_TOKEN 2>/dev/null || true)"; \
    if [ -n "$token" ]; then \
      export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.https://x-access-token:${token}@github.com/just-tavrn/.insteadOf" \
             GIT_CONFIG_VALUE_0="https://github.com/just-tavrn/"; \
    fi; \
    ELF_MACHINE=; if [ -f /cross.env ]; then . /cross.env; fi; \
    touch src/main.rs src/lib.rs; \
    cargo build --release --locked -p tavrn-node ${BUILD_JOBS:+--jobs "$BUILD_JOBS"} \
    && cp "target/${CARGO_BUILD_TARGET:-.}/release/tavrn-node" /tavrn-node \
    && if [ -n "$ELF_MACHINE" ]; then file -b /tavrn-node && file -b /tavrn-node | grep -q "^ELF 64-bit LSB pie executable, $ELF_MACHINE,"; fi

# ---- Static ffmpeg for the media pipeline (src/media.rs) ------------------------------
# Only what the pipeline needs: image and short-video decoders, WebP encoding, file/pipe I/O. No network
# protocols, no devices, no other muxers: a small static binary instead of Debian's ffmpeg with its
# ~100 shared libraries. The version rule (README.md "Tool versions"): the same FFmpeg release as the tests use
# (`just ffmpeg-install` and ci.yml take BtbN's dated build of that release); bump them together.
# Runs on the build machine; for another target architecture libwebp and ffmpeg are cross-compiled with Debian's
# cross gcc against the target's zlib (dpkg multiarch), and the result is checked with `file` instead of being run.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS ffmpeg
ARG BUILDARCH
ARG TARGETARCH
ARG FFMPEG_VERSION=8.1.3
ARG FFMPEG_SHA256=7138d28c96d9d3e3af4ee3d8cad72741f8ffb40da90c1112235dea3ecd3178a3
ARG LIBWEBP_VERSION=1.6.0
ARG LIBWEBP_SHA256=e4ab7009bf0629fd11982d4c2aa83964cf244cffba7347ecd39019a9e38c4564
# /cross.env: empty for a native build; the cross prefix and configure flags otherwise.
RUN set -eu; \
    if [ "$TARGETARCH" = "$BUILDARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends build-essential nasm pkg-config ca-certificates curl xz-utils zlib1g-dev; \
      : > /cross.env; \
    else \
      case "$TARGETARCH" in \
        amd64) arch=x86_64; machine=x86-64 ;; \
        arm64) arch=aarch64; machine="ARM aarch64" ;; \
        *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
      esac; \
      gnu="$arch-linux-gnu"; \
      dpkg --add-architecture "$TARGETARCH"; \
      apt-get update && apt-get install -y --no-install-recommends build-essential nasm pkg-config ca-certificates curl xz-utils file \
        "gcc-$(echo "$gnu" | tr _ -)" "libc6-dev-$TARGETARCH-cross" "zlib1g-dev:$TARGETARCH"; \
      { echo "CROSS=$gnu-"; \
        echo "WEBP_CROSS='--host=$gnu'"; \
        echo "FFMPEG_CROSS='--enable-cross-compile --arch=$arch --target-os=linux --cross-prefix=$gnu- --pkg-config=pkg-config'"; \
        echo "ELF_MACHINE='$machine'"; } > /cross.env; \
      cat /cross.env; \
    fi; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN set -eu; CROSS=; WEBP_CROSS=; . /cross.env; \
    curl -fsSLo webp.tar.gz "https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${LIBWEBP_VERSION}.tar.gz" \
    && echo "${LIBWEBP_SHA256}  webp.tar.gz" | sha256sum -c - \
    && tar xzf webp.tar.gz && cd "libwebp-${LIBWEBP_VERSION}" \
    && ./configure $WEBP_CROSS --prefix=/opt/deps --disable-shared --enable-static --disable-png --disable-jpeg --disable-tiff --disable-gif --disable-wic --disable-gl --disable-sdl \
    && make -j"$(nproc)" && make install
RUN set -eu; CROSS=; FFMPEG_CROSS=; ELF_MACHINE=; . /cross.env; \
    curl -fsSLo ffmpeg.tar.xz "https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz" \
    && echo "${FFMPEG_SHA256}  ffmpeg.tar.xz" | sha256sum -c - \
    && tar xJf ffmpeg.tar.xz && cd "ffmpeg-${FFMPEG_VERSION}" \
    && PKG_CONFIG_PATH=/opt/deps/lib/pkgconfig ./configure $FFMPEG_CROSS --prefix=/opt/ffmpeg \
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
    && make -j"$(nproc)" && make install && "${CROSS}strip" /opt/ffmpeg/bin/ffmpeg \
    && if [ -z "$ELF_MACHINE" ]; then \
         /opt/ffmpeg/bin/ffmpeg -hide_banner -encoders | grep -q libwebp_anim; \
       else \
         grep -q "define CONFIG_LIBWEBP_ANIM_ENCODER 1" config_components.h \
         && file -b /opt/ffmpeg/bin/ffmpeg \
         && file -b /opt/ffmpeg/bin/ffmpeg | grep -q "^ELF 64-bit LSB executable, $ELF_MACHINE, .*, statically linked,"; \
       fi

# ---- LiveKit binary ---------------------------------------------------------
# Pinned; keep in sync with livekit_version in the justfile and LIVEKIT_VERSION in .github/workflows/ci.yml.
# The digest is the multi-architecture index: the stage resolves to the target's image (amd64 or arm64).
FROM livekit/livekit-server:v1.13.9@sha256:d0c04791bf63ca8dcea123571827d56ba9504bd57c8d5de60ee03b5408cc3154 AS livekit

# ---- Runtime image ---------------------------------------------------------
# The only stage of the target architecture that runs commands (emulated in a cross build): keep it small.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
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
# One local request to /healthz (3 s timeout, nothing printed while healthy); `check-config` stays a manual command.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["tavrn-node", "health"]
ENTRYPOINT ["tini", "--", "tavrn-node"]
CMD ["serve"]
