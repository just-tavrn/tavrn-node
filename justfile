# tavrn-node: developer tasks. `just --list` shows all of them.

set shell := ["bash", "-euo", "pipefail", "-c"]

# tavrn-crypto is a private git dependency for now: let cargo fetch it with the git CLI, which uses your git
# credentials (for example `gh auth setup-git`), see README.md "Building".
export CARGO_NET_GIT_FETCH_WITH_CLI := "true"

# LiveKit version the node is tested with (also pinned in deploy/Dockerfile and .github/workflows/ci.yml)
livekit_version := "1.13.8"

# Test containers of `just test-pg` (start them with `just test-services`)
pg_url := env("TAVRN_TEST_DATABASE_URL", "postgres://tavrn:tavrn@localhost:55432/tavrn_test")
valkey_url := env("TAVRN_TEST_CACHE_URL", "redis://127.0.0.1:56379")

default:
    @just --list

# Start the node in development mode (SQLite in data-dev/, HTTP without TLS, http://127.0.0.1:8080)
dev-server: protocol
    cargo run -p tavrn-node -- --dev

# Every check of the CI: licenses, format, lints (node and load generator), tests on SQLite and on PostgreSQL
check: license-check fmt-check clippy clippy-loadgen test test-pg test-perf-report

# SPDX headers and the licenses of the Rust dependencies (deny.toml; all of cargo deny: `just deny`)
license-check:
    scripts/check-spdx.sh
    if command -v cargo-deny >/dev/null; then cargo deny --log-level error check licenses; else echo "cargo-deny not installed (cargo install cargo-deny --locked): Rust licenses not checked"; fi

# Licenses, advisories, bans and sources of the Rust dependencies (deny.toml)
deny:
    cargo deny --log-level error check

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy: protocol
    cargo clippy -p tavrn-node --all-targets --locked -- -D warnings

# Lints of the load generator of the performance budgets (perf/loadgen)
clippy-loadgen:
    cargo clippy -p tavrn-perf-loadgen --all-targets --locked -- -D warnings

# Unit and integration tests on SQLite, including the protocol's test vectors and the OpenAPI comparison
# with protocol/openapi.json. Tests needing livekit-server or ffmpeg skip themselves when those are missing.
test: protocol
    env -u TAVRN_TEST_DATABASE_URL -u TAVRN_TEST_CACHE_URL cargo test --workspace --locked

# The same tests against PostgreSQL (catches dialect bugs SQLite hides), with the Valkey cluster tests
test-pg: protocol
    TAVRN_TEST_DATABASE_URL="{{pg_url}}" TAVRN_TEST_CACHE_URL="{{valkey_url}}" cargo test --workspace --locked

# Start the PostgreSQL and Valkey test containers of `just test-pg` (throwaway data: fsync off)
test-services:
    docker start tavrn-test-pg 2>/dev/null || docker run -d --name tavrn-test-pg --shm-size=1g -e POSTGRES_USER=tavrn -e POSTGRES_PASSWORD=tavrn -e POSTGRES_DB=tavrn_test -p 55432:5432 postgres:17-alpine -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=600
    docker start tavrn-test-valkey 2>/dev/null || docker run -d --name tavrn-test-valkey -p 56379:6379 valkey/valkey:8

# Drop the throwaway per-test databases (t_*) left behind by earlier runs (run only when no tests are running)
test-pg-clean:
    docker exec tavrn-test-pg psql -U tavrn -d postgres -Atc "SELECT 'DROP DATABASE ' || quote_ident(datname) || ';' FROM pg_database WHERE datname LIKE 't\_%'" | docker exec -i tavrn-test-pg psql -U tavrn -d postgres -q

# Unit tests of the performance report (Node.js 24, no dependencies)
test-perf-report:
    node --test perf/report.test.ts

# Compare the specification generated from the routes with protocol/openapi.json (the protocol repository
# is the source of truth: an API change is made there first, then the submodule moves to the new tag)
openapi: protocol
    #!/usr/bin/env bash
    set -euo pipefail
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
    cargo run -q -p tavrn-node -- --dev openapi > "$tmp"
    # info.version is the version of the node that generated the file, not part of the comparison.
    published_version="$(grep -m1 '^    "version": ' protocol/openapi.json)"
    sed -i "0,/^    \"version\": .*/s//${published_version}/" "$tmp"
    if ! diff -u protocol/openapi.json "$tmp"; then
        echo >&2
        echo "The specification generated from the routes differs from protocol/openapi.json (protocol $(git -C protocol describe --tags --always))." >&2
        echo "The protocol repository is the source of truth: update tavrn-protocol first (write the generated file there with" >&2
        echo "  cargo run -q -p tavrn-node -- --dev openapi > <your tavrn-protocol checkout>/openapi.json" >&2
        echo "and tag a new protocol version), then move the submodule:" >&2
        echo "  git -C protocol fetch --tags && git -C protocol checkout <tag> && git add protocol" >&2
        exit 1
    fi
    echo "OpenAPI specification matches protocol/openapi.json"

# Build the container image tavrn-node:dev. `just docker-build local` embeds ./web/dist (a prebuilt bundle of
# tavrn-web), `just docker-build git <ref>` builds tavrn-web at a branch, tag or commit; auto (the default)
# picks local when web/dist/index.html exists. The private repositories are read with $GH_TOKEN or the
# token of `gh auth token`; CARGO_BUILD_JOBS limits the compile jobs inside the build.
docker-build web="auto" ref="main":
    #!/usr/bin/env bash
    set -euo pipefail
    source="{{web}}"
    case "$source" in auto | local | git) ;; *) echo "web source must be auto, local or git" >&2; exit 1 ;; esac
    if [ "$source" = auto ]; then if [ -f web/dist/index.html ]; then source=local; else source=git; fi; fi
    GH_TOKEN="${GH_TOKEN:-$(gh auth token 2>/dev/null || true)}"
    [ -n "$GH_TOKEN" ] || { echo "no GitHub token: set GH_TOKEN or log in with gh auth login" >&2; exit 1; }
    export GH_TOKEN
    echo "web client: $source$( [ "$source" = git ] && echo " (tavrn-web@{{ref}})" || true )"
    docker build -f deploy/Dockerfile -t tavrn-node:dev --secret id=read_token,env=GH_TOKEN \
        --build-arg TAVRN_WEB_SOURCE="$source" --build-arg TAVRN_WEB_REF="{{ref}}" \
        ${CARGO_BUILD_JOBS:+--build-arg BUILD_JOBS="$CARGO_BUILD_JOBS"} .

# Install livekit-server into ~/.local/bin (voice needs it next to the node; outside the repository)
livekit-install:
    #!/usr/bin/env bash
    set -euo pipefail
    # SHA-256 of the release archives (update them with livekit_version: the release's checksums.txt).
    case "$(uname -m)" in
      x86_64) arch=amd64 sum=059f6de65da11a57400e4646027da705d592ce42acb48c08570a397df446f869 ;;
      aarch64|arm64) arch=arm64 sum=39883cb07f370057692139fcf500a763cfedae1e9934bd8a1815a144e2127bd2 ;;
      armv7l) arch=armv7 sum=ccc859fea666a8f21444d27bff8e0e74f8f51ae4bb5bb37cb8e4073fbaaeed5d ;;
      *) echo "unsupported architecture $(uname -m)"; exit 1 ;;
    esac
    dir="${LIVEKIT_INSTALL_DIR:-$HOME/.local/bin}"
    mkdir -p "$dir"
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    file="livekit_{{livekit_version}}_linux_${arch}.tar.gz"
    curl -fsSLo "$tmp/$file" "https://github.com/livekit/livekit/releases/download/v{{livekit_version}}/$file"
    echo "$sum  $tmp/$file" | sha256sum -c --quiet - || { echo "livekit-server download does not match its checksum"; exit 1; }
    tar -xzf "$tmp/$file" -C "$tmp" livekit-server
    install -m 0755 "$tmp/livekit-server" "$dir/livekit-server"
    "$dir/livekit-server" --version
    case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to PATH (or set TAVRN_LIVEKIT_BINARY=$dir/livekit-server)" ;; esac

# Install a static ffmpeg into ~/.local/bin unless one with libwebp is in PATH (media pipeline: avatars,
# headers, room icons; src/media.rs). The Docker image builds its own minimal ffmpeg (deploy/Dockerfile).
ffmpeg-install:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v ffmpeg >/dev/null && ffmpeg -hide_banner -encoders 2>/dev/null | grep -q libwebp_anim; then ffmpeg -hide_banner -version | head -1; exit 0; fi
    # A dated BtbN build (the month-end builds stay available) checked against its SHA-256; the same as ci.yml.
    release=autobuild-2026-09-30-13-08
    case "$(uname -m)" in
      x86_64) file=ffmpeg-n8.1.3-9-g29e619e767-linux64-gpl-8.1.tar.xz sum=97ce978979194b5cf7e06a5e68020dbdaa7a4f3294c5452b6a1bc347100dbb79 ;;
      aarch64|arm64) file=ffmpeg-n8.1.3-9-g29e619e767-linuxarm64-gpl-8.1.tar.xz sum=10523d1e0be6b3ce62a9708cc50815c4b5eb5f36ae147fbe2afeecda6f2d6845 ;;
      *) echo "unsupported architecture $(uname -m)"; exit 1 ;;
    esac
    dir="${FFMPEG_INSTALL_DIR:-$HOME/.local/bin}"
    mkdir -p "$dir"
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    curl -fsSLo "$tmp/$file" "https://github.com/BtbN/FFmpeg-Builds/releases/download/$release/$file"
    echo "$sum  $tmp/$file" | sha256sum -c --quiet - || { echo "ffmpeg download does not match its checksum"; exit 1; }
    tar -xJf "$tmp/$file" -C "$tmp" --strip-components=2 --wildcards '*/bin/ffmpeg'
    install -m 0755 "$tmp/ffmpeg" "$dir/ffmpeg"
    "$dir/ffmpeg" -hide_banner -version | head -1
    case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to PATH (or set TAVRN_MEDIA_FFMPEG=$dir/ffmpeg)" ;; esac

# Node performance budgets (perf/README.md): release builds, the load generator against a release node with
# PostgreSQL, then the report (several minutes; run it alone on the machine)
perf-node: protocol
    cargo build --release --locked -p tavrn-node -p tavrn-perf-loadgen
    rm -f perf/results/raw/node.json
    target="${CARGO_TARGET_DIR:-target}"; status=0; TAVRN_TEST_DATABASE_URL="{{pg_url}}" "$target/release/tavrn-loadgen" --node-bin "$target/release/tavrn-node" || status=1; node perf/report.ts perf/results/raw/node.json || status=1; exit $status

# Check out the protocol submodule (test vectors, openapi.json) if it is missing
protocol:
    @[ -f protocol/testvectors/permissions.json ] || git submodule update --init protocol

# Free the build caches (cargo never garbage-collects; honors CARGO_TARGET_DIR)
clean-caches:
    cargo clean
    du -sh "${CARGO_TARGET_DIR:-target}" 2>/dev/null || true
