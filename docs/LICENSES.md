# Licenses and dependency audit

The licensing model of tavrn-node, the allow-list for third-party licenses, the direct dependencies with their
licenses, the special cases (binaries in the container image that are not ordinary dependencies) and the
compatibility verdict. Audit date: 2026-10-06 (`cargo deny check licenses`, `cargo metadata`).

## 1. Model

Everything in this repository (the node `tavrn-node`, the deployment files in `deploy/` and the performance
tooling in `perf/`, including the load generator `perf/loadgen`) is **AGPL-3.0-only** ([LICENSE](../LICENSE)).
The node is the piece a hosting company would run as a service: network use counts as distribution, so
changes to a public node must be published.

The other tavrn repositories carry their own licenses: the protocol ([tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol),
Apache-2.0 for schemas and test vectors, CC-BY-4.0 for the prose), the encryption core
([tavrn-crypto](https://github.com/just-tavrn/tavrn-crypto), MPL-2.0), the SDK and bot runtime
([tavrn-js](https://github.com/just-tavrn/tavrn-js), Apache-2.0 and MPL-2.0) and the web client
([tavrn-web](https://github.com/just-tavrn/tavrn-web), Apache-2.0). Apache-2.0 and MPL-2.0 code may be used
inside AGPL projects. The name and logo are covered by [TRADEMARK.md](../TRADEMARK.md), not by these licenses.

Rules for dependencies:

- The node may use GPL-compatible copyleft code and GPL tools (it is AGPL-3.0 itself), but only through an
  explicit, crate-specific exception in `deny.toml`, and only if the crate is not reachable from
  `tavrn-crypto` (`cargo tree -i <crate>`), which must stay free of it.
- Development-only tools are not distributed; they are still checked so that nothing copyleft slips into a
  build by accident.

Every hand-written source file carries an SPDX header. Checks: `just license-check` (part of `just check`
and the CI): `scripts/check-spdx.sh` and `cargo deny check licenses` (`deny.toml`); the CI runs the full
`cargo deny check`.

## 2. Allow-list

`deny.toml` (the same list as the other tavrn repositories):

`MIT`, `MIT-0`, `0BSD`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`,
`ISC`, `MPL-2.0`, `Zlib`, `Unicode-3.0`, `Unicode-DFS-2016`, `CC0-1.0`, `BSL-1.0`, `OpenSSL`.

An SPDX `OR` expression passes when one alternative is allowed (the project uses that alternative), an `AND`
expression when every part is allowed.

Crate-specific exceptions in `deny.toml`:

| Crate | License | Reason |
|---|---|---|
| `tavrn-node`, `tavrn-perf-loadgen` | AGPL-3.0-only | our own crates |
| `webpki-roots` | CDLA-Permissive-2.0 | Mozilla's CA certificate bundle (data, permissive), compiled into the rustls TLS stack of `reqwest`, `lettre` and `sqlx` |

Audit result: `cargo deny check licenses`: **licenses ok**.

Advisories: `cargo deny check advisories` reports two advisories that predate this audit; both are accepted
as `ignore` entries in `deny.toml` until upstream moves: RUSTSEC-2023-0071 (`rsa` 0.9, Marvin timing attack, via `jsonwebtoken`
and `livekit-api`; no fixed version exists; the node uses RSA only to verify ID-token signatures of SSO
providers with public keys, where the timing side channel on private-key operations does not apply) and RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained, a build-time macro crate via
`openmls_rust_crypto` → `hpke-rs` → `libcrux`).

`cargo audit` scans every entry of `Cargo.lock` rather than the build graph and additionally reports
RUSTSEC-2026-0330 and RUSTSEC-2026-0331 (`libcrux-kem` 0.0.9). That crate is a lockfile entry only and is never
compiled: `hpke-rs` 0.7 declares its libcrux backend as an optional dependency named by a weak feature, which
Cargo records in the lockfile, but nothing enables it (`cargo tree --target all -i libcrux-kem` prints nothing;
`cargo deny` does not see it). `.cargo/audit.toml` ignores both, with the same reasoning, until a released
`openmls_rust_crypto` accepts `hpke-rs` 0.8 (which brings the fixed `libcrux-kem` 0.0.10).

## 3. Direct dependencies

`tavrn-node` (AGPL-3.0-only):

| Crate | Version | License | Kind |
|---|---|---|---|
| `aes-gcm` | 0.11.1 | Apache-2.0 OR MIT | runtime |
| `anyhow` | 1.0.104 | MIT OR Apache-2.0 | runtime |
| `argon2` | 0.5.3 | MIT OR Apache-2.0 | runtime |
| `axum` | 0.8.9 | MIT | runtime |
| `base64` | 0.23.1 | MIT OR Apache-2.0 | runtime |
| `chrono` | 0.4.45 | MIT OR Apache-2.0 | runtime |
| `clap` | 4.6.7 | MIT OR Apache-2.0 | runtime |
| `ed25519-dalek` | 2.2.0 | BSD-3-Clause | runtime |
| `figment` | 0.10.19 | MIT OR Apache-2.0 | runtime, dev |
| `futures` | 0.3.34 | MIT OR Apache-2.0 | runtime |
| `hkdf` | 0.13.0 | MIT OR Apache-2.0 | runtime |
| `hmac` | 0.13.0 | MIT OR Apache-2.0 | runtime |
| `image-webp` | 0.2.4 | MIT OR Apache-2.0 | runtime |
| `ipnet` | 2.12.2 | MIT OR Apache-2.0 | runtime |
| `jsonwebtoken` | 11.1.0 | MIT | runtime |
| `lettre` | 0.11.23 | MIT | runtime |
| `livekit-api` | 0.8.2 | Apache-2.0 | runtime |
| `livekit-protocol` | 0.8.0 | Apache-2.0 | runtime |
| `log` | 0.4.34 | MIT OR Apache-2.0 | runtime |
| `mime_guess` | 2.0.5 | MIT | runtime |
| `nix` | 0.31.3 | MIT | runtime (unix) |
| `openssl` (vendored: `openssl-src`, OpenSSL 3, Apache-2.0) | 0.10.81 | Apache-2.0 | runtime |
| `rand` | 0.10.3 | MIT OR Apache-2.0 | runtime |
| `reqwest` | 0.12.28 | MIT OR Apache-2.0 | runtime |
| `rust-embed` | 8.13.0 | MIT | runtime |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | runtime |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 | runtime |
| `sha2` | 0.11.0 | MIT OR Apache-2.0 | runtime |
| `sqlx` | 0.8.6 | MIT OR Apache-2.0 | runtime |
| `subtle` | 2.6.1 | BSD-3-Clause | runtime |
| `tavrn-crypto` | 0.1.0 | MPL-2.0 | runtime ([crates.io](https://crates.io/crates/tavrn-crypto), [tavrn-crypto](https://github.com/just-tavrn/tavrn-crypto)) |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 | runtime |
| `tokio` | 1.53.2 | MIT | runtime |
| `tokio-tungstenite` | 0.29.0 | MIT | runtime |
| `totp-rs` | 6.0.0 | MIT | runtime |
| `tower-http` | 0.7.1 | MIT | runtime |
| `tracing` | 0.1.44 | MIT | runtime |
| `tracing-subscriber` | 0.3.23 | MIT | runtime |
| `ulid` | 3.0.0 | MIT | runtime |
| `unicode-normalization` | 0.1.25 | MIT OR Apache-2.0 | runtime |
| `utoipa` | 5.5.0 | MIT OR Apache-2.0 | runtime |
| `webauthn-rs` | 0.5.5 | MPL-2.0 | runtime |
| `zeroize` | 1.9.1 | Apache-2.0 OR MIT | runtime |
| `http-body-util` | 0.1.5 | MIT | dev |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 | dev |
| `tower` | 0.5.3 | MIT | dev |
| `webauthn-authenticator-rs` | 0.5.5 | MPL-2.0 | dev |

Notable transitive licenses of `tavrn-crypto` (210 crates): `hpke-rs`, `hpke-rs-crypto`,
`hpke-rs-libcrux`, `hpke-rs-rust-crypto` (MPL-2.0, via OpenMLS), `bitcoin_hashes`, `hex-conservative`
(CC0-1.0, via `bip39`), `r-efi` (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`, used under MIT/Apache; UEFI only,
never compiled for our targets), `libloading` (ISC), `ryu-js` (`Apache-2.0 OR BSL-1.0`),
`unicode-ident` (`(MIT OR Apache-2.0) AND Unicode-3.0`). Everything else is MIT and/or Apache-2.0.

`tavrn-perf-loadgen` (`perf/loadgen/`, AGPL-3.0-only): `anyhow`, `chrono`, `clap`, `futures`, `libc`,
`reqwest`, `serde`, `serde_json`, `sqlx` (all MIT OR Apache-2.0), `tokio`, `tokio-tungstenite` 0.29,
`totp-rs`, `ulid` (MIT), `tavrn-crypto` (MPL-2.0).

## 4. Special cases

**The embedded web client.** The image embeds the production bundle of
[tavrn-web](https://github.com/just-tavrn/tavrn-web) (Apache-2.0, with MPL-2.0 files of `@tavrn/crypto` and
`@tavrn/e2ee`, OFL-1.1 fonts and Apache-2.0 MediaPipe models). It is served as static files, not linked into
the node; its own license audit lives in that repository.

**ffmpeg in the Docker image** (`deploy/Dockerfile`, stage `ffmpeg`). The image builds its own static
ffmpeg 8.0 with libwebp 1.6.0 (BSD-3-Clause) and zlib (Zlib). Configure flags used:

```text
--prefix=/opt/ffmpeg --pkg-config-flags=--static --extra-ldflags=-static --enable-static --disable-shared
--disable-everything --disable-autodetect --disable-network --disable-doc --disable-debug
--disable-ffplay --disable-ffprobe --disable-avdevice --enable-small
--enable-zlib --enable-libwebp
--enable-protocol=file,pipe
--enable-demuxer=gif,apng,image_png_pipe,image_jpeg_pipe,image_webp_pipe,mov,matroska,rawvideo
--enable-decoder=gif,png,apng,mjpeg,webp,h264,hevc,vp8,vp9,mpeg4,rawvideo
--enable-parser=h264,hevc,vp8,vp9,mpeg4video,png,gif,mjpeg,webp
--enable-encoder=libwebp,libwebp_anim
--enable-muxer=webp,null
--enable-filter=scale,crop,fps,format,null,setsar
```

There is no `--enable-gpl`, `--enable-version3` or `--enable-nonfree`, and no GPL component (x264, x265,
GPL filters) is enabled, so this binary is licensed under **LGPL-2.1-or-later**, not GPL. It is a separate
program that the node starts as a child process (`src/media.rs`), not linked into `tavrn-node`; both
licenses are compatible anyway. When the image is distributed, the LGPL asks for the ffmpeg and libwebp
source and license to be offered: the exact versions and SHA-256 sums are pinned in the Dockerfile (ffmpeg.org
tarballs); adding the license texts under `/usr/share/doc/ffmpeg/` in the image is an open item.
For development and CI, `just ffmpeg-install` and the CI download the BtbN "gpl" static build (GPL-3.0); it is
only executed on developer and CI machines, never distributed, so this is fine for every package.

**LiveKit server** (`livekit/livekit-server` v1.13.9, copied into the image): Apache-2.0, a separate
process supervised by the node.

## 5. Compatibility verdict

| Package | License | Depends on (A)GPL? | Verdict |
|---|---|---|---|
| `tavrn-node` | AGPL-3.0-only | No crate under (A)GPL/LGPL (only `r-efi`, which offers MIT/Apache as alternatives). Runs LGPL ffmpeg (container image) or GPL ffmpeg (development and CI) as a separate process. | Compatible. MPL-2.0 (`webauthn-rs`, `hpke-rs`, `tavrn-crypto`), Apache-2.0, MIT, BSD, ISC, CC0, Unicode, CDLA-Permissive data: all may be combined with AGPL-3.0. |
| `deploy/` | AGPL-3.0-only | The image bundles LGPL-2.1+ ffmpeg and Apache-2.0 LiveKit as separate programs and the Apache-2.0 web bundle as data | Compatible (mere aggregation; source offer for ffmpeg, see section 4). |
| `perf/` | AGPL-3.0-only | No | Compatible. |

Result: no incompatibility found.
