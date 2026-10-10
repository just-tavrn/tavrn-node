# tavrn-node

The server of [tavrn](https://github.com/just-tavrn/tavrn), a federated, self-hostable community chat with
end-to-end encrypted conversations: rooms with text, voice, announcement, forum and files channels, roles and
permissions, direct messages and friends across all nodes, voice, video and screen sharing. Anyone can run a
node; the nodes federate with each other, and messages in encrypted conversations are end-to-end encrypted,
so node operators can never read along.

One Rust binary, `tavrn-node`, holds the HTTP API and the WebSocket, federation with other nodes, the MLS
delivery service for end-to-end encryption, voice signaling and the embedded web client. The container image
adds `livekit-server` (voice and video, supervised by the node) and a minimal `ffmpeg` (avatars and other
media). The node speaks plain HTTP; a reverse proxy in front terminates TLS.

**This repository is for operators and node developers.** It contains the node (`src/`, `migrations/`,
`templates/`, `tests/`), the container image and deployment examples (`deploy/`), the operator documentation
(`docs/`) and the performance tooling (`perf/`).

| Related repository | What it is |
|---|---|
| [tavrn](https://github.com/just-tavrn/tavrn) | project overview, architecture, roadmap, [self-hosting overview](https://github.com/just-tavrn/tavrn/blob/main/docs/self-hosting.md), Discussions |
| [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol) | the protocol: API (`openapi.json`), federation, encryption, test vectors (here the submodule `protocol/`) |
| [tavrn-crypto](https://github.com/just-tavrn/tavrn-crypto) | the end-to-end encryption core (a Rust dependency of the node) |
| [tavrn-web](https://github.com/just-tavrn/tavrn-web) | the web client embedded in the image |
| [tavrn-js](https://github.com/just-tavrn/tavrn-js) | SDK and bot runtime for clients and bots |

## Quick start (Docker Compose)

Requirements: a Linux host with Docker, a domain pointing to it, and a reverse proxy with TLS (nginx, Caddy,
Traefik or Nginx Proxy Manager; the node never terminates TLS itself). For voice and video, a UDP port range
and one TCP port must be reachable from the internet.

1. Put [`deploy/docker-compose.yml`](deploy/docker-compose.yml) and [`deploy/.env.example`](deploy/.env.example)
   into a directory on the host, and copy `.env.example` to `.env` there.
2. In `.env`, set at least `TAVRN_DOMAIN` and `POSTGRES_PASSWORD`, and decide on `TAVRN_REGISTRATION`.
3. Start it:

   ```sh
   docker compose up -d
   docker compose logs -f tavrn      # the node validates its configuration and names every problem
   ```

4. Point the reverse proxy at `127.0.0.1:8080` with WebSocket support:
   [Reverse proxy and TLS](docs/HANDBOOK.md#reverse-proxy-and-tls) (examples for nginx and Caddy in `deploy/`).
5. Open the firewall for voice: the UDP range `TAVRN_RTC_UDP_PORT_RANGE` (default `61000-61100`) and
   `TAVRN_RTC_TCP_PORT` (default 7881), published 1:1 and forwarded by the router.
6. Open `https://<your domain>` and register: the first account becomes node admin.

The compose file runs PostgreSQL next to the node; an external database works too (`TAVRN_DATABASE_URL`).
`docker compose exec tavrn tavrn-node check-config` prints the effective configuration and checks LiveKit and
the SSO provider. Everything after the quick start is in the [operator handbook](docs/HANDBOOK.md).

## Configuration

Everything is configured through environment variables; [`deploy/.env.example`](deploy/.env.example) is the
annotated template, and the [operator handbook](docs/HANDBOOK.md) lists **every variable** with its default and
range in [Configuration](docs/HANDBOOK.md#configuration). The handbook also covers:

- [Reverse proxy and TLS](docs/HANDBOOK.md#reverse-proxy-and-tls): WebSockets, nginx and Caddy, TURN over TLS,
  delegating an identity domain to another host.
- [Keys and backups](docs/HANDBOOK.md#keys-and-backups), [Database](docs/HANDBOOK.md#database) and
  [Storage and media](docs/HANDBOOK.md#storage-and-media): the key files, encryption at rest and the storage key,
  who may upload what, files channels and external stores, message retention.
- [Federation](docs/HANDBOOK.md#federation): the peer directory and conformance checks of other nodes;
  [Voice and video](docs/HANDBOOK.md#voice-and-video): ports, addresses, TURN, moved members and the desktop app's
  native voice.
- [Web push](docs/HANDBOOK.md#web-push) and [Metrics and health](docs/HANDBOOK.md#metrics-and-health).
- [Scaling with Valkey](docs/HANDBOOK.md#scaling-with-valkey): several instances of one node behind a load balancer.
- [Webhooks and applications](docs/HANDBOOK.md#webhooks-and-applications): bots and incoming webhooks, including
  encrypted channels.
- [SSO with OpenID Connect](docs/HANDBOOK.md#single-sign-on-openid-connect), [mail languages and templates](docs/HANDBOOK.md#mail-languages-and-templates),
  [legal pages and GDPR](docs/HANDBOOK.md#legal-pages-and-gdpr) with the [age gates](docs/HANDBOOK.md#age-gates),
  [moderation](docs/HANDBOOK.md#moderation-and-auto-moderation) (channel visibility, audit logs, history restores
  after a key reset), the [CLI commands](docs/HANDBOOK.md#the-doctor-and-other-cli-commands),
  [troubleshooting](docs/HANDBOOK.md#logs-and-troubleshooting) and a
  [security hardening checklist](docs/HANDBOOK.md#security-hardening-checklist).

## Backups

Back up the **database** (`pg_dump`) and the **data volume** (`./data`, mounted at `/data`) together, before
every upgrade and regularly. The volume holds the uploaded files and, in `data/keys/`, the node's keys, all
created at the first start:

| File | What it is | If it is lost |
|---|---|---|
| `keys/node-<kid>.pem` | the node's signing keys (federation, tokens) | other nodes no longer trust the node's identity |
| `keys/secrets.key` | encrypts data at rest such as the users' TOTP secrets and the credentials of external file stores | every TOTP enrollment becomes unusable; external file stores need their credentials again |
| `keys/storage.key` | wraps the keys of every stored file (attachments, avatars, emojis, …) | **every stored file is unreadable**; the node refuses to start |
| `keys/livekit.key` | LiveKit's API key | regenerated, nothing lost |
| `keys/vapid.key` | the key that signs web push requests (VAPID) | every push subscription becomes invalid; users re-enable push on each device |

Never replace or delete these files; restore them from the same backup as the database. Backup and restore
procedure: [Keys and backups](docs/HANDBOOK.md#keys-and-backups); rotating the storage key:
[Rotating the storage key](docs/HANDBOOK.md#rotating-the-storage-key).

## Upgrading

```sh
docker compose pull && docker compose up -d
```

- Back up first (see above). Migrations run automatically at start and only forward; the node refuses to
  start against a database that is newer than the binary, so a downgrade means restoring the backup.
- Pin a release line with `IMAGE_TAG` in `.env` (for example `0.1`) to get fixes without surprises; the
  default `latest` follows every release. Read the [release notes](https://github.com/just-tavrn/tavrn-node/releases)
  before moving to a new minor version.
- Several instances behind a load balancer: update one instance at a time
  ([Upgrade and rollback](docs/HANDBOOK.md#upgrade-and-rollback)).
- Watch the releases of this repository for security fixes.

Versions before 1.0 may still change configuration or behavior between minor versions; the release notes say
what an operator has to do.

## Building

Requirements: Rust (the toolchain in `rust-toolchain.toml`), [`just`](https://github.com/casey/just), git,
optionally [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny), Docker for the PostgreSQL/Valkey test
containers and the image, Node.js 24 for the performance report.

```sh
git clone --recurse-submodules https://github.com/just-tavrn/tavrn-node
cd tavrn-node
just dev-server      # node on http://127.0.0.1:8080 (development mode: SQLite in data-dev/, no TLS)
just test-services   # PostgreSQL and Valkey test containers
just check           # what the CI runs: SPDX headers, licenses, fmt, clippy, tests on SQLite and PostgreSQL
```

While the repositories are private, the protocol submodule and the git dependency `tavrn-crypto` need your
GitHub credentials. Cargo uses the git command line for that when `CARGO_NET_GIT_FETCH_WITH_CLI=true` is set
(the `justfile` sets it; for plain `cargo` export it yourself), and git needs a credential helper for
github.com, for example `gh auth setup-git`.

The node embeds the web client from `web/dist/` at compile time. Without a bundle there (only the tracked
placeholder `web/dist/.gitkeep`) the node builds and serves the API, and `/` answers that the web client is not
embedded. To embed one, build [tavrn-web](https://github.com/just-tavrn/tavrn-web) and copy its bundle into
`web/dist/`. For development, run the web client's dev server against `just dev-server` instead.

Voice needs `livekit-server` next to the node (`just livekit-install`; without it start with
`TAVRN_VOICE_ENABLED=false`), the media pipeline `ffmpeg` with libwebp (`just ffmpeg-install`). Tests that need
them skip themselves with a message when they are missing; the CI installs both.

Tests: `just test` (SQLite) and `just test-pg` (PostgreSQL, and the cluster tests against Valkey) run the unit
tests, the integration tests in `tests/` (one test binary, `tests/main.rs`), the protocol's test vectors from
`protocol/testvectors/` and a comparison of the API specification generated from the routes with
`protocol/openapi.json`. API changes are made in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol)
first; `just openapi` shows the difference and what to do. Performance budgets: `just perf-node`
([perf/README.md](perf/README.md)).

With `TAVRN_TEST_DATABASE_URL` (what `just test-pg` sets: the container of `just test-services`) every test node
gets its own database `t_<ulid>` on that PostgreSQL server and drops it again when the node goes away
(`tests/common/databases.rs`). A run that is killed or crashes leaves its databases behind; the name carries the
creation time, and before creating a database the tests drop the `t_*` databases older than
`TAVRN_TEST_DB_MAX_AGE_SECS` (default 1200, 20 minutes; at most once a minute per test binary). Nothing else on
the server is touched. `just test-pg-clean` drops every `t_*` database at once (only while no tests run).

### Container image

Releases are published as `ghcr.io/just-tavrn/tavrn-node:<version>` (tags `X.Y.Z`, `X.Y`, `latest`). To build
the image yourself:

```sh
GH_TOKEN=$(gh auth token) docker build -f deploy/Dockerfile -t tavrn-node:dev \
  --secret id=read_token,env=GH_TOKEN .
```

The Dockerfile builds the web client from tavrn-web at the build argument `TAVRN_WEB_REF` (default `main`; a
branch, tag or commit). With `--build-arg TAVRN_WEB_SOURCE=local` it embeds a prebuilt bundle from `web/dist/`
of the build context instead. The token (secret `read_token`, or `TAVRN_WEB_TOKEN` for the web stage only) is
needed while the repositories are private: cargo fetches `tavrn-crypto` with it and the web stage clones
tavrn-web. It is never stored in the image. `just docker-build` wraps this (`just docker-build local`,
`just docker-build git v0.1.0`).

## Security

Please report vulnerabilities privately through GitHub's private vulnerability reporting ("Report a
vulnerability" on the [Security tab](https://github.com/just-tavrn/tavrn-node/security/advisories/new)), never
as public issues; see the [security policy](https://github.com/just-tavrn/.github/blob/main/SECURITY.md). The
code has not been audited yet.

## Contributing

Contributions are welcome: see the [contributing guide](https://github.com/just-tavrn/.github/blob/main/CONTRIBUTING.md)
and the [code of conduct](https://github.com/just-tavrn/.github/blob/main/CODE_OF_CONDUCT.md). Changes to the
API or the federation protocol start in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol).
Contributions are accepted under the [contributor license agreement](CLA.md), signed once through the CLA bot
on your first pull request. Run `just check` before opening a pull request. Questions go to the
[Discussions](https://github.com/just-tavrn/tavrn/discussions).

## License

[AGPL-3.0-only](LICENSE): if you run a modified node for others, you must offer them its source code. The
dependencies and the binaries in the image (LiveKit: Apache-2.0, ffmpeg: LGPL-2.1-or-later, the web client:
Apache-2.0) are audited in [docs/LICENSES.md](docs/LICENSES.md). The name "tavrn" and the logo are not covered
by the license: see [TRADEMARK.md](TRADEMARK.md) (running an unmodified or locally patched node under the name
is fine).
