# GitHub setup of tavrn-node

The repository is prepared so that nothing runs on GitHub until the owner switches it on. This page lists
what is configured in the repository and what has to be set by hand.

## Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to `main`, pull requests, by hand | the organization's `rust-ci.yml` (`cargo fmt`, `cargo clippy` of the node and the load generator, `cargo test` on PostgreSQL with livekit-server, ffmpeg and a Valkey for the cluster tests, incl. the protocol test vectors and the comparison with `protocol/openapi.json`, `cargo deny`); SPDX headers, `scripts/publish-check.sh`, the perf report tests; on pushes to `main` (and manual runs on `main`) the image is built on `ubuntu-latest` (never on the self-hosted runners) and published as `ghcr.io/just-tavrn/tavrn-node:edge` (what tavrn-web's end-to-end suite pulls by default); the web client inside it is the current commit of tavrn-web `main` (or `vars.TAVRN_WEB_REF`), resolved before the build so the build cache never serves a stale bundle |
| `release.yml` | tag `v*.*.*` | checks the tag against `Cargo.toml` and that `TAVRN_WEB_REF` is a tavrn-web release tag (a branch fails the release), builds the image GitHub-hosted and without any cache from that tag's commit (the organization's `docker-publish.yml`, pinned by commit: BuildKit's SLSA provenance and SBOM) and pushes `ghcr.io/just-tavrn/tavrn-node:<version>`, `:<major>.<minor>`, `:latest` and `:sha-…`, records GitHub's build provenance attestation of the digest, then creates the GitHub release with the digest |
| `perf.yml` | nightly, by hand | release builds, the load generator against a release node with PostgreSQL, the budget report (`perf/README.md`) |
| `gitleaks.yml` | push to `main`, pull requests, by hand | the organization's `gitleaks.yml`: secret scan of the full history (`.gitleaks.toml`) |
| `dependency-review.yml` | pull requests | refuses vulnerable dependencies and licenses outside the allow-list |
| `cla.yml` | pull requests, comments | the organization's `cla.yml` (CLA bot) |

The reusable workflows live in [`just-tavrn/.github`](https://github.com/just-tavrn/.github); its
`docs/GITHUB.md` describes the organization settings and how to create the tokens below.

Every job carries `if: ${{ vars.CI_ENABLED == 'true' }}`.

## Variables and secrets (Settings → Secrets and variables → Actions)

| Name | Kind | Purpose |
|---|---|---|
| `CI_ENABLED` | variable | `true` switches all workflows on. Unset or anything else: every job is skipped. |
| `TAVRN_READ_PAT` | secret | Private phase only: fine-grained PAT with `contents: read` on `tavrn-protocol`, `tavrn-crypto`, `tavrn-js` and `tavrn-web`. The reusable workflows get it as `READ_TOKEN`: the Rust job fetches the `protocol/` submodule and the `tavrn-crypto` git dependency with it, the image build receives it as the build secret `read_token` (cargo's git fetch and the web stage cloning tavrn-web and its git dependencies). Delete it once the repositories are public. |
| `TAVRN_WEB_REF` | variable | The tavrn-web release tag (`vX.Y.Z`) whose web client goes into release images; a release fails without it or with a branch name. The `edge` image of `main` uses it too (any branch, tag or commit; default `main`). Set it to the tavrn-web release before tagging a node release. |
| `PUBLISH_CHECK_PRIVATE` | secret | Comma-separated private domains, hosts and addresses that `scripts/publish-check.sh` refuses (the same strings as the owner's local `.publish-check.private`). |
| Dependabot secrets | secret (Dependabot) | Dependabot pull requests run with Dependabot's own secret store: add `TAVRN_READ_PAT` and `PUBLISH_CHECK_PRIVATE` again under Settings → Secrets and variables → Dependabot (or as organization Dependabot secrets), otherwise their CI fails at the private git dependencies and at the hygiene check. |
| `CLA_PAT` | organization secret | the CLA bot's token (`contents: write` on `just-tavrn/cla-signatures`). Organization secrets do not reach private repositories on the free plan: until the repository is public, add it as a repository secret as well. |

The image is pushed with the job's `GITHUB_TOKEN` (`packages: write`); no registry secret is needed. After the
first push, set the package `tavrn-node` (organization → Packages) to inherit access from this repository,
and to public visibility once the repository is public.

## Building the image locally (private phase)

```sh
git clone --recurse-submodules https://github.com/just-tavrn/tavrn-node && cd tavrn-node
GH_TOKEN=$(gh auth token) docker build -f deploy/Dockerfile -t tavrn-node:dev \
  --secret id=read_token,env=GH_TOKEN .
```

`just docker-build` does the same (`just docker-build local` embeds a prebuilt `web/dist` instead of
building tavrn-web). The token never ends up in a layer: the Dockerfile reads it from the secret mount inside a single
`RUN` and hands it to git through environment variables.

## Verifying an image

Release and `edge` images are one manifest list for `linux/amd64` and `linux/arm64`: `docker pull` picks the
host's architecture, and `docker buildx imagetools inspect ghcr.io/just-tavrn/tavrn-node:<version>` lists the list's
digest and both platform images. Both are built on an amd64 runner; the arm64 binaries (tavrn-node, ffmpeg) are
cross-compiled, not emulated, and LiveKit comes from its official arm64 image.

Every release image carries BuildKit's SLSA provenance and SBOM in the registry. Release images built after the
repository went public also carry GitHub's build provenance for their digest (GitHub's Free plan has no artifact
attestations for private repositories, so `release.yml` skips that job until the public switch; the release notes
print the command when it ran):

```sh
gh attestation verify oci://ghcr.io/just-tavrn/tavrn-node:<version> --repo just-tavrn/tavrn-node
docker buildx imagetools inspect ghcr.io/just-tavrn/tavrn-node:<version> --format '{{ json .Provenance }}'
```

The first proves that `release.yml` of this repository built the digest from the tagged commit on a GitHub-hosted
runner (the attestation's subject is the manifest list's digest, which `gh attestation verify` resolves the tag to;
verify the tag or that digest, not the digest of one platform's image); the second shows the build's inputs (the Dockerfile's base images, all pinned by digest, and the
`TAVRN_WEB_REF` commit of tavrn-web). Pin the digest in your compose file (`image:
ghcr.io/just-tavrn/tavrn-node:<version>@sha256:…`) to run exactly what you verified.

`release.yml` calls the organization's `docker-publish.yml` by commit, not `@main`; bumping it is a reviewed pull
request (just-tavrn/.github `docs/GITHUB.md` "Reusable workflows in release paths").

## Settings applied through the API

Default branch `main`, delete branches on merge, squash merges allowed, issues on, wiki off, projects off.
The labels of `scripts/github-labels.sh` were created at setup (run it again after changing the list).

## Settings the owner flips by hand

- [ ] `CI_ENABLED`, `TAVRN_READ_PAT`, `PUBLISH_CHECK_PRIVATE` and `CLA_PAT` when CI should run; `TAVRN_WEB_REF`
      before the first release built by CI.
- [ ] Secret scanning with push protection (Settings → Code security; free for public repositories).
- [ ] Private vulnerability reporting (Settings → Code security), so "Report a vulnerability" works.
- [ ] Dependency graph and Dependabot alerts (needed by `dependency-review.yml`; on private repositories
      only with GitHub Advanced Security). Dependabot cannot read the private git dependency and submodule
      until the repositories are public (or until it gets access through Settings → Code security →
      "Grant Dependabot access to private repositories" at the organization).
- [ ] Discussions: questions are routed to the Discussions of the umbrella repository `just-tavrn/tavrn`
      (`ISSUE_TEMPLATE/config.yml`).
- [ ] The container package `ghcr.io/just-tavrn/tavrn-node`: repository access and visibility (see above).
- [ ] Once public: branch protection or a ruleset for `main` (require pull requests, the CI checks `Rust`,
      `SPDX headers, publication hygiene, perf report`, `gitleaks`, `Dependency review`, `CLA`, linear
      history, no force pushes) and tag protection for `v*`. Not available for private repositories on the
      free plan.
