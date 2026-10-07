## What and why

<!-- What does this change, and why? Link the issue (Fixes #123). -->

## Checklist

- [ ] `just check` passes locally (fmt, clippy, tests on SQLite and PostgreSQL, SPDX headers, licenses)
- [ ] API, federation or wire-format changes are specified in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol) first; `just openapi` matches the pinned `protocol/` submodule
- [ ] New migrations are additive (existing migration files are never edited: their checksums are stored in every database)
- [ ] New configuration is documented in `deploy/.env.example` (and the README if operators must act)
- [ ] New source files carry the SPDX header `// SPDX-License-Identifier: AGPL-3.0-only`
- [ ] No secrets, keys or private hosts in code, tests or logs
- [ ] I have signed the [CLA](https://github.com/just-tavrn/tavrn-node/blob/main/CLA.md) (the CLA bot asks on your first pull request)
