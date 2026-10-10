# Changelog

Changes of the tavrn node and its container image `ghcr.io/just-tavrn/tavrn-node`, newest first. Releases are the
tags `vX.Y.Z` of this repository; the image tags follow them (`X.Y.Z`, `X.Y`, `latest`). Upgrade notes are in the
[README](README.md) ("Upgrading"); protocol changes in
[tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release of the node and its container image.

- **Rooms and channels**: text, voice, announcement, forum and files channels, threads and forum posts, roles with
  layered permissions (room, channel and single-member overrides), visibility that withholds events, hints and pushes
  of channels a member cannot view.
- **End-to-end encryption delivery service** (MLS): key packages, commits checked against the public group state,
  stale epochs refused, history shares sealed per device, history restore after a key reset, encrypted files
  channels.
- **Federation** between nodes, direct messages and friends across nodes, a signed "over 18" claim instead of dates
  of birth.
- **Voice, video and screen sharing** through a supervised `livekit-server`, moves into voice channels, the voice
  state of all rooms (`/users/me/voice`).
- **Accounts**: mandatory second factor, passkeys, single sign-on, sessions and devices, age assurance (date of
  birth at registration, minimum age, adults-only rooms and channels).
- **Operators**: moderation with reports and evidence, auto-moderation, web push, localized mails with replaceable
  templates, message retention, metrics, legal tooling (takedown notices), clustering with Valkey, the operator
  handbook and deployment examples (Docker Compose, reverse proxies).
