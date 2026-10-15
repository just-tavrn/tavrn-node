#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Checks that the pins of livekit-server and ffmpeg agree between the justfile (development), .github/workflows/ci.yml
# (the CI's tests) and deploy/Dockerfile (the image); README.md "Tool versions" has the rule. Prints what differs.
# Usage: scripts/check-tool-pins.sh [repository root]   (default: this script's repository)
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"

fail=0
same() { # <what> <value> <value> ...
  local what="$1" first="$2" v
  shift
  for v in "$@"; do
    if [ -z "$v" ] || [ "$v" != "$first" ]; then
      echo "check-tool-pins: $what differs: $*" >&2
      fail=1
      return
    fi
  done
}
# First value of a sed expression on a file, empty when it does not match.
pick() { sed -n "$2" "$1" | head -n 1; }

lk_just=$(pick justfile 's/^livekit_version := "\(.*\)"$/\1/p')
lk_ci=$(pick .github/workflows/ci.yml 's/^ *LIVEKIT_VERSION=\(.*\)$/\1/p')
lk_docker=$(pick deploy/Dockerfile 's#^FROM livekit/livekit-server:v\([^@ ]*\)@.*#\1#p')
same "LiveKit version (justfile, ci.yml, deploy/Dockerfile)" "$lk_just" "$lk_ci" "$lk_docker"
same "LiveKit amd64 SHA-256 (justfile, ci.yml)" \
  "$(pick justfile 's/^ *x86_64) arch=amd64 sum=\([0-9a-f]*\) ;;$/\1/p')" \
  "$(pick .github/workflows/ci.yml 's/^ *LIVEKIT_SHA256=\(.*\)$/\1/p')"

ff_docker=$(pick deploy/Dockerfile 's/^ARG FFMPEG_VERSION=\(.*\)$/\1/p')
ff_just_file=$(pick justfile 's/^ *x86_64) file=\(ffmpeg-[^ ]*\) sum=.*/\1/p')
ff_ci_file=$(pick .github/workflows/ci.yml 's/^ *FFMPEG_ASSET=\(.*\)$/\1/p')
release_of() { sed -n 's/^ffmpeg-n\([0-9][0-9.]*\)-.*/\1/p' <<< "$1"; }
same "FFmpeg release (deploy/Dockerfile, justfile, ci.yml)" "$ff_docker" "$(release_of "$ff_just_file")" "$(release_of "$ff_ci_file")"
same "FFmpeg test build (justfile, ci.yml)" "$ff_just_file" "$ff_ci_file"
same "FFmpeg build date (justfile, ci.yml)" \
  "$(pick justfile 's/^ *release=\(autobuild-[0-9-]*\)$/\1/p')" \
  "$(pick .github/workflows/ci.yml 's/^ *FFMPEG_RELEASE=\(.*\)$/\1/p')"
same "FFmpeg test build SHA-256 (justfile, ci.yml)" \
  "$(pick justfile 's/^ *x86_64) file=ffmpeg-[^ ]* sum=\([0-9a-f]*\) ;;$/\1/p')" \
  "$(pick .github/workflows/ci.yml 's/^ *FFMPEG_SHA256=\(.*\)$/\1/p')"

[ "$fail" = 0 ] || exit 1
echo "tool pins agree: LiveKit $lk_just, FFmpeg $ff_docker"
