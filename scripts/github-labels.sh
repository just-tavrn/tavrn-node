#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared script of the tavrn repositories, version 1. The source is scripts/github-labels.sh of just-tavrn/.github;
# every repository carries an identical copy (apart from the SPDX line above), and its own labels live in
# scripts/labels.txt next to it. Change the source first, then run its scripts/sync-shared.sh (docs/GITHUB.md
# "Shared scripts"); the CI job "Shared scripts in sync" fails while a copy differs.
#
# Creates (or updates) the issue and pull-request labels of a repository: the common set below (the issue forms use
# bug, enhancement, documentation, question and needs-triage; Dependabot dependencies and github-actions), then the
# lines of scripts/labels.txt (`name|colour|description`; `#` starts a comment; a common name there overrides it).
# Usage: scripts/github-labels.sh [owner/repo ...]   (default: the repository of this checkout, as `gh` resolves it)
# Needs the GitHub CLI (`gh`) authenticated with write access to the repositories. Safe to run again: existing labels
# get the colour and description of the list.
set -euo pipefail
cd "$(dirname "$0")/.."

repos=("$@")
[ ${#repos[@]} -eq 0 ] && repos=("$(gh repo view --json nameWithOwner --jq .nameWithOwner)")

labels=(
  "bug|d73a4a|Something does not work as described"
  "enhancement|a2eeef|New feature or improvement"
  "documentation|0075ca|Documentation only"
  "question|d876e3|Further information is requested"
  "security|b60205|Security relevant (report vulnerabilities privately, see SECURITY.md)"
  "good first issue|7057ff|A good place to start contributing"
  "help wanted|008672|Maintainers would welcome a contribution"
  "duplicate|cfd3d7|This issue or pull request already exists"
  "invalid|e4e669|This does not seem right"
  "wontfix|ffffff|This will not be worked on"
  "needs-triage|fbca04|Not yet looked at by a maintainer"
  "dependencies|0366d6|Dependency updates"
  "github-actions|000000|Updates of the GitHub Actions workflows"
)
if [ -f scripts/labels.txt ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]] && continue
    labels+=("$line")
  done < scripts/labels.txt
fi

for repo in "${repos[@]}"; do
  for entry in "${labels[@]}"; do
    IFS='|' read -r name color description <<< "$entry"
    gh label create "$name" --repo "$repo" --color "$color" --description "$description" --force
  done
  echo "labels of $repo up to date"
done
