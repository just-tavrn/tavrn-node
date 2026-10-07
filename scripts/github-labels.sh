#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Creates (or updates) the issue labels of this repository. Needs the GitHub CLI, authenticated with
# write access to the repository. Usage: scripts/github-labels.sh [owner/repo]
set -euo pipefail
repo="${1:-just-tavrn/tavrn-node}"

label() {
  gh label create "$1" --repo "$repo" --color "$2" --description "$3" --force
}

label bug "d73a4a" "Something does not work as described"
label enhancement "a2eeef" "New feature or improvement"
label documentation "0075ca" "Documentation only"
label security "b60205" "Security hardening (report vulnerabilities privately, not as issues)"
label "good first issue" "7057ff" "Good for newcomers"
label "help wanted" "008672" "Extra attention is wanted"
label question "d876e3" "Further information is requested"
label duplicate "cfd3d7" "This issue or pull request already exists"
label invalid "e4e669" "This does not seem right"
label wontfix "ffffff" "This will not be worked on"
label dependencies "0366d6" "Dependency updates"
label federation "1d76db" "Federation between nodes"
label voice "5319e7" "Voice, video and LiveKit"
label e2ee "0e8a16" "End-to-end encryption on the node (MLS delivery service, keys)"
label database "c5def5" "Migrations, SQLite and PostgreSQL"
label deployment "0052cc" "Container image, compose file, reverse proxy, operator documentation"
label scaling "bfdadc" "Several instances of one node (Valkey)"
label performance "f9d0c4" "Performance budgets and the load generator"
label protocol "fbca04" "Needs a change or clarification in tavrn-protocol"
label ci "ededed" "Workflows and build tooling"
label "needs-triage" "ffffff" "Not looked at yet"
