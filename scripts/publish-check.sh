#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Pre-publication check (docs/GITHUB.md). Run it before every push and in the CI:
#   scripts/publish-check.sh [directory]          (default: the current directory)
# It fails when the tree contains anything private: planning notes, agent or memory files, local data, test
# output, environment or key files, secrets, or private domains and addresses outside the two deploy examples.
#
# Private domains and addresses are not written into this script (it is public itself). They come from
#   - PUBLISH_CHECK_PRIVATE (comma-separated literal strings; in the CI the secret of the same name),
#   - the file .publish-check.private in the checked directory, in its parent directory or next to this
#     script's repository (one string per line, gitignored, never committed),
#   - the example reference node in deploy/.env.example (TAVRN_REFERENCE_NODES) and its parent domain.
set -uo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-.}"
cd "$dir" || exit 2
problems=0
report() { echo "publish-check: $*" >&2; problems=$((problems + 1)); }

# Every file that would be published: tracked plus untracked-but-not-ignored in a git checkout, else all.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -d '' files < <(git ls-files -z --cached --others --exclude-standard)
else
  mapfile -d '' files < <(find . -type f -not -path './.git/*' -not -path '*/node_modules/*' -not -path './target/*' -printf '%P\0')
fi

# 1. Paths that never belong in a public repository.
for f in "${files[@]}"; do
  case "$f" in
    .claude/* | */.claude/*) report "agent files: $f" ;;
    docs/PLAN.md | */PLAN.md) report "planning notes: $f" ;;
    MEMORY.md | */MEMORY.md | memory/* | */memory/*) report "memory file: $f" ;;
    data-dev/* | */data-dev/* | data/* | pgdata/*) report "local data: $f" ;;
    test-results/* | */test-results/* | playwright-report/* | */playwright-report/* | perf/results/*) report "test output: $f" ;;
    .env | */.env | .env.* | */.env.*)
      case "$f" in *.env.example) ;; *) report "environment file: $f" ;; esac ;;
    *.pem | *.key | *.p12 | *.pfx | *id_rsa* | *id_ed25519* | *.keystore | node.key | */node.key) report "key file: $f" ;;
    *.db | *.sqlite | *.sqlite3 | *.db-wal | *.db-shm) report "database file: $f" ;;
    .publish-check.private) report "private pattern list must stay untracked: $f" ;;
  esac
done

# 2. Private domains and addresses (allowed only as the example default in the two deploy files).
patterns=()
IFS=',' read -r -a env_patterns <<< "${PUBLISH_CHECK_PRIVATE:-}"
for p in "${env_patterns[@]}"; do [ -n "${p// /}" ] && patterns+=("${p// /}"); done
for list in ./.publish-check.private ../.publish-check.private "$here/.publish-check.private"; do
  [ -f "$list" ] || continue
  while IFS= read -r p; do [ -n "$p" ] && [[ "$p" != \#* ]] && patterns+=("$p"); done < "$list"
done
for example in deploy/.env.example "$here/deploy/.env.example"; do
  [ -f "$example" ] || continue
  ref=$(sed -n 's/^TAVRN_REFERENCE_NODES=\([^ #]*\).*/\1/p' "$example" | head -n 1)
  for d in ${ref//,/ }; do
    patterns+=("$d")
    parent="${d#*.}"
    [[ "$parent" == *.* ]] && patterns+=("$parent")
  done
done
[ "${#patterns[@]}" -gt 0 ] && mapfile -t patterns < <(printf '%s\n' "${patterns[@]}" | sort -u)
if [ "${#patterns[@]}" -eq 0 ]; then
  report "no private domains or addresses configured (PUBLISH_CHECK_PRIVATE or .publish-check.private)"
else
  for f in "${files[@]}"; do
    case "$f" in
      deploy/docker-compose.yml | deploy/.env.example | */node_modules/* | *.lock | pnpm-lock.yaml) continue ;;
    esac
    [ -f "$f" ] || continue
    for p in "${patterns[@]}"; do
      if grep -qIF -- "$p" "$f"; then
        report "private domain/address in $f: $(grep -nIF -- "$p" "$f" | head -n 1 | cut -c1-120)"
      fi
    done
  done
fi

# 3. Secret patterns (a quick net; gitleaks below is the thorough one).
secret_re='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}'
for f in "${files[@]}"; do
  case "$f" in */node_modules/* | *.lock | pnpm-lock.yaml) continue ;; esac
  [ -f "$f" ] || continue
  # Documented example credentials (AWS's AKIAIOSFODNN7EXAMPLE and the like) are fine.
  hit=$(grep -nIE -- "$secret_re" "$f" | grep -v 'EXAMPLE' | head -n 1)
  [ -n "$hit" ] && report "possible secret in $f: $(cut -c1-80 <<< "$hit")"
done

# 4. gitleaks, if installed.
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks dir --help >/dev/null 2>&1; then
    gitleaks dir --no-banner --redact . >/dev/null 2>&1 || report "gitleaks found secrets (run: gitleaks dir --redact .)"
  else
    gitleaks detect --no-git --no-banner --redact --source . >/dev/null 2>&1 || report "gitleaks found secrets (run: gitleaks detect --no-git --redact)"
  fi
else
  echo "publish-check: gitleaks not installed, only the built-in secret patterns were checked" >&2
fi

if [ "$problems" -gt 0 ]; then
  echo "publish-check: $problems problem(s); nothing may be published until they are fixed" >&2
  exit 1
fi
echo "publish-check: ok (${#files[@]} files)"
