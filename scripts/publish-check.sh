#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Pre-publication check (docs/GITHUB.md). Run it before every push and in the CI:
#   scripts/publish-check.sh [directory]          (default: the current directory)
# It fails when the tree contains anything private: planning notes, agent or memory files, local data, test
# output, environment or key files, secrets, or private domains and addresses.
#
# Private domains and addresses are not written into this script (it is public itself). They come from
#   - PUBLISH_CHECK_PRIVATE (comma-separated literal strings; in the CI the secret of the same name),
#   - the file .publish-check.private in the checked directory, in its parent directory or next to this
#     script's repository (one string per line, gitignored, never committed).
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
    *.pem | *.key | *.p12 | *.pfx | *id_rsa* | *id_ed25519* | *.keystore) report "key file: $f" ;;
    *.db | *.sqlite | *.sqlite3 | *.db-wal | *.db-shm) report "database file: $f" ;;
    .publish-check.private) report "private pattern list must stay untracked: $f" ;;
  esac
done

# 2. Private domains and addresses: the configured private patterns are refused everywhere, the deploy examples included
#    (the default reference node tavrn.org is the project's public domain, not a private name).
patterns=()
IFS=',' read -r -a env_patterns <<< "${PUBLISH_CHECK_PRIVATE:-}"
for p in "${env_patterns[@]}"; do [ -n "${p// /}" ] && patterns+=("${p// /}"); done
for list in ./.publish-check.private ../.publish-check.private "$here/.publish-check.private"; do
  [ -f "$list" ] || continue
  while IFS= read -r p; do [ -n "$p" ] && [[ "$p" != \#* ]] && patterns+=("$p"); done < "$list"
done
[ "${#patterns[@]}" -gt 0 ] && mapfile -t patterns < <(printf '%s\n' "${patterns[@]}" | sort -u)
if [ "${#patterns[@]}" -eq 0 ]; then
  report "no private domains or addresses configured (PUBLISH_CHECK_PRIVATE or .publish-check.private)"
else
  for f in "${files[@]}"; do
    case "$f" in
      */node_modules/* | *.lock | pnpm-lock.yaml) continue ;;
    esac
    [ -f "$f" ] || continue
    for p in "${patterns[@]}"; do
      if grep -qIF -- "$p" "$f"; then
        # File and line only: the CI log of a public repository must not repeat the private string.
        report "private domain/address in $f:$(grep -nIF -- "$p" "$f" | head -n 1 | cut -d: -f1)"
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
  [ -n "$hit" ] && report "possible secret in $f:${hit%%:*}"
done

# 4. gitleaks, if installed: only what would be published (the files above, not ignored build or test output such as
#    build output or local data), plus the git history.
if command -v gitleaks >/dev/null 2>&1; then
  tree="$(mktemp -d)"
  trap 'rm -rf "$tree"' EXIT
  for f in "${files[@]}"; do [ -f "$f" ] && printf '%s\0' "$f"; done | tar --null -T - -cf - | tar -xf - -C "$tree"
  if gitleaks dir --help >/dev/null 2>&1; then
    (cd "$tree" && gitleaks dir --no-banner --redact . >/dev/null 2>&1) ||
      report "gitleaks found secrets in the files to publish: $(cd "$tree" && gitleaks dir --no-banner --redact -v . 2>/dev/null | sed -n 's/^File: *//p' | sort -u | tr '\n' ' ')"
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      gitleaks git --no-banner --redact . >/dev/null 2>&1 || report "gitleaks found secrets in the git history (run: gitleaks git --redact -v .)"
    fi
  else
    (cd "$tree" && gitleaks detect --no-git --no-banner --redact --source . >/dev/null 2>&1) ||
      report "gitleaks found secrets in the files to publish: $(cd "$tree" && gitleaks detect --no-git --no-banner --redact -v --source . 2>/dev/null | sed -n 's/^File: *//p' | sort -u | tr '\n' ' ')"
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      gitleaks detect --no-banner --redact --source . >/dev/null 2>&1 || report "gitleaks found secrets in the git history (run: gitleaks detect --redact -v)"
    fi
  fi
else
  echo "publish-check: gitleaks not installed, only the built-in secret patterns were checked" >&2
fi

if [ "$problems" -gt 0 ]; then
  echo "publish-check: $problems problem(s); nothing may be published until they are fixed" >&2
  exit 1
fi
echo "publish-check: ok (${#files[@]} files)"
