#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared script of the tavrn repositories, version 1. The source is scripts/publish-check.sh of just-tavrn/.github;
# every repository carries an identical copy (apart from the SPDX line above). A repository that needs more (the
# website: the default node host of its deployment) adds it in scripts/publish-check-extra.sh next to this script.
# Change the source first, then run its scripts/sync-shared.sh (docs/GITHUB.md "Shared scripts"); the CI job
# "Shared scripts in sync" fails while a copy differs.
#
# Pre-publication check (docs/GITHUB.md). Run it before every push and in the CI:
#   scripts/publish-check.sh [directory]          (default: the current directory)
# It fails when the tree contains anything private: planning notes, agent or memory files, local data, test
# output, environment or key files, secrets, or private domains and addresses.
#
# Private domains and addresses are not written into this script (it is public itself). They come from
#   - PUBLISH_CHECK_PRIVATE (comma-separated literal strings, surrounding spaces trimmed; in the CI the secret of the
#     same name),
#   - the file .publish-check.private in the checked directory, in its parent directory or in the root of this
#     script's repository (one string per line, gitignored, never committed),
#   - scripts/publish-check-extra.sh, when the repository has one (sourced after the lists above are known): it may
#     add pattern lists (extra_lists), patterns (extra_patterns), and one literal string (allow_value) that the files
#     in allow_files may contain; that string is removed from those files before they are searched, so every other
#     private string is still found there.
# Without any pattern the check fails, unless PUBLISH_CHECK_ALLOW_UNCONFIGURED=1: then only the private-pattern
# step is skipped, with a warning, and every other step still runs and still fails. The CI sets it for Dependabot's
# pull requests alone (they see only Dependabot secrets); the push to main runs the full check with the patterns.
# A finding names the file and the line, never the matching text (CI logs of public repositories are public).
#
# No `set -e`: the script collects every finding and fails at the end (grep's "no match" is not an error here).
set -uo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-.}"
cd "$dir" || exit 2
problems=0
report() { echo "publish-check: $*" >&2; problems=$((problems + 1)); }
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

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

# The files the content checks read: no dependencies, no lockfiles (hashes and registry URLs only), no deleted files.
content=()
for f in "${files[@]}"; do
  case "$f" in */node_modules/* | node_modules/* | *.lock | pnpm-lock.yaml | package-lock.json) continue ;; esac
  [ -f "$f" ] && content+=("$f")
done

# 2. Private domains and addresses.
patterns=()
extra_lists=()
extra_patterns=()
allow_value=""
allow_files=()
if [ -f "$here/scripts/publish-check-extra.sh" ]; then
  # shellcheck source=/dev/null
  . "$here/scripts/publish-check-extra.sh"
fi
IFS=',' read -r -a env_patterns <<< "${PUBLISH_CHECK_PRIVATE:-}"
for p in "${env_patterns[@]}"; do p="$(trim "$p")"; [ -n "$p" ] && patterns+=("$p"); done
for list in ./.publish-check.private ../.publish-check.private "$here/.publish-check.private" "${extra_lists[@]}"; do
  [ -f "$list" ] || continue
  while IFS= read -r p || [ -n "$p" ]; do
    p="$(trim "$p")"
    [ -n "$p" ] && [[ "$p" != \#* ]] && patterns+=("$p")
  done < "$list"
done
for p in "${extra_patterns[@]}"; do [ -n "$p" ] && patterns+=("$p"); done
[ "${#patterns[@]}" -gt 0 ] && mapfile -t patterns < <(printf '%s\n' "${patterns[@]}" | sort -u)
if [ "${#patterns[@]}" -eq 0 ] && [ "${PUBLISH_CHECK_ALLOW_UNCONFIGURED:-}" = "1" ]; then
  echo "publish-check: warning: private-pattern check skipped: no patterns configured and PUBLISH_CHECK_ALLOW_UNCONFIGURED=1 (the push to main runs it with the patterns)" >&2
elif [ "${#patterns[@]}" -eq 0 ]; then
  report "no private domains or addresses configured (PUBLISH_CHECK_PRIVATE or .publish-check.private)"
else
  pattern_file="$(mktemp)"
  printf '%s\n' "${patterns[@]}" > "$pattern_file"
  plain=()
  allowed=()
  for f in "${content[@]}"; do
    is_allowed=0
    if [ -n "$allow_value" ]; then
      for a in "${allow_files[@]}"; do [ "$f" = "$a" ] && is_allowed=1 && break; done
    fi
    if [ "$is_allowed" = 1 ]; then allowed+=("$f"); else plain+=("$f"); fi
  done
  # One grep over all files lists those with a hit (-l, never the text); the line number is looked up for those only.
  # File and line only: the CI log of a public repository must not repeat the private string.
  if [ "${#plain[@]}" -gt 0 ]; then
    while IFS= read -r -d '' f; do
      report "private domain/address in $f:$(grep -nIF -f "$pattern_file" -- "$f" | head -n 1 | cut -d: -f1)"
    done < <(printf '%s\0' "${plain[@]}" | xargs -0 grep -lIZF -f "$pattern_file" --)
  fi
  # The files that may contain allow_value: every occurrence of it (a literal string, never a regular expression)
  # is cut out of each line before the patterns are searched.
  for f in "${allowed[@]}"; do
    grep -qI . "$f" 2>/dev/null || continue
    hit=$(ALLOW="$allow_value" PATTERNS="$pattern_file" awk '
      BEGIN { a = ENVIRON["ALLOW"]; while ((getline p < ENVIRON["PATTERNS"]) > 0) pats[++n] = p }
      {
        line = $0
        while ((i = index(line, a)) > 0) line = substr(line, 1, i - 1) substr(line, i + length(a))
        for (k = 1; k <= n; k++) if (index(line, pats[k])) { print NR; exit }
      }' "$f")
    [ -n "$hit" ] && report "private domain/address in $f:$hit"
  done
  rm -f "$pattern_file"
fi

# 3. Secret patterns (a quick net; gitleaks below is the thorough one). One grep over all files; -Z ends each file
#    name with NUL, so the name is read exactly and the matching text is dropped. Documented example credentials
#    (AWS's AKIAIOSFODNN7EXAMPLE and the like) are fine.
secret_re='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}'
if [ "${#content[@]}" -gt 0 ]; then
  declare -A secret_seen=()
  while IFS= read -r -d '' f && IFS= read -r rest; do
    [[ "$rest" == *EXAMPLE* ]] && continue
    [ -n "${secret_seen[$f]:-}" ] && continue
    secret_seen[$f]=1
    report "possible secret in $f:${rest%%:*}"
  done < <(printf '%s\0' "${content[@]}" | xargs -0 grep -HnIZE -- "$secret_re")
fi

# 4. gitleaks, if installed: only what would be published (the files above, not ignored build or test output or
#    local data), plus the git history.
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
