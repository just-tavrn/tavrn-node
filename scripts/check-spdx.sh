#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared script of the tavrn repositories, version 1. The source is scripts/check-spdx.sh of just-tavrn/.github;
# every repository carries an identical copy (apart from the SPDX line above), and what differs per repository lives
# in scripts/spdx-map.sh next to it. Change the source first, then run its scripts/sync-shared.sh (docs/GITHUB.md
# "Shared scripts"); the CI job "Shared scripts in sync" fails while a copy differs.
#
# Checks that every hand-written source file carries the SPDX header of its path. The map in scripts/spdx-map.sh
# (kept in sync with LICENSE.md) defines `spdx_files`, the git pathspecs to check (empty: every file), and
# `license_for <path>`, which prints the license id of a path, `skip` or `unmapped`. The header is a comment in the
# syntax of the file:
#   # SPDX-License-Identifier: <id>        shell, YAML, Dockerfiles, Python, TOML, configuration files
#   /* SPDX-License-Identifier: <id> */    CSS
#   // SPDX-License-Identifier: <id>       everything else (Rust, TypeScript, JavaScript, Kotlin)
# on the first line, or on the second after a shebang (a Rust inner attribute `#![` is no shebang), a Dockerfile
# `# syntax=` directive, `#cloud-config`, or the `---` that opens the frontmatter of an Astro file.
# Usage: scripts/check-spdx.sh [--fix]   (--fix inserts missing headers; wrong ones are only reported)
set -euo pipefail
cd "$(dirname "$0")/.."
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "check-spdx: not a git checkout" >&2; exit 2; }

fix=0
[ "${1:-}" = "--fix" ] && fix=1

spdx_files=()
license_for() { echo unmapped; }
# shellcheck source=/dev/null
. scripts/spdx-map.sh

header_for() {
  case "$1" in
    *.sh | *.bash | *.yml | *.yaml | *.toml | *.py | *.conf | Dockerfile | */Dockerfile | *.dockerfile)
      echo "# SPDX-License-Identifier: $2" ;;
    *.css) echo "/* SPDX-License-Identifier: $2 */" ;;
    *) echo "// SPDX-License-Identifier: $2" ;;
  esac
}

# Rewrites $1 with $2 inserted before line $3 (1 or 2).
insert_line() {
  local tmp
  tmp=$(mktemp)
  if [ "$3" = 2 ]; then
    { head -n 1 "$1"; printf '%s\n' "$2"; tail -n +2 "$1"; } > "$tmp"
  else
    { printf '%s\n' "$2"; cat "$1"; } > "$tmp"
  fi
  cat "$tmp" > "$1" && rm -f "$tmp"
}

missing=0
wrong=0
fixed=0
while IFS= read -r -d '' file; do
  [ -f "$file" ] || continue
  expected=$(license_for "$file")
  [ "$expected" = skip ] && continue
  if [ "$expected" = unmapped ]; then
    echo "no license mapped for $file (add its directory to scripts/spdx-map.sh and LICENSE.md)" >&2
    missing=$((missing + 1))
    continue
  fi
  header=$(header_for "$file" "$expected")
  first=$(head -n 1 "$file")
  line=1
  if [[ "$file" == *.astro ]]; then
    if [ "$first" != "---" ]; then
      if [ "$fix" = 1 ]; then
        insert_line "$file" $'---\n'"$header"$'\n---\n' 1
        fixed=$((fixed + 1))
      else
        echo "$file: missing frontmatter with '$header'" >&2
        missing=$((missing + 1))
      fi
      continue
    fi
    line=2
  elif [[ ( "$first" == '#!'* && "$first" != '#!['* ) || "$first" == '# syntax='* || "$first" == '#cloud-config' ]]; then
    line=2
  fi
  actual=$(sed -n "${line}p" "$file")
  [ "$actual" = "$header" ] && continue
  if [[ "$actual" == *'SPDX-License-Identifier:'* ]]; then
    echo "$file: wrong license header '$actual' (expected '$header')" >&2
    wrong=$((wrong + 1))
    continue
  fi
  if [ "$fix" = 1 ]; then
    insert_line "$file" "$header" "$line"
    fixed=$((fixed + 1))
  else
    echo "$file: missing '$header'" >&2
    missing=$((missing + 1))
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- "${spdx_files[@]}")

[ "$fixed" -gt 0 ] && echo "inserted $fixed SPDX headers"
if [ "$missing" -gt 0 ] || [ "$wrong" -gt 0 ]; then
  echo "SPDX check failed: $missing missing, $wrong wrong (run scripts/check-spdx.sh --fix for missing headers)" >&2
  exit 1
fi
echo "SPDX headers ok"
