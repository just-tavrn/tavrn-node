#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Checks that every hand-written source file starts with the SPDX header of its directory:
# `// SPDX-License-Identifier: <id>` (Rust, TypeScript, JavaScript) or `# SPDX-License-Identifier: <id>`
# (shell) as the first line, or the second line after a shebang. The embedded web client bundle (web/dist),
# dependencies and the protocol submodule are not checked.
# Usage: scripts/check-spdx.sh [--fix]   (--fix inserts missing headers; wrong ones are only reported)
set -euo pipefail
cd "$(dirname "$0")/.."

fix=0
[ "${1:-}" = "--fix" ] && fix=1

# Expected license per path (first match wins). Everything in this repository is AGPL-3.0-only (LICENSE).
license_for() {
  case "$1" in
    web/dist/* | */node_modules/* | node_modules/* | target/* | protocol/*) echo skip ;;
    src/* | tests/* | perf/* | deploy/* | scripts/*) echo AGPL-3.0-only ;;
    *) echo unmapped ;;
  esac
}

missing=0
wrong=0
fixed=0
while IFS= read -r -d '' file; do
  [ -f "$file" ] || continue
  expected=$(license_for "$file")
  [ "$expected" = skip ] && continue
  if [ "$expected" = unmapped ]; then
    echo "no license mapped for $file (add its directory to scripts/check-spdx.sh)" >&2
    missing=$((missing + 1))
    continue
  fi
  case "$file" in
    *.sh) header="# SPDX-License-Identifier: $expected" ;;
    *) header="// SPDX-License-Identifier: $expected" ;;
  esac
  first=$(head -n 1 "$file")
  line=1
  if [[ "$first" == '#!'* && "$first" != '#!['* ]]; then
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
    tmp=$(mktemp)
    if [ "$line" = 2 ]; then
      { head -n 1 "$file"; echo "$header"; tail -n +2 "$file"; } > "$tmp"
    else
      { echo "$header"; cat "$file"; } > "$tmp"
    fi
    cat "$tmp" > "$file" && rm -f "$tmp"
    fixed=$((fixed + 1))
  else
    echo "$file: missing '$header'" >&2
    missing=$((missing + 1))
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- '*.rs' '*.ts' '*.tsx' '*.mjs' '*.js' '*.sh')

[ "$fixed" -gt 0 ] && echo "inserted $fixed SPDX headers"
if [ "$missing" -gt 0 ] || [ "$wrong" -gt 0 ]; then
  echo "SPDX check failed: $missing missing, $wrong wrong (run scripts/check-spdx.sh --fix for missing headers)" >&2
  exit 1
fi
echo "SPDX headers ok"
