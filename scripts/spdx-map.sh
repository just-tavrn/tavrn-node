# SPDX-License-Identifier: AGPL-3.0-only
#
# The license map of scripts/check-spdx.sh (sourced by it): the files it checks and the license of each path, first
# match wins. Keep it in sync with LICENSE: everything is AGPL-3.0-only; the embedded web bundle and the
# protocol submodule are not checked.
# shellcheck shell=bash disable=SC2034 # spdx_files is read by check-spdx.sh

spdx_files=('*.rs' '*.ts' '*.tsx' '*.mjs' '*.js' '*.sh')

license_for() {
  case "$1" in
    web/dist/* | */node_modules/* | node_modules/* | target/* | protocol/*) echo skip ;;
    src/* | tests/* | perf/* | deploy/* | scripts/*) echo AGPL-3.0-only ;;
    *) echo unmapped ;;
  esac
}
