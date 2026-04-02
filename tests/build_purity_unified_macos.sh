#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exe="${CMR_EXE:-}"
if [[ -z "$exe" ]]; then
  if [[ -x "$repo_root/bin/Metal_Mnemonic_Recovery" ]]; then
    exe="$repo_root/bin/Metal_Mnemonic_Recovery"
  else
    exe="$repo_root/out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery"
  fi
fi

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

export CMR_BUILD_PURITY_UNIFIED=1

# shellcheck source=../scripts/build_purity_common.sh
source "$repo_root/scripts/build_purity_common.sh"

pushd "$repo_root" >/dev/null
cmr_scan_build_purity "$repo_root" "$exe"
popd >/dev/null
