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
device="${CMR_DEVICE:-0}"
skip_d4="${CMR_SKIP_D4:-${CMR_SKIP_EXPERIMENTAL:-0}}"

# shellcheck source=./build_purity_common.sh
source "$repo_root/scripts/build_purity_common.sh"

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

pushd "$repo_root" >/dev/null

echo "[case] invalid device handling"
invalid_output="$(env CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 "$exe" -device 99 -recovery "adapt access alert human kiwi rough pottery level soon funny burst *" -d examples/derivations/default.txt -c c -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 -silent 2>&1)"
if ! grep -Eq -- 'Warning: device 99 is out of range' <<<"$invalid_output"; then
  echo "Invalid device warning was not emitted." >&2
  printf '%s\n' "$invalid_output" >&2
  exit 1
fi
cmr_require_no_runtime_fallback "invalid device handling" "$invalid_output"
if ! grep -Eq -- 'Recovery task done' <<<"$invalid_output"; then
  echo "Invalid device handling did not emit the normal task summary." >&2
  printf '%s\n' "$invalid_output" >&2
  exit 1
fi
if ! grep -Eq -- 'Found:[[:space:]]+[0-9]+' <<<"$invalid_output"; then
  echo "Invalid device handling did not emit a Found counter." >&2
  printf '%s\n' "$invalid_output" >&2
  exit 1
fi
echo "[ok] invalid device handling"

CMR_EXE="$exe" CMR_DEVICE="$device" CMR_SKIP_D4="$skip_d4" CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 bash "$repo_root/scripts/validate_release.sh"
CMR_EXE="$exe" CMR_DEVICE="$device" CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 bash "$repo_root/tests/no_fallback_macos.sh"
CMR_EXE="$exe" CMR_DEVICE="$device" CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 bash "$repo_root/tests/unified_missing_acceptance_macos.sh"
CMR_EXE="$exe" CMR_DEVICE="$device" CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 bash "$repo_root/scripts/benchmark_smoke_macos.sh"
CMR_EXE="$exe" CMR_BUILD_PURITY_MODE="${CMR_BUILD_PURITY_MODE:-hybrid}" CMR_BUILD_PURITY_STRICT="${CMR_BUILD_PURITY_STRICT:-0}" bash "$repo_root/tests/build_purity_macos.sh"

echo "[case] valid device handling"
valid_output="$(env CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 "$exe" -device "$device" -recovery "adapt access alert human kiwi rough pottery level soon funny burst *" -d examples/derivations/default.txt -c c -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 -silent 2>&1)"
if ! grep -Eq -- 'Active Metal devices:[[:space:]]+0' <<<"$valid_output"; then
  echo "Valid device selection was not reflected in output." >&2
  printf '%s\n' "$valid_output" >&2
  exit 1
fi
cmr_require_no_runtime_fallback "valid device handling" "$valid_output"
if ! grep -Eq -- 'Recovery task done' <<<"$valid_output"; then
  echo "Valid device handling did not emit the normal task summary." >&2
  printf '%s\n' "$valid_output" >&2
  exit 1
fi
if ! grep -Eq -- 'Found:[[:space:]]+[0-9]+' <<<"$valid_output"; then
  echo "Valid device handling did not emit a Found counter." >&2
  printf '%s\n' "$valid_output" >&2
  exit 1
fi
echo "[ok] valid device handling"

popd >/dev/null
