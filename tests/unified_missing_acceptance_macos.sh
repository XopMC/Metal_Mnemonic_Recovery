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
hash_prefix_phrase="96edbea40e7d1d3ad8239cf255765a1b3dc7d995"
hash_prefix_15_phrase="074b7746152f080447582bb3881d1594bfd2d857"

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

# shellcheck source=../scripts/build_purity_common.sh
source "$repo_root/scripts/build_purity_common.sh"

run_case() {
  local name="$1"
  shift
  echo "[case] $name"
  local output
  if ! output="$(env CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 "$exe" "$@" 2>&1)"; then
    echo "$output" >&2
    echo "Case '$name' failed." >&2
    exit 1
  fi
  printf '%s\n' "$output"
}

require_pattern() {
  local name="$1"
  local output="$2"
  local pattern="$3"
  if ! grep -Eq -- "$pattern" <<<"$output"; then
    echo "Case '$name' did not match pattern '$pattern'." >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

run_prefix_case() {
  local label="$1"
  local template_path="$2"
  local target_hash="${3:-$hash_prefix_phrase}"
  local sampled_batches="${4:-0}"
  local output
  if [[ "$sampled_batches" != "0" ]]; then
    output="$(CMR_BENCH_MAX_CHECKSUM_BATCHES="$sampled_batches" run_case "$label" \
      -device "$device" \
      -recovery -i "$template_path" \
      -d examples/derivations/default.txt \
      -c c \
      -d_type 1 \
      -hash "$target_hash" \
      -silent)"
  else
    output="$(run_case "$label" \
      -device "$device" \
      -recovery -i "$template_path" \
      -d examples/derivations/default.txt \
      -c c \
      -d_type 1 \
      -hash "$target_hash" \
      -silent)"
  fi
  require_pattern "$label" "$output" 'Found:[[:space:]]+1'
  require_pattern "$label" "$output" 'Recovery task done'
  require_pattern "$label" "$output" 'tested=[0-9]+'
  cmr_require_no_runtime_fallback "$label" "$output"
  echo "[ok] $label"
}

pushd "$repo_root" >/dev/null

run_prefix_case "unified missing 1" "examples/validation/templates-prefix-1missing.txt"
run_prefix_case "unified missing 3" "examples/validation/templates-prefix-3missing.txt" "$hash_prefix_phrase" 1
run_prefix_case "unified missing 5" "examples/validation/templates-prefix-5missing.txt" "$hash_prefix_phrase" 1
run_prefix_case "unified missing 6" "examples/validation/templates-prefix-6missing.txt" "$hash_prefix_phrase" 1
run_prefix_case "unified missing 8" "examples/validation/templates-prefix-8missing.txt" "$hash_prefix_phrase" 1
run_prefix_case "unified missing 12" "examples/validation/templates-prefix-12missing.txt" "$hash_prefix_15_phrase" 1

popd >/dev/null
