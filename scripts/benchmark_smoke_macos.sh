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
threads="${CMR_BENCH_THREADS:-}"
blocks="${CMR_BENCH_BLOCKS:-}"
found_size="${CMR_BENCH_FSIZE:-32}"
preheat_enabled="${CMR_BENCH_SMOKE_PREHEAT:-1}"

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

# shellcheck source=./build_purity_common.sh
source "$repo_root/scripts/build_purity_common.sh"

pushd "$repo_root" >/dev/null

cmd=(
  env
  CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0
  "$exe"
  -device "$device"
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst *"
  -d examples/derivations/default.txt
  -c c
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
  -fsize "$found_size"
  -silent
)

if [[ -n "$threads" && "$threads" != "0" ]]; then
  cmd+=( -t "$threads" )
fi

if [[ -n "$blocks" && "$blocks" != "0" ]]; then
  cmd+=( -b "$blocks" )
fi

if [[ "$preheat_enabled" != "0" ]]; then
  echo "[preheat] discarded smoke warmup"
  preheat_output="$("${cmd[@]}" 2>&1)"
  cmr_require_no_runtime_fallback "Apple Silicon benchmark smoke preheat" "$preheat_output"
fi

output="$("${cmd[@]}" 2>&1)"

cmr_require_no_runtime_fallback "Apple Silicon benchmark smoke" "$output"

if ! grep -Eq -- 'Recovery task done' <<<"$output"; then
  echo "Benchmark smoke did not emit the normal task summary." >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

if ! grep -Eq -- 'Recovery speed:[[:space:]]+[0-9.]+[[:space:]]+[MG] candidates/s|Recovery tested [0-9]+ candidates\.(?:[[:space:]]+Checksum-valid:[[:space:]]+[0-9]+\.)?[[:space:]]+Found:[[:space:]]+[0-9]+\.' <<<"$output"; then
  echo "Benchmark smoke did not emit a recovery speed or recovery summary line." >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

if ! grep -Eq -- 'tested=[0-9]+' <<<"$output"; then
  echo "Benchmark smoke did not emit a tested counter." >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

if ! grep -Eq -- 'Found:[[:space:]]+[0-9]+' <<<"$output"; then
  echo "Benchmark smoke did not emit a Found counter." >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

echo "[ok] Apple Silicon benchmark smoke"

popd >/dev/null
