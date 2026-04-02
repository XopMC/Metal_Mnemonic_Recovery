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
skip_multi_missing="${CMR_NO_FALLBACK_SKIP_MULTIMISSING:-0}"

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

# shellcheck source=../scripts/build_purity_common.sh
source "$repo_root/scripts/build_purity_common.sh"

solana_bloom="${TMPDIR:-/tmp}/cmr-solana-no-fallback.blf"
solana_xor="${TMPDIR:-/tmp}/cmr-solana-no-fallback.xor_u"
cleanup() {
  rm -f "$solana_bloom"
  rm -f "$solana_xor"
}
trap cleanup EXIT

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

require_literal() {
  local name="$1"
  local output="$2"
  local text="$3"
  if ! grep -Fq -- "$text" <<<"$output"; then
    echo "Case '$name' did not contain expected text." >&2
    printf '%s\n' "$text" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

pushd "$repo_root" >/dev/null

d4_output="$(run_case "d_type 4 exact fixture" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c c \
  -d_type 4 \
  -hash 4fd01a8da7097495668c9ee9499084bc5680199a)"
require_pattern "d_type 4 exact fixture" "$d4_output" '\(ed25519-bip32-test\)'
require_pattern "d_type 4 exact fixture" "$d4_output" 'Found:[[:space:]]+1'
require_pattern "d_type 4 exact fixture" "$d4_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 4 exact fixture" "$d4_output"
echo "[ok] d_type 4 exact fixture"

d2_output="$(run_case "d_type 2 solana no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -hash 89dfcdfe8986448bf0ca1f5bc1720de5ad66104c \
  -silent)"
require_pattern "d_type 2 solana no fallback" "$d2_output" 'Found:[[:space:]]+1'
require_pattern "d_type 2 solana no fallback" "$d2_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 solana no fallback" "$d2_output"
echo "[ok] d_type 2 solana no fallback"

d1_solana_output="$(run_case "d_type 1 solana no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 1 \
  -hash 553ff1f4f34d1c013fd885073a0b6b82f02bb3d0)"
require_pattern "d_type 1 solana no fallback" "$d1_solana_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 solana no fallback" "$d1_solana_output" '\(bip32-secp256k1\)'
require_pattern "d_type 1 solana no fallback" "$d1_solana_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 solana no fallback" "$d1_solana_output"
echo "[ok] d_type 1 solana no fallback"

d3_mixed_output="$(run_case "d_type 3 mixed solana no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 3 \
  -hash 553ff1f4f34d1c013fd885073a0b6b82f02bb3d0)"
require_pattern "d_type 3 mixed solana no fallback" "$d3_mixed_output" 'Found:[[:space:]]+1'
require_pattern "d_type 3 mixed solana no fallback" "$d3_mixed_output" '\(bip32-secp256k1\)'
require_pattern "d_type 3 mixed solana no fallback" "$d3_mixed_output" 'Recovery task done'
require_literal "d_type 3 mixed solana no fallback" "$d3_mixed_output" "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:(bip32-secp256k1) m/44'/501'/0'/0':75ef5cae4949cf9cc85048e58d329ba291a846b688eb272a127e0fe8fea2af7b:SOLANA:553ff1f4f34d1c013fd885073a0b6b82f02bb3d0f7b5e7750c552e369e56a35d"
cmr_require_no_runtime_fallback "d_type 3 mixed solana no fallback" "$d3_mixed_output"
echo "[ok] d_type 3 mixed solana no fallback"

d3_mixed_full_output="$(run_case "d_type 3 mixed full no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c cS \
  -d_type 3 \
  -full)"
require_pattern "d_type 3 mixed full no fallback" "$d3_mixed_full_output" 'Found:[[:space:]]+4'
require_pattern "d_type 3 mixed full no fallback" "$d3_mixed_full_output" 'Recovery task done'
require_literal "d_type 3 mixed full no fallback" "$d3_mixed_full_output" "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:m/44'/501'/0'/0':75ef5cae4949cf9cc85048e58d329ba291a846b688eb272a127e0fe8fea2af7b:COMPRESSED:c6ae7c084b16e89415cd92160f8eb89d71e46872"
require_literal "d_type 3 mixed full no fallback" "$d3_mixed_full_output" "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:(slip0010-ed25519) m/44'/501'/0'/0':2af60a958e4a68310136587f469b488e720574c50cd1eeac4e9723ca23380bce:COMPRESSED:a7eafc9781c0376c46ec7baa26d86fa6e1c2f54a"
require_literal "d_type 3 mixed full no fallback" "$d3_mixed_full_output" "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:(bip32-secp256k1) m/44'/501'/0'/0':75ef5cae4949cf9cc85048e58d329ba291a846b688eb272a127e0fe8fea2af7b:SOLANA:553ff1f4f34d1c013fd885073a0b6b82f02bb3d0f7b5e7750c552e369e56a35d"
require_literal "d_type 3 mixed full no fallback" "$d3_mixed_full_output" "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:m/44'/501'/0'/0':2af60a958e4a68310136587f469b488e720574c50cd1eeac4e9723ca23380bce:SOLANA:89dfcdfe8986448bf0ca1f5bc1720de5ad66104c672238ff3b8064c4c6659f63"
cmr_require_no_runtime_fallback "d_type 3 mixed full no fallback" "$d3_mixed_full_output"
echo "[ok] d_type 3 mixed full no fallback"

d2_full_output="$(run_case "d_type 2 solana full no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -full \
  -silent)"
require_pattern "d_type 2 solana full no fallback" "$d2_full_output" 'Found:[[:space:]]+1'
require_pattern "d_type 2 solana full no fallback" "$d2_full_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 solana full no fallback" "$d2_full_output"
echo "[ok] d_type 2 solana full no fallback"

secp_exact_output="$(run_case "d_type 1 secp exact no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c c \
  -d_type 1 \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
  -silent)"
require_pattern "d_type 1 secp exact no fallback" "$secp_exact_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp exact no fallback" "$secp_exact_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp exact no fallback" "$secp_exact_output"
echo "[ok] d_type 1 secp exact no fallback"

secp_uncompressed_output="$(run_case "d_type 1 secp uncompressed no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c u \
  -d_type 1 \
  -hash 45be8f10bff228e0de5c068731a7d00ff4914e24 \
  -silent)"
require_pattern "d_type 1 secp uncompressed no fallback" "$secp_uncompressed_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp uncompressed no fallback" "$secp_uncompressed_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp uncompressed no fallback" "$secp_uncompressed_output"
echo "[ok] d_type 1 secp uncompressed no fallback"

secp_segwit_output="$(run_case "d_type 1 secp segwit no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c s \
  -d_type 1 \
  -hash eb8ee680d5353afac9d542b8a3fb701481689a3c \
  -silent)"
require_pattern "d_type 1 secp segwit no fallback" "$secp_segwit_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp segwit no fallback" "$secp_segwit_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp segwit no fallback" "$secp_segwit_output"
echo "[ok] d_type 1 secp segwit no fallback"

secp_taproot_output="$(run_case "d_type 1 secp taproot no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c r \
  -d_type 1 \
  -full \
  -fsize 1 \
  -silent)"
require_pattern "d_type 1 secp taproot no fallback" "$secp_taproot_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp taproot no fallback" "$secp_taproot_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp taproot no fallback" "$secp_taproot_output"
echo "[ok] d_type 1 secp taproot no fallback"

secp_taproot_exact_output="$(run_case "d_type 1 secp taproot exact output no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c r \
  -d_type 1 \
  -full \
  -fsize 1)"
require_pattern "d_type 1 secp taproot exact output no fallback" "$secp_taproot_exact_output" 'TAPROOT:c41cd4f04ea29397823eb787633dc7a6fc8b50fb85d62029817ec80b15e23e82'
require_pattern "d_type 1 secp taproot exact output no fallback" "$secp_taproot_exact_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp taproot exact output no fallback" "$secp_taproot_exact_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp taproot exact output no fallback" "$secp_taproot_exact_output"
echo "[ok] d_type 1 secp taproot exact output no fallback"

secp_xpoint_output="$(run_case "d_type 1 secp xpoint exact output no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c x \
  -d_type 1 \
  -full \
  -fsize 1)"
require_pattern "d_type 1 secp xpoint exact output no fallback" "$secp_xpoint_output" 'XPOINT:7f2eb986147480a8cbaa053e35bfc2e1c458af60d5d810b2e8b2b0035bf5bf4f'
require_pattern "d_type 1 secp xpoint exact output no fallback" "$secp_xpoint_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp xpoint exact output no fallback" "$secp_xpoint_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp xpoint exact output no fallback" "$secp_xpoint_output"
echo "[ok] d_type 1 secp xpoint exact output no fallback"

secp_eth_output="$(run_case "d_type 1 secp ethereum no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/derivations/default.txt \
  -c e \
  -d_type 1 \
  -hash fa810dee4c4bfc61000ce3f239582bb3a834d483 \
  -silent)"
require_pattern "d_type 1 secp ethereum no fallback" "$secp_eth_output" 'Found:[[:space:]]+1'
require_pattern "d_type 1 secp ethereum no fallback" "$secp_eth_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 1 secp ethereum no fallback" "$secp_eth_output"
echo "[ok] d_type 1 secp ethereum no fallback"

python3 "$repo_root/scripts/generate_filter_fixtures.py" \
  --digest 89dfcdfe8986448bf0ca1f5bc1720de5ad66104c \
  --bloom "$solana_bloom" \
  --xor-u "$solana_xor"

solana_bloom_output="$(run_case "d_type 2 solana bloom no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -xb "$solana_bloom" \
  -silent)"
require_pattern "d_type 2 solana bloom no fallback" "$solana_bloom_output" 'Found:[[:space:]]+1'
require_pattern "d_type 2 solana bloom no fallback" "$solana_bloom_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 solana bloom no fallback" "$solana_bloom_output"
echo "[ok] d_type 2 solana bloom no fallback"

solana_xor_output="$(run_case "d_type 2 solana xor no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -xu "$solana_xor" \
  -silent)"
require_pattern "d_type 2 solana xor no fallback" "$solana_xor_output" 'Found:[[:space:]]+1'
require_pattern "d_type 2 solana xor no fallback" "$solana_xor_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 solana xor no fallback" "$solana_xor_output"
echo "[ok] d_type 2 solana xor no fallback"

ton_short_output="$(run_case "d_type 2 ton short full no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c t \
  -d_type 2 \
  -full \
  -silent)"
require_pattern "d_type 2 ton short full no fallback" "$ton_short_output" 'Found:[[:space:]]+4'
require_pattern "d_type 2 ton short full no fallback" "$ton_short_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 ton short full no fallback" "$ton_short_output"
echo "[ok] d_type 2 ton short full no fallback"

ton_short_exact_output="$(run_case "d_type 2 ton short exact output no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c t \
  -d_type 2 \
  -full)"
require_pattern "d_type 2 ton short exact output no fallback" "$ton_short_exact_output" 'TON\(v3r1\):dab923287a62ea710c205f46362db01545714943bf5ddffcd8a783c21d8e78e9'
require_pattern "d_type 2 ton short exact output no fallback" "$ton_short_exact_output" 'TON\(v5r1\):d6193b12205abd4196e4f5c179f5185a541e578dd4b392802ffc86537509b92b'
require_pattern "d_type 2 ton short exact output no fallback" "$ton_short_exact_output" 'Found:[[:space:]]+4'
require_pattern "d_type 2 ton short exact output no fallback" "$ton_short_exact_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 ton short exact output no fallback" "$ton_short_exact_output"
echo "[ok] d_type 2 ton short exact output no fallback"

ton_all_output="$(run_case "d_type 2 ton all full no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c T \
  -d_type 2 \
  -full \
  -silent)"
require_pattern "d_type 2 ton all full no fallback" "$ton_all_output" 'Found:[[:space:]]+10'
require_pattern "d_type 2 ton all full no fallback" "$ton_all_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 ton all full no fallback" "$ton_all_output"
echo "[ok] d_type 2 ton all full no fallback"

ton_all_exact_output="$(run_case "d_type 2 ton all exact output no fallback" \
  -device "$device" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c T \
  -d_type 2 \
  -full)"
require_pattern "d_type 2 ton all exact output no fallback" "$ton_all_exact_output" 'TON\(v1r1\):0519e2f56838cfb4c8fce8256c85a496320fe9a8c0e535022e75031928e8c556'
require_pattern "d_type 2 ton all exact output no fallback" "$ton_all_exact_output" 'TON\(v4r1\):0b9fddc606dca709377394f6bb88c045bd84983cc640dddaf75668dd64097ae3'
require_pattern "d_type 2 ton all exact output no fallback" "$ton_all_exact_output" 'TON\(v5r1\):d6193b12205abd4196e4f5c179f5185a541e578dd4b392802ffc86537509b92b'
require_pattern "d_type 2 ton all exact output no fallback" "$ton_all_exact_output" 'Found:[[:space:]]+10'
require_pattern "d_type 2 ton all exact output no fallback" "$ton_all_exact_output" 'Recovery task done'
cmr_require_no_runtime_fallback "d_type 2 ton all exact output no fallback" "$ton_all_exact_output"
echo "[ok] d_type 2 ton all exact output no fallback"

if [[ "$skip_multi_missing" != "1" ]]; then
  multi_missing_output="$(run_case "multi-missing no fallback" \
    -device "$device" \
    -recovery "adapt access alert human kiwi rough pottery level soon * * divorce" \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    -silent)"
  require_pattern "multi-missing no fallback" "$multi_missing_output" 'Found:[[:space:]]+1'
  require_pattern "multi-missing no fallback" "$multi_missing_output" 'Recovery task done'
  require_pattern "multi-missing no fallback" "$multi_missing_output" 'tested=[0-9]+'
  cmr_require_no_runtime_fallback "multi-missing no fallback" "$multi_missing_output"
  echo "[ok] multi-missing no fallback"
fi

popd >/dev/null
