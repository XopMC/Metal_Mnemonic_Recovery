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
exact_fixture_found_size="${CMR_BENCH_EXACT_FSIZE:-1024}"
repeat_count="${CMR_BENCH_REPEAT:-3}"
out_dir="${CMR_BENCH_OUT_DIR:-$repo_root/out/benchmarks}"
gt5_template="${CMR_BENCH_GT5_TEMPLATE:-}"
include_long_cases="${CMR_BENCH_INCLUDE_LONG:-0}"
warmup_enabled="${CMR_BENCH_WARMUP:-1}"
case_warmup_enabled="${CMR_BENCH_CASE_WARMUP:-1}"
long_sample_batches="${CMR_BENCH_SAMPLE_BATCHES_LONG:-2}"
python_bin="${PYTHON:-python3}"

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

# shellcheck source=./build_purity_common.sh
source "$repo_root/scripts/build_purity_common.sh"

mkdir -p "$out_dir"
tsv_path="$out_dir/benchmark-matrix.tsv"
md_path="$out_dir/benchmark-matrix.md"
solana_bloom="$out_dir/solana-bench.blf"
solana_xor="$out_dir/solana-bench.xor_u"

"$python_bin" "$repo_root/scripts/generate_filter_fixtures.py" \
  --digest 89dfcdfe8986448bf0ca1f5bc1720de5ad66104c \
  --bloom "$solana_bloom" \
  --xor-u "$solana_xor"

cat > "$tsv_path" <<'EOF'
bucket	case	repeat	missing_count	coin_types	d_type	elapsed_ms	tested	checksum_valid	found	speed_cands_per_sec
EOF

dispatch_args=(-device "$device" -fsize "$found_size" -silent)
if [[ -n "$threads" && "$threads" != "0" ]]; then
  dispatch_args+=( -t "$threads" )
fi
if [[ -n "$blocks" && "$blocks" != "0" ]]; then
  dispatch_args+=( -b "$blocks" )
fi

exe_dir="$(cd "$(dirname "$exe")" && pwd)"
secp_blob_path="$exe_dir/secp-precompute-v1.bin"
if [[ ! -f "$secp_blob_path" ]]; then
  echo "Packaged secp precompute blob not found: $secp_blob_path" >&2
  exit 1
fi

home_dir="${HOME:-}"
pipeline_archive_count=0
if [[ -n "$home_dir" ]]; then
  shopt -s nullglob
  pipeline_archives=( "$home_dir"/Library/Caches/Metal_Mnemonic_Recovery/metal-pipelines-v2-*.binarchive )
  shopt -u nullglob
  pipeline_archive_count="${#pipeline_archives[@]}"
fi

need_warmup=0
if [[ "$warmup_enabled" == "1" ]]; then
  if [[ "$pipeline_archive_count" -eq 0 ]]; then
    need_warmup=1
  else
    for archive_path in "${pipeline_archives[@]}"; do
      if [[ "$exe" -nt "$archive_path" ]]; then
        need_warmup=1
        break
      fi
    done
  fi
fi

run_case() {
  local bucket="$1"
  local case_name="$2"
  local missing_count="$3"
  local coin_types="$4"
  local d_type="$5"
  shift 5

  local output
  local start_ns
  local end_ns
  local elapsed_ms
  local case_batch_cap="${CMR_BENCH_MAX_CHECKSUM_BATCHES:-}"

  if [[ "$case_warmup_enabled" == "1" ]]; then
    if ! output="$(env CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 "$exe" "$@" 2>&1)"; then
      printf '%s\n' "$output" >&2
      echo "Benchmark warmup case '$case_name' failed." >&2
      exit 1
    fi
    cmr_require_no_runtime_fallback "$case_name warmup" "$output"
  fi

  for ((repeat = 1; repeat <= repeat_count; ++repeat)); do
    if [[ -n "$case_batch_cap" ]]; then
      echo "[case] $case_name (run $repeat/$repeat_count, sampled batches=$case_batch_cap)"
    else
      echo "[case] $case_name (run $repeat/$repeat_count)"
    fi
    start_ns="$("$python_bin" - <<'PY'
import time
print(time.perf_counter_ns())
PY
)"
    if ! output="$(env CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0 "$exe" "$@" 2>&1)"; then
      printf '%s\n' "$output" >&2
      echo "Benchmark case '$case_name' failed." >&2
      exit 1
    fi
    end_ns="$("$python_bin" - <<'PY'
import time
print(time.perf_counter_ns())
PY
)"

    cmr_require_no_runtime_fallback "$case_name" "$output"

    elapsed_ms="$("$python_bin" - "$start_ns" "$end_ns" <<'PY'
import sys
start_ns = int(sys.argv[1])
end_ns = int(sys.argv[2])
print(f"{(end_ns - start_ns) / 1_000_000:.3f}")
PY
)"

    CMR_BENCH_OUTPUT="$output" "$python_bin" - "$tsv_path" "$bucket" "$case_name" "$repeat" "$missing_count" "$coin_types" "$d_type" "$elapsed_ms" <<'PY'
import os
import re
import sys

tsv_path, bucket, case_name, repeat, missing_count, coin_types, d_type, elapsed_ms = sys.argv[1:]
output = os.environ["CMR_BENCH_OUTPUT"]

summary = re.search(r"Recovery tested\s+(\d+)\s+candidates\.(?:\s+Checksum-valid:\s+(\d+)\.)?\s+Found:\s+(\d+)\.", output)
task_summary = re.search(r"tested=(\d+)(?:\s+checksum-valid=(\d+))?", output)
found = re.search(r"Found:\s+(\d+)", output)
speed = re.search(r"Recovery speed:\s+([0-9.]+)\s+([MG]) candidates/s", output)

if summary:
    tested = int(summary.group(1))
    checksum_valid = int(summary.group(2)) if summary.group(2) else 0
    found_count = int(summary.group(3))
else:
    tested = int(task_summary.group(1)) if task_summary else 0
    checksum_valid = int(task_summary.group(2)) if task_summary and task_summary.group(2) else 0
    found_count = int(found.group(1)) if found else 0
if speed:
    multiplier = 1_000_000 if speed.group(2) == "M" else 1_000_000_000
    speed_value = float(speed.group(1)) * multiplier
else:
    elapsed_seconds = max(float(elapsed_ms) / 1000.0, 1e-9)
    speed_value = tested / elapsed_seconds

with open(tsv_path, "a", encoding="utf-8") as handle:
    handle.write(
        f"{bucket}\t{case_name}\t{repeat}\t{missing_count}\t{coin_types}\t{d_type}\t{elapsed_ms}\t"
        f"{tested}\t{checksum_valid}\t{found_count}\t{speed_value:.3f}\n"
    )
PY
  done
}

pushd "$repo_root" >/dev/null

if [[ "$need_warmup" -eq 1 ]]; then
  echo "[warmup] Metal pipeline archive"
  warmup_cmd=(
    env
    CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0
    "$exe"
    -recovery "adapt access alert human kiwi rough pottery level soon funny burst *"
    -d examples/derivations/default.txt
    -c c
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
    "${dispatch_args[@]}"
  )
  warmup_output="$("${warmup_cmd[@]}" 2>&1)" || {
    printf '%s\n' "$warmup_output" >&2
    echo "Benchmark warmup failed." >&2
    exit 1
  }
  cmr_require_no_runtime_fallback "benchmark warmup" "$warmup_output"

  warmup_mixed_cmd=(
    env
    CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0
    "$exe"
    -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce"
    -d examples/validation/derivations-solana.txt
    -c cS
    -d_type 3
    -full
    "${dispatch_args[@]}"
  )
  warmup_mixed_output="$("${warmup_mixed_cmd[@]}" 2>&1)" || {
    printf '%s\n' "$warmup_mixed_output" >&2
    echo "Benchmark mixed warmup failed." >&2
    exit 1
  }
  cmr_require_no_runtime_fallback "benchmark mixed warmup" "$warmup_mixed_output"

  warmup_filter_cmd=(
    env
    CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0
    "$exe"
    -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce"
    -d examples/validation/derivations-solana.txt
    -c S
    -d_type 2
    -xb "$solana_bloom"
    "${dispatch_args[@]}"
  )
  warmup_filter_output="$("${warmup_filter_cmd[@]}" 2>&1)" || {
    printf '%s\n' "$warmup_filter_output" >&2
    echo "Benchmark filter warmup failed." >&2
    exit 1
  }
  cmr_require_no_runtime_fallback "benchmark filter warmup" "$warmup_filter_output"

  warmup_xor_cmd=(
    env
    CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0
    "$exe"
    -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce"
    -d examples/validation/derivations-solana.txt
    -c S
    -d_type 2
    -xu "$solana_xor"
    "${dispatch_args[@]}"
  )
  warmup_xor_output="$("${warmup_xor_cmd[@]}" 2>&1)" || {
    printf '%s\n' "$warmup_xor_output" >&2
    echo "Benchmark xor warmup failed." >&2
    exit 1
  }
  cmr_require_no_runtime_fallback "benchmark xor warmup" "$warmup_xor_output"
fi

run_case "search_fixture_small" "secp_exact_1missing" "1" "c" "1" \
  -recovery -i examples/bench/templates-64x-1missing.txt \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "search_fixture_expanded" "secp_exact_1x2missing" "2" "c" "1" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny * *" \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
  "${dispatch_args[@]}"

run_case "single_family" "solana_d2_exact" "0" "S" "2" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -hash 89dfcdfe8986448bf0ca1f5bc1720de5ad66104c \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "mixed_family" "mixed_d3_full" "0" "cS" "3" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/validation/derivations-solana.txt \
  -c cS \
  -d_type 3 \
  -full \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "single_family" "d4_exact" "0" "c" "4" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/derivations/default.txt \
  -c c \
  -d_type 4 \
  -hash 4fd01a8da7097495668c9ee9499084bc5680199a \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "single_family" "ton_short_full" "0" "t" "2" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/validation/derivations-solana.txt \
  -c t \
  -d_type 2 \
  -full \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "single_family" "ton_all_full" "0" "T" "2" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/validation/derivations-solana.txt \
  -c T \
  -d_type 2 \
  -full \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "filter_heavy" "solana_bloom" "0" "S" "2" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -xb "$solana_bloom" \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

run_case "filter_heavy" "solana_xor_u" "0" "S" "2" \
  -recovery -i examples/bench/templates-64x-exact.txt \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -xu "$solana_xor" \
  "${dispatch_args[@]}" \
  -fsize "$exact_fixture_found_size"

if [[ "$include_long_cases" == "1" ]]; then
  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_8x2missing_sampled" "2x8" "c" "1" \
    -recovery -i examples/bench/templates-8x-2missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_1x3missing_sampled" "3" "c" "1" \
    -recovery -i examples/bench/templates-1x-3missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_8x3missing_sampled" "3x8" "c" "1" \
    -recovery -i examples/bench/templates-8x-3missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_1x4missing_sampled" "4" "c" "1" \
    -recovery -i examples/bench/templates-1x-4missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_1x5missing_sampled" "5" "c" "1" \
    -recovery -i examples/bench/templates-1x-5missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_1x6missing_sampled" "6" "c" "1" \
    -recovery -i examples/bench/templates-1x-6missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_1x8missing_sampled" "8" "c" "1" \
    -recovery -i examples/bench/templates-1x-8missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"

  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "long_missing_sampled" "secp_exact_1x12missing_sampled" "12" "c" "1" \
    -recovery -i examples/bench/templates-1x-12missing.txt \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"
fi

if [[ "$include_long_cases" == "1" && -n "$gt5_template" ]]; then
  CMR_BENCH_MAX_CHECKSUM_BATCHES="$long_sample_batches" run_case "custom_gt5_sampled" ">5_missing_custom_sampled" ">5" "c" "1" \
    -recovery -i "$gt5_template" \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    "${dispatch_args[@]}"
fi

popd >/dev/null

"$python_bin" - "$tsv_path" "$md_path" <<'PY'
from collections import defaultdict
from pathlib import Path
import os
import sys

tsv_path = Path(sys.argv[1])
md_path = Path(sys.argv[2])

rows = []
with tsv_path.open("r", encoding="utf-8") as handle:
    header = handle.readline().rstrip("\n").split("\t")
    for line in handle:
        values = line.rstrip("\n").split("\t")
        rows.append(dict(zip(header, values)))

grouped = defaultdict(list)
for row in rows:
    grouped[row["bucket"]].append(row)

def median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0

def render_table(bucket: str, bucket_rows: list[dict[str, str]]) -> list[str]:
    lines = [f"## {bucket.replace('_', ' ').title()}", "", "| Case | Runs | Missing | Coin Types | d_type | Tested | Checksum-valid | Found | Median ms | Median cands/s |", "| --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    case_groups = defaultdict(list)
    for row in bucket_rows:
        case_groups[row["case"]].append(row)
    for case_name in sorted(case_groups):
        case_rows = case_groups[case_name]
        first = case_rows[0]
        median_elapsed = median([float(row["elapsed_ms"]) for row in case_rows])
        median_speed = median([float(row["speed_cands_per_sec"]) for row in case_rows])
        lines.append(
            f"| {case_name} | {len(case_rows)} | {first['missing_count']} | {first['coin_types']} | {first['d_type']} | "
            f"{first['tested']} | {first['checksum_valid']} | {first['found']} | "
            f"{median_elapsed:.3f} | {median_speed:.3f} |"
        )
    lines.append("")
    return lines

lines = [
    "# Benchmark Matrix",
    "",
    "Generated by `scripts/benchmark_matrix_macos.sh`.",
    "",
    f"- TSV: `{tsv_path}`",
    f"- Cases: `{len(rows)}`",
    f"- Long sampled batch cap: `{os.environ.get('CMR_BENCH_SAMPLE_BATCHES_LONG', '2')}`",
    "",
]
for bucket in ("search_fixture_small", "search_fixture_expanded", "single_family", "mixed_family", "filter_heavy", "long_missing_sampled", "custom_gt5_sampled"):
    if bucket in grouped:
        lines.extend(render_table(bucket, grouped[bucket]))

md_path.write_text("\n".join(lines), encoding="utf-8")
PY

echo "[ok] benchmark matrix written to $tsv_path"
echo "[ok] benchmark summary written to $md_path"
