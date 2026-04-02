#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
matrix_script="$repo_root/scripts/benchmark_matrix_macos.sh"
python_bin="${PYTHON:-python3}"
threshold_pct="${CMR_BENCH_STABILITY_THRESHOLD_PCT:-3}"
pass_count="${CMR_BENCH_SIGNOFF_PASSES:-2}"
repeat_count="${CMR_BENCH_SIGNOFF_REPEAT:-2}"
long_sample_batches="${CMR_BENCH_SIGNOFF_SAMPLE_BATCHES_LONG:-8}"
cooldown_sec="${CMR_BENCH_SIGNOFF_COOLDOWN_SEC:-60}"
preheat_enabled="${CMR_BENCH_SIGNOFF_PREHEAT:-1}"
gt5_template="${CMR_BENCH_GT5_TEMPLATE:-}"
base_out_dir="${CMR_BENCH_SIGNOFF_OUT_DIR:-$repo_root/out/benchmarks-signoff}"
run_id="${CMR_BENCH_SIGNOFF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
staging_out_dir="$base_out_dir/runs/$run_id"

if [[ ! -x "$matrix_script" ]]; then
  echo "Benchmark matrix script not found or not executable: $matrix_script" >&2
  exit 1
fi

if [[ -n "$gt5_template" && ! -f "$gt5_template" ]]; then
  echo "Strict benchmark signoff template not found: $gt5_template" >&2
  exit 1
fi

if [[ "$pass_count" -lt 2 ]]; then
  echo "CMR_BENCH_SIGNOFF_PASSES must be at least 2." >&2
  exit 1
fi

if [[ "$repeat_count" -lt 1 ]]; then
  echo "CMR_BENCH_SIGNOFF_REPEAT must be at least 1." >&2
  exit 1
fi

if [[ "$long_sample_batches" -lt 1 ]]; then
  echo "CMR_BENCH_SIGNOFF_SAMPLE_BATCHES_LONG must be at least 1." >&2
  exit 1
fi

if [[ "$cooldown_sec" -lt 0 ]]; then
  echo "CMR_BENCH_SIGNOFF_COOLDOWN_SEC must be non-negative." >&2
  exit 1
fi

mkdir -p "$staging_out_dir"

run_matrix() {
  local out_dir="$1"
  local repeats="$2"
  if [[ -n "$gt5_template" ]]; then
    CMR_BENCH_OUT_DIR="$out_dir" \
    CMR_BENCH_INCLUDE_LONG=1 \
    CMR_BENCH_REPEAT="$repeats" \
    CMR_BENCH_SAMPLE_BATCHES_LONG="$long_sample_batches" \
    CMR_BENCH_GT5_TEMPLATE="$gt5_template" \
    bash "$matrix_script"
  else
    CMR_BENCH_OUT_DIR="$out_dir" \
    CMR_BENCH_INCLUDE_LONG=1 \
    CMR_BENCH_REPEAT="$repeats" \
    CMR_BENCH_SAMPLE_BATCHES_LONG="$long_sample_batches" \
    bash "$matrix_script"
  fi
}

if [[ "$preheat_enabled" != "0" ]]; then
  preheat_dir="$staging_out_dir/preheat-discard"
  rm -rf "$preheat_dir"
  mkdir -p "$preheat_dir"
  echo "[preheat] discarded suite warmup"
  run_matrix "$preheat_dir" 1
  rm -rf "$preheat_dir"
fi

pass_dirs=()
for ((pass_index = 1; pass_index <= pass_count; ++pass_index)); do
  pass_dir="$staging_out_dir/pass-$pass_index"
  rm -rf "$pass_dir"
  mkdir -p "$pass_dir"
  pass_dirs+=( "$pass_dir" )
  echo "[pass] $pass_index/$pass_count"
  run_matrix "$pass_dir" "$repeat_count"

  if [[ "$pass_index" -lt "$pass_count" && "$cooldown_sec" -gt 0 ]]; then
    echo "[cooldown] sleeping ${cooldown_sec}s before next pass"
    sleep "$cooldown_sec"
  fi
done

summary_path="$staging_out_dir/signoff-summary.md"

summary_status=0
if ! "$python_bin" - "$threshold_pct" "$repeat_count" "$long_sample_batches" "$summary_path" "${pass_dirs[@]}" <<'PY'
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import statistics
import sys

threshold_pct = float(sys.argv[1])
repeat_count = int(sys.argv[2])
long_sample_batches = int(sys.argv[3])
summary_path = Path(sys.argv[4])
pass_dirs = [Path(arg) for arg in sys.argv[5:]]

def median(values: list[float]) -> float:
    return statistics.median(values)

def load_tsv(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        header = handle.readline().rstrip("\n").split("\t")
        for line in handle:
            values = line.rstrip("\n").split("\t")
            rows.append(dict(zip(header, values)))
    return rows

pass_totals: list[tuple[int, float, float, dict[str, tuple[float, float]]]] = []
for index, pass_dir in enumerate(pass_dirs, start=1):
    tsv_path = pass_dir / "benchmark-matrix.tsv"
    if not tsv_path.exists():
        raise SystemExit(f"Missing benchmark TSV for pass {index}: {tsv_path}")
    rows = load_tsv(tsv_path)
    per_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        per_case[row["case"]].append(row)
    elapsed_total = 0.0
    speed_total = 0.0
    case_summaries: dict[str, tuple[float, float]] = {}
    for case_name in sorted(per_case):
        case_rows = per_case[case_name]
        case_elapsed = median([float(row["elapsed_ms"]) for row in case_rows])
        case_speed = median([float(row["speed_cands_per_sec"]) for row in case_rows])
        elapsed_total += case_elapsed
        speed_total += case_speed
        case_summaries[case_name] = (case_elapsed, case_speed)
    pass_totals.append((index, elapsed_total, speed_total, case_summaries))

previous = pass_totals[-2]
current = pass_totals[-1]

prev_elapsed = previous[1]
curr_elapsed = current[1]
prev_speed = previous[2]
curr_speed = current[2]
prev_cases = previous[3]
curr_cases = current[3]

if set(prev_cases) != set(curr_cases):
    raise SystemExit("Benchmark signoff failed: pass case sets do not match.")

elapsed_delta_pct = 0.0 if prev_elapsed == 0.0 else abs(curr_elapsed - prev_elapsed) / prev_elapsed * 100.0
speed_delta_pct = 0.0 if prev_speed == 0.0 else abs(curr_speed - prev_speed) / prev_speed * 100.0
per_case_deltas: list[tuple[str, float, float, float]] = []
for case_name in sorted(curr_cases):
    prev_case_elapsed, prev_case_speed = prev_cases[case_name]
    curr_case_elapsed, curr_case_speed = curr_cases[case_name]
    case_elapsed_delta = 0.0 if prev_case_elapsed == 0.0 else abs(curr_case_elapsed - prev_case_elapsed) / prev_case_elapsed * 100.0
    case_speed_delta = 0.0 if prev_case_speed == 0.0 else abs(curr_case_speed - prev_case_speed) / prev_case_speed * 100.0
    per_case_deltas.append((case_name, case_elapsed_delta, case_speed_delta, max(case_elapsed_delta, case_speed_delta)))

worst_case_name, worst_case_elapsed_delta, worst_case_speed_delta, worst_case_delta = max(
    per_case_deltas,
    key=lambda item: item[3],
)
aggregate_delta_pct = max(elapsed_delta_pct, speed_delta_pct)
stability_delta_pct = max(aggregate_delta_pct, worst_case_delta)
passed = stability_delta_pct < threshold_pct

lines = [
    "# Benchmark Signoff Summary",
    "",
    f"- Threshold: `{threshold_pct:.3f}%`",
    f"- Passes: `{len(pass_totals)}`",
    f"- Repeats per case: `{repeat_count}`",
    f"- Long sampled batches per case: `{long_sample_batches}`",
    "",
]
for index, elapsed_total, speed_total, case_summaries in pass_totals:
    lines.append(
        f"- Pass {index}: `{len(case_summaries)}` cases, total median elapsed `{elapsed_total:.3f} ms`, "
        f"total median speed `{speed_total:.3f} cands/s`"
    )
lines.extend([
    "",
    f"- Aggregate elapsed delta (last two passes): `{elapsed_delta_pct:.3f}%`",
    f"- Aggregate speed delta (last two passes): `{speed_delta_pct:.3f}%`",
    f"- Worst per-case delta: `{worst_case_name}` elapsed `{worst_case_elapsed_delta:.3f}%`, speed `{worst_case_speed_delta:.3f}%`, max `{worst_case_delta:.3f}%`",
    f"- Stability delta (max aggregate/per-case): `{stability_delta_pct:.3f}%`",
    f"- Result: `{'PASS' if passed else 'FAIL'}`",
    "",
    "Strict signoff uses the max absolute delta across aggregate totals and per-case medians.",
])
summary_path.write_text("\n".join(lines), encoding="utf-8")

if not passed:
    raise SystemExit(
        f"Benchmark signoff failed: stability delta {stability_delta_pct:.3f}% >= threshold {threshold_pct:.3f}%"
    )
PY
then
  summary_status=$?
fi

for ((pass_index = 1; pass_index <= pass_count; ++pass_index)); do
  rm -rf "$base_out_dir/pass-$pass_index"
  cp -R "$staging_out_dir/pass-$pass_index" "$base_out_dir/pass-$pass_index"
done
cp "$summary_path" "$base_out_dir/signoff-summary.md"
printf '%s\n' "$run_id" > "$base_out_dir/latest-run.txt"

echo "[ok] benchmark signoff summary written to $summary_path"
echo "[ok] published signoff artifacts to $base_out_dir (run $run_id)"
exit "$summary_status"
