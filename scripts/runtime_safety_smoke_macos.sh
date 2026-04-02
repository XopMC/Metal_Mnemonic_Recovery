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
safe_timeout_ms="${CMR_RUNTIME_COMPLETION_TIMEOUT_MS:-12000}"
safe_threads="${CMR_RUNTIME_SAFE_THREADS:-64}"
safe_sleep_seconds="${CMR_RUNTIME_SAFE_SLEEP_SECONDS:-5}"
safe_settle_seconds="${CMR_RUNTIME_SAFE_SETTLE_SECONDS:-3}"
safe_tile_seed_cap="${CMR_RUNTIME_TILE_SEED_CAP:-}"
safe_cursor_tile_cap="${CMR_RUNTIME_CURSOR_TILE_CAP:-}"
cooldown_stamp="${CMR_RUNTIME_SAFE_COOLDOWN_FILE:-/tmp/cmr_runtime_safety_smoke.last_end}"
watchdog_dir="/Library/Logs/DiagnosticReports"
watchdog_retired_dir="/Library/Logs/DiagnosticReports/Retired"

if [[ ! -x "$exe" ]]; then
  echo "Executable not found or not executable: $exe" >&2
  exit 1
fi

if ! command -v log >/dev/null 2>&1; then
  echo "macOS unified log tool is unavailable." >&2
  exit 1
fi

record_cooldown() {
  date +%s >"$cooldown_stamp" 2>/dev/null || true
}

respect_cooldown() {
  if [[ ! -f "$cooldown_stamp" ]]; then
    return
  fi

  local previous_epoch
  previous_epoch="$(tr -cd '0-9' <"$cooldown_stamp" 2>/dev/null || true)"
  if [[ -z "$previous_epoch" ]]; then
    return
  fi

  local now_epoch delta remaining
  now_epoch="$(date +%s)"
  delta=$(( now_epoch - previous_epoch ))
  if (( delta >= safe_sleep_seconds )); then
    return
  fi

  remaining=$(( safe_sleep_seconds - delta ))
  echo "[wait] cooldown ${remaining}s"
  sleep "$remaining"
}

snapshot_watchdog_reports() {
  {
    find "$watchdog_dir" -maxdepth 1 -type f -name 'WindowServer*.userspace_watchdog_timeout*' -print 2>/dev/null
    find "$watchdog_retired_dir" -maxdepth 1 -type f -name 'WindowServer-*.ips' -print 2>/dev/null
  } | LC_ALL=C sort || true
}

check_watchdog_markers() {
  local name="$1"
  local start_time="$2"
  local before_snapshot="$3"
  local log_output after_snapshot new_reports settle_step

  for ((settle_step = 0; settle_step <= safe_settle_seconds; ++settle_step)); do
    log_output="$(log show --style compact --start "$start_time" --predicate '(process == "WindowServer") || (process == "loginwindow")' 2>/dev/null || true)"
    if grep -Eiq 'coreanimation synchronize timed out|display .* has become stuck|Window Server exited, closing down the session immediately' <<<"$log_output"; then
      echo "Case '$name' triggered GUI watchdog markers." >&2
      grep -Ei 'coreanimation synchronize timed out|display .* has become stuck|Window Server exited, closing down the session immediately' <<<"$log_output" >&2 || true
      exit 1
    fi

    after_snapshot="$(snapshot_watchdog_reports)"
    new_reports=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if ! grep -Fqx -- "$line" <<<"$before_snapshot"; then
        new_reports+="$line"$'\n'
      fi
    done <<<"$after_snapshot"

    if [[ -n "$new_reports" ]]; then
      echo "Case '$name' created new WindowServer watchdog reports." >&2
      printf '%s' "$new_reports" >&2
      exit 1
    fi

    if (( settle_step < safe_settle_seconds )); then
      sleep 1
    fi
  done
}

run_safe_case_capture() {
  local name="$1"
  shift
  echo "[case] $name"

  local start_time before_snapshot output status=0
  start_time="$(date '+%Y-%m-%d %H:%M:%S')"
  before_snapshot="$(snapshot_watchdog_reports)"
  local -a env_cmd=(
    env
    "CMR_EXPERIMENTAL_PERSISTENT_RUNTIME=0"
    "CMR_RUNTIME_COMPLETION_TIMEOUT_MS=$safe_timeout_ms"
    "CMR_RUNTIME_SEED_GROUP_CAP=${CMR_RUNTIME_SEED_GROUP_CAP:-1}"
    "CMR_RUNTIME_SECP_GROUP_CAP=${CMR_RUNTIME_SECP_GROUP_CAP:-1}"
    "CMR_RUNTIME_ED_GROUP_CAP=${CMR_RUNTIME_ED_GROUP_CAP:-1}"
    "CMR_RUNTIME_ED_PROMOTE_GROUP_CAP=${CMR_RUNTIME_ED_PROMOTE_GROUP_CAP:-1}"
    "CMR_RUNTIME_SECP_PROMOTE_GROUP_CAP=${CMR_RUNTIME_SECP_PROMOTE_GROUP_CAP:-1}"
  )
  if [[ -n "${CMR_RUNTIME_CHECKSUM_GROUP_CAP:-}" ]]; then
    env_cmd+=("CMR_RUNTIME_CHECKSUM_GROUP_CAP=$CMR_RUNTIME_CHECKSUM_GROUP_CAP")
  fi
  if [[ -n "$safe_tile_seed_cap" ]]; then
    env_cmd+=("CMR_RUNTIME_TILE_SEED_CAP=$safe_tile_seed_cap")
  fi
  if [[ -n "$safe_cursor_tile_cap" ]]; then
    env_cmd+=("CMR_RUNTIME_CURSOR_TILE_CAP=$safe_cursor_tile_cap")
  fi
  if [[ -n "${CMR_BENCH_MAX_CHECKSUM_BATCHES:-}" ]]; then
    env_cmd+=("CMR_BENCH_MAX_CHECKSUM_BATCHES=$CMR_BENCH_MAX_CHECKSUM_BATCHES")
  fi
  env_cmd+=("$exe" "-device" "$device" "-t" "$safe_threads")
  output="$("${env_cmd[@]}" "$@" 2>&1)" || status=$?

  check_watchdog_markers "$name" "$start_time" "$before_snapshot"
  printf '%s\n' "$output"
  return "$status"
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

require_no_pattern() {
  local name="$1"
  local output="$2"
  local pattern="$3"
  if grep -Eq -- "$pattern" <<<"$output"; then
    echo "Case '$name' matched forbidden pattern '$pattern'." >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

count_found_lines() {
  local output="$1"
  awk 'match($0, /Found:[[:space:]]+[0-9]+/) { count++ } END { print count + 0 }' <<<"$output"
}

require_found_line_count() {
  local name="$1"
  local output="$2"
  local expected="$3"
  local count
  count="$(count_found_lines "$output")"
  if [[ "$count" -ne "$expected" ]]; then
    echo "Case '$name' emitted $count Found lines, expected $expected." >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

require_found_line_count_max() {
  local name="$1"
  local output="$2"
  local max_allowed="$3"
  local count
  count="$(count_found_lines "$output")"
  if (( count > max_allowed )); then
    echo "Case '$name' emitted $count Found lines, expected at most $max_allowed." >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

trap record_cooldown EXIT
respect_cooldown

pushd "$repo_root" >/dev/null

if ! tiny_exact_output="$(run_safe_case_capture "tiny exact secp" \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst *" \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
  -silent)"; then
  echo "$tiny_exact_output" >&2
  echo "Case 'tiny exact secp' failed." >&2
  exit 1
fi
require_pattern "tiny exact secp" "$tiny_exact_output" 'Found:[[:space:]]+1'
require_pattern "tiny exact secp" "$tiny_exact_output" 'Recovery task done'
require_found_line_count "tiny exact secp" "$tiny_exact_output" 1
require_no_pattern "tiny exact secp" "$tiny_exact_output" 'invalid FoundRecord word_count'
require_no_pattern "tiny exact secp" "$tiny_exact_output" 'kIOGPUCommandBufferCallbackErrorTimeout'
echo "[ok] tiny exact secp"

sleep "$safe_sleep_seconds"

sampled_two_missing_status=0
sampled_two_missing_output="$(
  CMR_BENCH_MAX_CHECKSUM_BATCHES=1 run_safe_case_capture "sampled two missing secp" \
    -recovery "adapt access alert human kiwi rough pottery level soon * * divorce" \
    -d examples/derivations/default.txt \
    -c c \
    -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0 \
    -silent
)" || sampled_two_missing_status=$?
require_no_pattern "sampled two missing secp" "$sampled_two_missing_output" 'invalid FoundRecord word_count'
require_no_pattern "sampled two missing secp" "$sampled_two_missing_output" 'kIOGPUCommandBufferCallbackErrorTimeout'
require_found_line_count_max "sampled two missing secp" "$sampled_two_missing_output" 1
if [[ "$sampled_two_missing_status" -eq 0 ]]; then
  require_pattern "sampled two missing secp" "$sampled_two_missing_output" 'Recovery task done'
  require_pattern "sampled two missing secp" "$sampled_two_missing_output" 'tested=[0-9]+'
else
  require_pattern "sampled two missing secp" "$sampled_two_missing_output" 'Metal unified runtime completion wait timed out'
fi
echo "[ok] sampled two missing secp"

popd >/dev/null
