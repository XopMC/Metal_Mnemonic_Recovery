#!/usr/bin/env bash

cmr_fallback_pattern='falling back to CPU checksum path|CPU checksum enumeration failed|CPU fallback'
cmr_runtime_reference_pattern='run_oracle|native recovery oracle|recovery_native::run_oracle|Recovery oracle error'
cmr_binary_reference_pattern='recovery_native|native_recovery_oracle|__ZN15recovery_native10run_oracle|CUDA_Mnemonic_Recovery|found_record_evaluator'
cmr_runtime_source_reference_pattern='run_oracle\(|recovery_native::run_oracle|OracleRecord'
cmr_cpu_filter_reference_pattern='useBloomCPU|useXorCPU|record_matches_cpu_filters|loadXorFilters|loadBloomFiltersIntoSharedMemory'
cmr_host_eval_reference_pattern='recovery_eval_runtime|evaluate_found_records'
cmr_runtime_orchestration_pattern='high_missing|low_missing|RecoveryRange|RecoveryChecksumTileCursor|tile_cursor\.next|unsupported wildcard split'
cmr_unified_runtime_orchestration_pattern='recovery_checksum_batch_count_for_missing|recovery_checksum_batch_submission_count|checksum_batch_count|checksum_batch_submission_count|submitted_batches|submitted_buffers|pending_batch_count|kRecoveryTileBatchDepth|batch_submission_index|addCompletedHandler|submit_next_batch|cursor_state->exhausted'
cmr_source_name_pattern='CUDA_Mnemonic_Recovery|cuda_mnemonic_recovery|cuda_runtime|__CUDA_ARCH__'
cmr_allowed_upstream_doc_pattern='README\.md:.*https://github\.com/XopMC/CUDA_Mnemonic_Recovery|THIRD_PARTY_NOTICES\.md:.*https://github\.com/XopMC/CUDA_Mnemonic_Recovery|CITATION\.cff:.*https://github\.com/XopMC/CUDA_Mnemonic_Recovery'
cmr_legacy_tree_pattern='(^|/)include/(cuda|compat)/|(^|/)[^/]+\\.(cu|cuh)$|(^|/)src/cuda/|validate_release\\.ps1$|CUDA_Mnemonic_Recovery\\.(sln|vcxproj|vcxproj\\.filters)$'
cmr_platform_docs_pattern='Windows|Linux / WSL|linux-release|windows-release|msbuild CUDA_Mnemonic_Recovery|PowerShell'
cmr_source_purity_pattern='runtime_stub|legacy_math|curand_kernel|cudaError_t|cudaMemcpyToSymbol|workerRecoveryCompat|match_loaded_filters|__device__|__host__|__global__|__constant__|__forceinline__|__noinline__|__align__\(|windows\\.h|_WIN64|Words\\.h|setDictPointer|workerRecoveryEvalEd25519Compat|CMR_SOURCE_DIR'
cmr_build_graph_purity_pattern='include/runtime_compat|legacy_math/|CMR_SOURCE_DIR'

cmr_build_purity_mode="${CMR_BUILD_PURITY_MODE:-strict}"
cmr_build_purity_strict="${CMR_BUILD_PURITY_STRICT:-1}"
cmr_build_purity_unified="${CMR_BUILD_PURITY_UNIFIED:-0}"

cmr_is_build_purity_strict() {
  [[ "$cmr_build_purity_mode" == "strict" || "$cmr_build_purity_strict" == "1" ]]
}

cmr_is_build_purity_unified() {
  [[ "$cmr_build_purity_unified" == "1" ]]
}

cmr_emit_multiline_block() {
  local text="$1"
  while IFS= read -r line; do
    [[ -n "$line" ]] && printf '    %s\n' "$line"
  done <<<"$text"
}

cmr_fail_or_note() {
  local heading="$1"
  local details="${2:-}"
  if cmr_is_build_purity_strict; then
    echo "$heading" >&2
    [[ -n "$details" ]] && cmr_emit_multiline_block "$details" >&2
    exit 1
  fi
  echo "[note] $heading"
  [[ -n "$details" ]] && cmr_emit_multiline_block "$details"
}

cmr_require_no_runtime_fallback() {
  local name="$1"
  local output="$2"
  if grep -Eq -- "$cmr_fallback_pattern" <<<"$output"; then
    echo "Case '$name' emitted an implicit CPU fallback warning." >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  if grep -Eq -- "$cmr_runtime_reference_pattern" <<<"$output"; then
    echo "Case '$name' referenced a legacy host-native oracle path." >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

cmr_scan_build_purity() {
  local repo_root="$1"
  local exe="$2"

  echo "[case] build purity scan (${cmr_build_purity_mode})"

  if command -v nm >/dev/null 2>&1 && command -v rg >/dev/null 2>&1; then
    local binary_refs
    binary_refs="$(nm -gU "$exe" 2>/dev/null | rg "$cmr_binary_reference_pattern" || true)"
    if [[ -n "$binary_refs" ]]; then
      cmr_fail_or_note "Executable still exports legacy oracle/native symbols." "$binary_refs"
    else
      echo "[ok] executable symbol scan"
    fi
  else
    echo "[note] executable symbol scan skipped because nm/rg is unavailable"
  fi

  if command -v rg >/dev/null 2>&1; then
    local cmake_refs
    cmake_refs="$(rg -n "$cmr_binary_reference_pattern|src/core/native_recovery_oracle\\.mm" "$repo_root/CMakeLists.txt" || true)"
    if [[ -n "$cmake_refs" ]]; then
      cmr_fail_or_note "CMake build graph still references legacy oracle/native sources." "$cmake_refs"
    else
      echo "[ok] cmake build graph scan"
    fi

    local runtime_refs
    runtime_refs="$(rg -n "$cmr_runtime_source_reference_pattern" "$repo_root/src/macos/recovery_macos.mm" || true)"
    if [[ -n "$runtime_refs" ]]; then
      cmr_fail_or_note "Runtime glue still references the oracle record path." "$runtime_refs"
    else
      echo "[ok] runtime source scan"
    fi

    local cpu_filter_refs
    cpu_filter_refs="$(rg -n "$cmr_cpu_filter_reference_pattern" "$repo_root/src/macos/recovery_macos.mm" || true)"
    if [[ -n "$cpu_filter_refs" ]]; then
      cmr_fail_or_note "Runtime glue still contains CPU filter verification hooks." "$cpu_filter_refs"
    else
      echo "[ok] cpu filter source scan"
    fi

    local host_eval_refs
    host_eval_refs="$(rg -n "$cmr_host_eval_reference_pattern" "$repo_root/CMakeLists.txt" "$repo_root/src" "$repo_root/include" 2>/dev/null || true)"
    if [[ -n "$host_eval_refs" ]]; then
      cmr_fail_or_note "Active tree still references the removed host evaluation runtime." "$host_eval_refs"
    else
      echo "[ok] host eval source scan"
    fi

    local runtime_orchestration_refs
    runtime_orchestration_refs="$(rg -n "$cmr_runtime_orchestration_pattern" "$repo_root/src/macos/recovery_macos.mm" 2>/dev/null || true)"
    if [[ -n "$runtime_orchestration_refs" ]]; then
      cmr_fail_or_note "Runtime glue still contains legacy host split/range-stack orchestration." "$runtime_orchestration_refs"
    else
      echo "[ok] runtime orchestration scan"
    fi

    if cmr_is_build_purity_unified; then
      local unified_runtime_orchestration_refs
      unified_runtime_orchestration_refs="$(rg -n "$cmr_unified_runtime_orchestration_pattern" "$repo_root/src/macos/recovery_macos.mm" 2>/dev/null || true)"
      if [[ -n "$unified_runtime_orchestration_refs" ]]; then
        cmr_fail_or_note "Runtime glue still contains active host-owned checksum scheduling or extra GPU->host ABI markers." "$unified_runtime_orchestration_refs"
      else
        echo "[ok] unified runtime orchestration scan"
      fi
    fi

    local source_name_refs
    source_name_refs="$(rg -n "$cmr_source_name_pattern" "$repo_root/CMakeLists.txt" "$repo_root/include" "$repo_root/src" "$repo_root/tests" "$repo_root/README.md" "$repo_root/BENCHMARKS.md" "$repo_root/VALIDATION.md" "$repo_root/RESPONSIBLE_USE.md" "$repo_root/CITATION.cff" "$repo_root/THIRD_PARTY_NOTICES.md" 2>/dev/null || true)"
    if [[ -n "$source_name_refs" ]]; then
      source_name_refs="$(printf '%s\n' "$source_name_refs" | rg -v "$cmr_allowed_upstream_doc_pattern" || true)"
    fi
    if [[ -n "$source_name_refs" ]]; then
      cmr_fail_or_note "Active source/docs still reference CUDA-era naming or CUDA runtime shims." "$source_name_refs"
    else
      echo "[ok] source/docs naming scan"
    fi

    local legacy_tree_refs
    legacy_tree_refs="$(cd "$repo_root" && rg -n "$cmr_legacy_tree_pattern" -g '!out/**' . || true)"
    if [[ -n "$legacy_tree_refs" ]]; then
      cmr_fail_or_note "Tracked tree still contains legacy CUDA-path files or directories." "$legacy_tree_refs"
    else
      echo "[ok] legacy tree scan"
    fi

    local platform_doc_refs
    platform_doc_refs="$(rg -n "$cmr_platform_docs_pattern" "$repo_root/README.md" "$repo_root/BENCHMARKS.md" "$repo_root/VALIDATION.md" "$repo_root/RELEASE_CHECKLIST.md" 2>/dev/null || true)"
    if [[ -n "$platform_doc_refs" ]]; then
      cmr_fail_or_note "Docs still advertise Windows/Linux release flows." "$platform_doc_refs"
    else
      echo "[ok] platform docs scan"
    fi

    local source_purity_refs
    source_purity_refs="$(rg -n "$cmr_source_purity_pattern" "$repo_root/CMakeLists.txt" "$repo_root/include" "$repo_root/src" "$repo_root/third_party" 2>/dev/null || true)"
    if [[ -n "$source_purity_refs" ]]; then
      cmr_fail_or_note "Tracked tree still contains CUDA-shaped compat declarations or dead host matcher seams." "$source_purity_refs"
    else
      echo "[ok] source purity scan"
    fi

    local build_graph_purity_refs
    build_graph_purity_refs="$(rg -n "$cmr_build_graph_purity_pattern" \
      "$repo_root/CMakeLists.txt" \
      "$repo_root/out/build/macos-metal-release/CMakeFiles/Metal_Mnemonic_Recovery.dir/flags.make" \
      "$repo_root/out/build/macos-metal-release/CMakeFiles/Metal_Mnemonic_Recovery_secp_precompute.dir/flags.make" \
      "$repo_root/out/build/macos-metal-release/CMakeFiles/Metal_Mnemonic_Recovery_metallib.dir/build.make" \
      2>/dev/null || true)"
    if [[ -n "$build_graph_purity_refs" ]]; then
      cmr_fail_or_note "Build graph still carries compat include directories or legacy header imports." "$build_graph_purity_refs"
    else
      echo "[ok] build graph purity scan"
    fi
  else
    echo "[note] source/build graph scan skipped because rg is unavailable"
  fi

  echo "[ok] build purity scan (${cmr_build_purity_mode})"
}
