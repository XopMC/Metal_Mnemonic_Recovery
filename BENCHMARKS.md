# Benchmarks

This document records the lightweight benchmark surface for `Metal_Mnemonic_Recovery`.

## Scope

- Platform: macOS with Metal support
- GPU API: Metal
- Build preset: `macos-metal-release`
- Binary: `out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery`

Primary validation host: Apple Silicon MacBook Pro.

The public repository does not make cross-platform or cross-vendor throughput claims. Benchmark numbers from this tree should be treated as local Metal measurements on the tested Mac.

## Quick Benchmark Commands

Smoke benchmark:

```bash
bash ./scripts/benchmark_smoke_macos.sh
```

Representative 3-missing local run with live status:

```bash
env CMR_RUNTIME_COMPLETION_TIMEOUT_MS=120000 CMR_BENCH_MAX_CHECKSUM_BATCHES=48 \
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -recovery \
  -i examples/bench/templates-1x-3missing.txt \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
```

## Reporting Guidance

When recording a local speed sample, keep:

- the full command line
- elapsed time
- tested counter
- checksum-valid counter
- found count
- visible live speed lines when available

The README includes a single local speed screenshot from the bundled `1x3missing` fixture. Treat it as a representative local capture, not a universal benchmark promise.
