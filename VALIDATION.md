# Validation

This document tracks the maintained validation surface for `Metal_Mnemonic_Recovery`.

## Main Commands

```bash
ctest --test-dir out/build/macos-metal-release --output-on-failure
bash ./scripts/validate_release_macos.sh
bash ./tests/no_fallback_macos.sh
bash ./tests/unified_missing_acceptance_macos.sh
bash ./tests/build_purity_macos.sh
bash ./tests/build_purity_unified_macos.sh
bash ./scripts/runtime_safety_smoke_macos.sh
bash ./scripts/benchmark_smoke_macos.sh
```

## Covered Public Cases

- `-help`
- inline recovery
- file recovery
- typo correction
- passphrase value and passphrase file flows
- `-save`
- valid and invalid `-device`
- secp exact/output parity across `c/u/s/r/x/e`
- Solana exact/output parity
- TON short/all exact/output parity
- mixed `-d_type 3`
- `-d_type 4`
- no-fallback recovery smoke
- missing-count acceptance across shipped fixture sizes
- benchmark smoke output shape
- build-purity and unified Metal purity scans

## Core Exact Fixtures

- secp compressed exact hash: `1a4603d1ff9121515d02a6fee37c20829ca522b0`
- secp uncompressed exact hash: `45be8f10bff228e0de5c068731a7d00ff4914e24`
- secp segwit exact hash: `eb8ee680d5353afac9d542b8a3fb701481689a3c`
- secp taproot exact full-output record: `TAPROOT:c41cd4f04ea29397823eb787633dc7a6fc8b50fb85d62029817ec80b15e23e82`
- secp xpoint exact full-output record: `XPOINT:7f2eb986147480a8cbaa053e35bfc2e1c458af60d5d810b2e8b2b0035bf5bf4f`
- secp ethereum exact hash: `fa810dee4c4bfc61000ce3f239582bb3a834d483`
- Solana exact hash: `89dfcdfe8986448bf0ca1f5bc1720de5ad66104c`
- TON short exact full-output record: `TON(v3r1):dab923287a62ea710c205f46362db01545714943bf5ddffcd8a783c21d8e78e9`
- TON all exact full-output record: `TON(v4r1):0b9fddc606dca709377394f6bb88c045bd84983cc640dddaf75668dd64097ae3`
- `-d_type 4` exact hash: `4fd01a8da7097495668c9ee9499084bc5680199a`

## Acceptance

The active tree is acceptable only when:

- the build is green
- the CTest suite is green
- validation scripts are green
- the no-fallback checks are green
- the build-purity scans are green
- the packaged Metal runtime assets are present beside the executable

## Notes

- The maintained public path is macOS through Metal, with primary validation on Apple Silicon.
- The public validation surface is intentionally recovery-focused.
- The default bounded recovery path now reports live candidates per second, hashes per second, tested counters, checksum-valid counters, and found counters during longer runs.
