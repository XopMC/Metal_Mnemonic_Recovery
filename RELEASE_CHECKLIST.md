# Release Checklist

## Source Tree

- Confirm the repository presents itself as `Metal_Mnemonic_Recovery`
- Confirm the README documents only the supported macOS and Metal release path
- Confirm the README explicitly credits the project as a full Metal adaptation of `CUDA_Mnemonic_Recovery`
- Confirm no generated `out/`, archives, crash logs, or watchdog artifacts are tracked

## Build And Validation

- `cmake --preset macos-metal-release`
- `cmake --build out/build/macos-metal-release -j4`
- `ctest --test-dir out/build/macos-metal-release --output-on-failure`
- `bash ./scripts/validate_release_macos.sh`
- `bash ./tests/no_fallback_macos.sh`
- `bash ./tests/build_purity_macos.sh`
- `bash ./tests/build_purity_unified_macos.sh`

## Local Release Bundle

- `cmake --install out/build/macos-metal-release --prefix out/release/Metal_Mnemonic_Recovery-macos`
- Confirm `bin/Metal_Mnemonic_Recovery`, `ChecksumKernels.metallib`, and `secp-precompute-v1.bin` exist in the staged bundle
- Confirm `README.md`, `LICENSE.txt`, `THIRD_PARTY_NOTICES.md`, `RESPONSIBLE_USE.md`, `SECURITY.md`, `SUPPORT.md`, and `examples/` are present in the staged release folder
- Run one exact-hash recovery command from the staged bundle

## GitHub Surface

- Confirm `.github/workflows/` only describes honest macOS and Metal CI behavior
- Confirm the repository is private if publishing a non-public staging copy
- Confirm the default branch is `main`
