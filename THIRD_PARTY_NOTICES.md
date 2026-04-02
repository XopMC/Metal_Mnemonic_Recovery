# Third-Party Notices

`Metal_Mnemonic_Recovery` bundles or derives code and data from upstream and third-party components. Their notices and license obligations must remain available in source and binary distributions.

## Project Origin

This repository is the Metal/macOS adaptation of [XopMC/CUDA_Mnemonic_Recovery](https://github.com/XopMC/CUDA_Mnemonic_Recovery). Public documentation should preserve that attribution.

## Notable Components

| Component | Location | Purpose | Origin / notice |
| --- | --- | --- | --- |
| Embedded wordlists | `include/recovery/RecoveryWordlistsEmbedded.h` | bundled BIP39 recovery dictionaries | bundled data used by the recovery CLI |
| SHA-256 implementation | `third_party/hash/sha256.cpp` | public hash formatting and checks | derived from VanitySearch; GPL notice retained in file headers |
| secp256k1 support code | `third_party/secp256k1/` | secp256k1 arithmetic, precompute data, and Metal evaluation support | adapted from secp256k1-oriented sources; bundled files include MIT-licensed material such as `secp256k1_modinv32.h` |
| Bloom/XOR filter support | `src/crypto/filter.cpp`, `include/recovery/filter.h` | target filtering support | integrated filter support used by the public recovery flow |
| ed25519 support code | `third_party/ed25519/` | ed25519 derivation and key support used by the Metal runtime | based on `ed25519-donna` / `curve25519-donna` style sources; public-domain notices retained in bundled headers |
