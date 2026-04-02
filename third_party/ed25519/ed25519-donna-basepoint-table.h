#pragma once
#if !defined(__METAL_VERSION__)
#include <cstdint>
#endif
/* multiples of the base point in packed {ysubx, xaddy, t2d} form */
#if defined(__METAL_VERSION__)
extern constant const uint8_t REC_ALIGN(16) ge25519_niels_base_multiples[256][96];
#else
extern REC_DEVICE  const uint8_t REC_ALIGN(16) ge25519_niels_base_multiples[256][96];
#endif
