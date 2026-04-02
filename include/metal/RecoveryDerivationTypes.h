#pragma once

#include "metal/RecoveryDeviceSupport.h"

typedef struct REC_ALIGN(16) {
    cmr_u8 key[32];
    cmr_u8 chain_code[32];
} extended_private_key_t;

typedef struct REC_ALIGN(16) {
    cmr_u8 key[64];
    cmr_u8 chain_code[32];
} extended_public_key_t;

typedef struct REC_ALIGN(16) {
    cmr_u64 inner_H[8];
    cmr_u64 outer_H[8];
} hmac_sha512_precomp_t;
