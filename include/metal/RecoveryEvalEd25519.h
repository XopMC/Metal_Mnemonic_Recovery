#pragma once

#include "metal/RecoveryMetalTypes.h"

#if !defined(__METAL_VERSION__)
#include <cstddef>
#endif

#define RECOVERY_ED25519_TARGET_FLAG_SOLANA 0x00000001u
#define RECOVERY_ED25519_TARGET_FLAG_TON_SHORT 0x00000002u
#define RECOVERY_ED25519_TARGET_FLAG_TON_ALL 0x00000004u
#define RECOVERY_ED25519_TARGET_FLAG_EMIT_ALL 0x80000000u
#define RECOVERY_ED25519_MAX_XOR_FILTERS 25u

#define RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS 64u
#define RECOVERY_ED25519_DERIVATION_FLAG_SECP256K1 0x00000001u
#define RECOVERY_ED25519_DERIVATION_FLAG_SLIP0010 0x00000002u
#define RECOVERY_ED25519_DERIVATION_FLAG_ED25519_BIP32_TEST 0x00000004u
#define RECOVERY_ED25519_DERIVATION_FLAG_ANY \
    (RECOVERY_ED25519_DERIVATION_FLAG_SECP256K1 | \
     RECOVERY_ED25519_DERIVATION_FLAG_SLIP0010 | \
     RECOVERY_ED25519_DERIVATION_FLAG_ED25519_BIP32_TEST)

struct RecoveryEd25519ExtendedPrivateKey {
    cmr_u8 key[32] = { 0 };
    cmr_u8 chain_code[32] = { 0 };
};

struct RecoveryEd25519DerivationProgram {
    cmr_u32 path_words[RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS] = { 0 };
    cmr_u32 path_word_count = 0u;
    cmr_u32 derivation_index = 0u;
    cmr_u32 derivation_type = RESULT_DERIVATION_SLIP0010_ED25519;
    cmr_u32 coin_type = 0u;
    cmr_u32 passphrase_index = 0u;
    cmr_u32 flags = 0u;
    cmr_u32 reserved = 0u;
};

struct RecoveryEd25519StageKernelParams {
    cmr_u32 record_count = 0u;
    cmr_u32 out_capacity = 0u;
    cmr_u32 seed_count = 0u;
    cmr_u32 program_count = 0u;
};

struct RecoveryEd25519EvalParams {
    cmr_u32 candidate_count = 0u;
    cmr_u32 target_flags = 0u;
    cmr_u32 derivation_type = RESULT_DERIVATION_SLIP0010_ED25519;
    cmr_u32 derivation_type_mask = RECOVERY_ED25519_DERIVATION_FLAG_ANY;
    cmr_u32 out_capacity = 0u;
    cmr_u32 match_len = 0u;
    cmr_u32 derivation_index = 0u;
    cmr_i64 round_delta = 0;
    cmr_u32 passphrase_index = 0u;
    cmr_u32 reserved = 0u;
    cmr_u8 target_bytes[32] = { 0 };
};

struct RecoveryEd25519EvalRecord {
    FoundRecord found;
    cmr_u8 public_key[32];
    cmr_u32 public_key_ready = 0u;
};

struct RecoveryEd25519StageRecord {
    FoundRecord found;
    RecoveryEd25519ExtendedPrivateKey private_key;
    cmr_u8 public_key[32];
    cmr_u32 private_key_ready = 0u;
    cmr_u32 public_key_ready = 0u;
    cmr_u32 reserved = 0u;
};

struct RecoveryFilterParams {
    cmr_u32 bloom_enabled = 0u;
    cmr_u32 xor_count = 0u;
    cmr_u32 reserved0 = 0u;
    cmr_u32 reserved1 = 0u;
    cmr_u64 xor_seed = 0ull;
    cmr_u64 xor_buffer_offset[RECOVERY_ED25519_MAX_XOR_FILTERS] = { 0 };
    cmr_u64 xor_array_length[RECOVERY_ED25519_MAX_XOR_FILTERS] = { 0 };
    cmr_u64 xor_segment_count_length[RECOVERY_ED25519_MAX_XOR_FILTERS] = { 0 };
    cmr_u64 xor_segment_length[RECOVERY_ED25519_MAX_XOR_FILTERS] = { 0 };
    cmr_u64 xor_segment_length_mask[RECOVERY_ED25519_MAX_XOR_FILTERS] = { 0 };
};

#if defined(__METAL_VERSION__)
static inline cmr_u32 recovery_ed25519_program_path_count(const thread RecoveryEd25519DerivationProgram& program) {
    return program.path_word_count < RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS
        ? program.path_word_count
        : RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS;
}

static inline cmr_u32 recovery_ed25519_program_path_component(const thread RecoveryEd25519DerivationProgram& program, const cmr_u32 index) {
    if (index >= recovery_ed25519_program_path_count(program)) {
        return 0u;
    }
    return program.path_words[index];
}
#else
static inline cmr_u32 recovery_ed25519_program_path_count(const RecoveryEd25519DerivationProgram& program) {
    return program.path_word_count < RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS
        ? program.path_word_count
        : RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS;
}

static inline cmr_u32 recovery_ed25519_program_path_component(const RecoveryEd25519DerivationProgram& program, const cmr_u32 index) {
    if (index >= recovery_ed25519_program_path_count(program)) {
        return 0u;
    }
    return program.path_words[index];
}
#endif

static inline bool recovery_ed25519_program_component_is_hardened(const cmr_u32 component) {
    return (component & 0x80000000u) != 0u;
}

static inline cmr_u32 recovery_ed25519_program_component_index(const cmr_u32 component) {
    return component & 0x7FFFFFFFu;
}

static inline cmr_u32 recovery_ed25519_derivation_flag_for_type(const cmr_u32 derivation_type) {
    switch (derivation_type) {
    case RESULT_DERIVATION_BIP32_SECP256K1:
        return RECOVERY_ED25519_DERIVATION_FLAG_SECP256K1;
    case RESULT_DERIVATION_SLIP0010_ED25519:
        return RECOVERY_ED25519_DERIVATION_FLAG_SLIP0010;
    case RESULT_DERIVATION_ED25519_BIP32_TEST:
        return RECOVERY_ED25519_DERIVATION_FLAG_ED25519_BIP32_TEST;
    default:
        return 0u;
    }
}

static inline bool recovery_ed25519_derivation_enabled(const cmr_u32 mask, const cmr_u32 derivation_type) {
    const cmr_u32 flag = recovery_ed25519_derivation_flag_for_type(derivation_type);
    if (flag == 0u) {
        return false;
    }
    return (mask == 0u) ? true : ((mask & flag) != 0u);
}

static inline cmr_u32 recovery_ed25519_default_target_match_len(const cmr_u32 coin_type) {
    return recovery_match_size_for_type(coin_type);
}

static inline cmr_u32 recovery_ed25519_default_derivation_type(const cmr_u32 coin_type) {
    return recovery_default_derivation_type_for_type(coin_type);
}

#if !defined(__METAL_VERSION__)
static_assert(sizeof(RecoveryEd25519ExtendedPrivateKey) == 64u, "RecoveryEd25519ExtendedPrivateKey layout mismatch");
static_assert(sizeof(RecoveryEd25519DerivationProgram) == 284u, "RecoveryEd25519DerivationProgram layout mismatch");
static_assert(sizeof(RecoveryEd25519StageKernelParams) == 16u, "RecoveryEd25519StageKernelParams layout mismatch");
static_assert(sizeof(RecoveryEd25519EvalParams) == 80u, "RecoveryEd25519EvalParams layout mismatch");
static_assert(sizeof(RecoveryEd25519EvalRecord) == 336u, "RecoveryEd25519EvalRecord layout mismatch");
static_assert(sizeof(RecoveryEd25519StageRecord) == 408u, "RecoveryEd25519StageRecord layout mismatch");
static_assert(sizeof(RecoveryFilterParams) == 1024u, "RecoveryFilterParams layout mismatch");
static_assert(alignof(RecoveryEd25519DerivationProgram) == 4u, "RecoveryEd25519DerivationProgram alignment mismatch");
static_assert(alignof(RecoveryEd25519StageKernelParams) == 4u, "RecoveryEd25519StageKernelParams alignment mismatch");
static_assert(alignof(RecoveryEd25519EvalParams) == 8u, "RecoveryEd25519EvalParams alignment mismatch");
static_assert(alignof(RecoveryEd25519EvalRecord) == 8u, "RecoveryEd25519EvalRecord alignment mismatch");
static_assert(alignof(RecoveryEd25519StageRecord) == 8u, "RecoveryEd25519StageRecord alignment mismatch");
static_assert(alignof(RecoveryFilterParams) == 8u, "RecoveryFilterParams alignment mismatch");
static_assert(offsetof(RecoveryEd25519DerivationProgram, path_word_count) == 256u, "RecoveryEd25519DerivationProgram.path_word_count offset mismatch");
static_assert(offsetof(RecoveryEd25519DerivationProgram, derivation_index) == 260u, "RecoveryEd25519DerivationProgram.derivation_index offset mismatch");
static_assert(offsetof(RecoveryEd25519DerivationProgram, derivation_type) == 264u, "RecoveryEd25519DerivationProgram.derivation_type offset mismatch");
static_assert(offsetof(RecoveryEd25519DerivationProgram, coin_type) == 268u, "RecoveryEd25519DerivationProgram.coin_type offset mismatch");
static_assert(offsetof(RecoveryEd25519DerivationProgram, passphrase_index) == 272u, "RecoveryEd25519DerivationProgram.passphrase_index offset mismatch");
static_assert(offsetof(RecoveryEd25519EvalParams, round_delta) == 32u, "RecoveryEd25519EvalParams.round_delta offset mismatch");
static_assert(offsetof(RecoveryEd25519EvalParams, target_bytes) == 48u, "RecoveryEd25519EvalParams.target_bytes offset mismatch");
static_assert(offsetof(RecoveryEd25519StageRecord, private_key) == 296u, "RecoveryEd25519StageRecord.private_key offset mismatch");
static_assert(offsetof(RecoveryEd25519StageRecord, public_key) == 360u, "RecoveryEd25519StageRecord.public_key offset mismatch");
static_assert(offsetof(RecoveryFilterParams, xor_seed) == 16u, "RecoveryFilterParams.xor_seed offset mismatch");
static_assert(offsetof(RecoveryFilterParams, xor_buffer_offset) == 24u, "RecoveryFilterParams.xor_buffer_offset offset mismatch");
static_assert(offsetof(RecoveryFilterParams, xor_array_length) == 224u, "RecoveryFilterParams.xor_array_length offset mismatch");
#endif
