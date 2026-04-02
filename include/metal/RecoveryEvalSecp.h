#pragma once

#include "metal/RecoveryMetalTypes.h"

#if !defined(__METAL_VERSION__)
#include <cstddef>
#endif

#define RECOVERY_SECP_MAX_DERIVATION_SEGMENTS 64u
#define RECOVERY_SECP_FLAG_EMIT_ALL 0x80000000u

enum RecoverySecpTargetBit : cmr_u32 {
    RecoverySecpTargetBitCompressed   = 1u << 0u,
    RecoverySecpTargetBitUncompressed = 1u << 1u,
    RecoverySecpTargetBitSegwit       = 1u << 2u,
    RecoverySecpTargetBitTaproot      = 1u << 3u,
    RecoverySecpTargetBitEth          = 1u << 4u,
    RecoverySecpTargetBitXPoint       = 1u << 5u,
};

struct RecoveryEvalSecpKernelParams {
    cmr_u32 record_count = 0u;
    cmr_u32 out_capacity = 0u;
    cmr_u32 target_mask = 0u;
    cmr_u32 derivation_type_mask = 0u;
    cmr_u32 flags = 0u;
    cmr_u32 passphrase_count = 0u;
    cmr_u32 words_count = 0u;
    cmr_u32 target_len = 0u;
    cmr_u8 target_bytes[32] = { 0 };
    cmr_u32 precompute_pitch = 0u;
};

struct RecoverySecpTargetConfig {
    cmr_u32 target_mask = 0u;
    cmr_u32 derivation_type_mask = 0u;
    cmr_u32 target_len = 0u;
    cmr_u32 flags = 0u;
    cmr_u8 target_bytes[32] = { 0 };
    cmr_u32 reserved = 0u;
};

struct RecoverySecpDerivationProgram {
    cmr_u32 path_words[RECOVERY_SECP_MAX_DERIVATION_SEGMENTS];
    cmr_u32 path_word_count = 0u;
    cmr_u32 derivation_index = 0u;
    cmr_u32 derivation_type = RESULT_DERIVATION_BIP32_SECP256K1;
    cmr_u32 coin_type = 0u;
    cmr_u32 passphrase_index = 0u;
    cmr_u32 flags = 0u;
    cmr_u32 reserved = 0u;
};

struct RecoverySecpEvalRecord {
    FoundRecord found;
    cmr_u8 private_key[32];
    cmr_u8 public_key[65];
    cmr_u8 taproot_xonly[32];
    cmr_u32 private_key_ready = 0u;
    cmr_u32 public_key_ready = 0u;
    cmr_u32 derivation_ready = 0u;
    cmr_u32 target_ready = 0u;
};

#if defined(__METAL_VERSION__)
static inline cmr_u32 recovery_secp_program_path_count(const thread RecoverySecpDerivationProgram& program) {
    return program.path_word_count < RECOVERY_SECP_MAX_DERIVATION_SEGMENTS
        ? program.path_word_count
        : RECOVERY_SECP_MAX_DERIVATION_SEGMENTS;
}

static inline cmr_u32 recovery_secp_program_path_component(const thread RecoverySecpDerivationProgram& program, const cmr_u32 index) {
    if (index >= recovery_secp_program_path_count(program)) {
        return 0u;
    }
    return program.path_words[index];
}

static inline bool recovery_secp_program_component_is_hardened(const cmr_u32 component) {
    return (component & 0x80000000u) != 0u;
}

static inline cmr_u32 recovery_secp_program_component_index(const cmr_u32 component) {
    return component & 0x7FFFFFFFu;
}
#else
static inline cmr_u32 recovery_secp_program_path_count(const RecoverySecpDerivationProgram& program) {
    return program.path_word_count < RECOVERY_SECP_MAX_DERIVATION_SEGMENTS
        ? program.path_word_count
        : RECOVERY_SECP_MAX_DERIVATION_SEGMENTS;
}

static inline cmr_u32 recovery_secp_program_path_component(const RecoverySecpDerivationProgram& program, const cmr_u32 index) {
    if (index >= recovery_secp_program_path_count(program)) {
        return 0u;
    }
    return program.path_words[index];
}

static inline bool recovery_secp_program_component_is_hardened(const cmr_u32 component) {
    return (component & 0x80000000u) != 0u;
}

static inline cmr_u32 recovery_secp_program_component_index(const cmr_u32 component) {
    return component & 0x7FFFFFFFu;
}
#endif

static inline cmr_u32 recovery_secp_target_mask_for_coin_type(const cmr_u32 coin_type) {
    switch (recovery_decode_base_type(coin_type)) {
    case 0x01u: return RecoverySecpTargetBitUncompressed;
    case 0x02u: return RecoverySecpTargetBitCompressed;
    case 0x03u: return RecoverySecpTargetBitSegwit;
    case 0x04u: return RecoverySecpTargetBitTaproot;
    case 0x05u: return RecoverySecpTargetBitXPoint;
    case 0x06u: return RecoverySecpTargetBitEth;
    default:    return 0u;
    }
}

static inline bool recovery_secp_target_uses_hash160(const cmr_u32 coin_type) {
    switch (recovery_decode_base_type(coin_type)) {
    case 0x01u:
    case 0x02u:
    case 0x03u:
    case 0x06u:
        return true;
    default:
        return false;
    }
}

static inline bool recovery_secp_target_uses_32_bytes(const cmr_u32 coin_type) {
    switch (recovery_decode_base_type(coin_type)) {
    case 0x04u:
    case 0x05u:
        return true;
    default:
        return false;
    }
}

static inline cmr_u32 recovery_secp_target_default_match_len(const cmr_u32 coin_type) {
    return recovery_match_size_for_type(coin_type);
}

static inline cmr_u32 recovery_secp_target_default_derivation_type(const cmr_u32 coin_type) {
    return recovery_default_derivation_type_for_type(coin_type);
}

static inline bool recovery_secp_target_enabled(const cmr_u32 target_mask, const cmr_u32 coin_type) {
    return (target_mask & recovery_secp_target_mask_for_coin_type(coin_type)) != 0u;
}

static inline bool recovery_secp_derivation_type_enabled(const cmr_u32 derivation_type_mask, const cmr_u32 derivation_type) {
    if (derivation_type_mask == 0u) {
        return true;
    }
    if (derivation_type > 31u) {
        return false;
    }
    return (derivation_type_mask & (1u << derivation_type)) != 0u;
}

static inline cmr_u32 recovery_secp_target_expected_match_len(const cmr_u32 target_len, const cmr_u32 coin_type) {
    const cmr_u32 expected = target_len != 0u ? target_len : recovery_secp_target_default_match_len(coin_type);
    return expected > 32u ? 32u : expected;
}

static inline bool recovery_secp_target_len_matches(const cmr_u32 target_len, const cmr_u32 record_match_len, const cmr_u32 coin_type) {
    return record_match_len == recovery_secp_target_expected_match_len(target_len, coin_type);
}

#if defined(__METAL_VERSION__)
static inline bool recovery_secp_program_is_bip32_path(const thread RecoverySecpDerivationProgram& program) {
    return recovery_secp_program_path_count(program) > 0u;
}

static inline bool recovery_secp_program_has_hardened_component(const thread RecoverySecpDerivationProgram& program) {
    const cmr_u32 count = recovery_secp_program_path_count(program);
    for (cmr_u32 i = 0u; i < count; ++i) {
        if (recovery_secp_program_component_is_hardened(program.path_words[i])) {
            return true;
        }
    }
    return false;
}

static inline bool recovery_secp_program_is_valid_child_index(const thread RecoverySecpDerivationProgram& program) {
    const cmr_u32 count = recovery_secp_program_path_count(program);
    if (count == 0u) {
        return false;
    }
    const cmr_u32 last_component = program.path_words[count - 1u];
    return recovery_secp_program_component_index(last_component) <= 0x7FFFFFFFu;
}

static inline bool recovery_secp_target_len_matches(const cmr_u32 target_len, const cmr_u32 record_match_len) {
    if (target_len == 0u) {
        return true;
    }
    return record_match_len == target_len;
}

static inline cmr_u32 recovery_secp_kernel_seed_count(const thread RecoveryEvalSecpKernelParams& params) {
    return params.passphrase_count;
}

static inline cmr_u32 recovery_secp_kernel_program_count(const thread RecoveryEvalSecpKernelParams& params) {
    return params.words_count;
}
#else
static inline bool recovery_secp_program_is_bip32_path(const RecoverySecpDerivationProgram& program) {
    return recovery_secp_program_path_count(program) > 0u;
}

static inline bool recovery_secp_program_has_hardened_component(const RecoverySecpDerivationProgram& program) {
    const cmr_u32 count = recovery_secp_program_path_count(program);
    for (cmr_u32 i = 0u; i < count; ++i) {
        if (recovery_secp_program_component_is_hardened(program.path_words[i])) {
            return true;
        }
    }
    return false;
}

static inline bool recovery_secp_program_is_valid_child_index(const RecoverySecpDerivationProgram& program) {
    const cmr_u32 count = recovery_secp_program_path_count(program);
    if (count == 0u) {
        return false;
    }
    const cmr_u32 last_component = program.path_words[count - 1u];
    return recovery_secp_program_component_index(last_component) <= 0x7FFFFFFFu;
}

static inline bool recovery_secp_target_len_matches(const cmr_u32 target_len, const cmr_u32 record_match_len) {
    if (target_len == 0u) {
        return true;
    }
    return record_match_len == target_len;
}

static inline cmr_u32 recovery_secp_kernel_seed_count(const RecoveryEvalSecpKernelParams& params) {
    return params.passphrase_count;
}

static inline cmr_u32 recovery_secp_kernel_program_count(const RecoveryEvalSecpKernelParams& params) {
    return params.words_count;
}
#endif

#if !defined(__METAL_VERSION__)
static_assert(sizeof(RecoverySecpTargetConfig) == 52u, "RecoverySecpTargetConfig layout mismatch");
static_assert(sizeof(RecoverySecpDerivationProgram) == 284u, "RecoverySecpDerivationProgram layout mismatch");
static_assert(sizeof(RecoverySecpEvalRecord) == 448u, "RecoverySecpEvalRecord layout mismatch");
static_assert(alignof(RecoverySecpTargetConfig) == 4u, "RecoverySecpTargetConfig alignment mismatch");
static_assert(alignof(RecoverySecpDerivationProgram) == 4u, "RecoverySecpDerivationProgram alignment mismatch");
static_assert(alignof(RecoverySecpEvalRecord) == 8u, "RecoverySecpEvalRecord alignment mismatch");
static_assert(offsetof(RecoverySecpDerivationProgram, path_word_count) == 256u, "RecoverySecpDerivationProgram.path_word_count offset mismatch");
static_assert(offsetof(RecoverySecpDerivationProgram, derivation_index) == 260u, "RecoverySecpDerivationProgram.derivation_index offset mismatch");
static_assert(offsetof(RecoverySecpDerivationProgram, derivation_type) == 264u, "RecoverySecpDerivationProgram.derivation_type offset mismatch");
static_assert(offsetof(RecoverySecpDerivationProgram, coin_type) == 268u, "RecoverySecpDerivationProgram.coin_type offset mismatch");
static_assert(offsetof(RecoverySecpDerivationProgram, passphrase_index) == 272u, "RecoverySecpDerivationProgram.passphrase_index offset mismatch");
#endif
