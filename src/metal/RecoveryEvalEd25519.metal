#include <metal_stdlib>
using namespace metal;

#include "metal/RecoveryCryptoCommon.h"
#include "metal/RecoveryEvalEd25519.h"
#include "metal/RecoveryEvalSecp.h"
#include "third_party/ed25519/ed25519.inc"

// Metal eval/staging layer for ed25519 target families:
// exact target-family matching, TON wallet hashes, and FoundRecord shaping.

constant RecoveryFilterParams kRecoveryEmptyFilterParams = {};
constant RecoveryFilterParams kRecoveryBloomOnlyFilterParams = {
    1u, 0u, 0u, 0u, 0ull
};

constant cmr_u8 kTonV5r1RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x06, 0x00, 0x00,
    0x20, 0x83, 0x4B, 0x7B, 0x72, 0xB1, 0x12, 0x14,
    0x7E, 0x1B, 0x2F, 0xB4, 0x57, 0xB8, 0x4E, 0x74,
    0xD1, 0xA3, 0x0F, 0x04, 0xF7, 0x37, 0xD4, 0xF6,
    0x2A, 0x66, 0x8E, 0x95, 0x52, 0xD2, 0xB7, 0x2F
};
constant cmr_u8 kTonV4r2RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x07, 0x00, 0x00,
    0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d,
    0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
    0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8,
    0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0
};
constant cmr_u8 kTonV4r1RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x07, 0x00, 0x00,
    0x64, 0xdd, 0x54, 0x80, 0x55, 0x22, 0xc5, 0xbe, 0x8a, 0x9d, 0xb5, 0x9c, 0xea, 0x01, 0x05, 0xcc,
    0xf0, 0xd0, 0x87, 0x86, 0xca, 0x79, 0xbe, 0xb8, 0xcb, 0x79, 0xe8, 0x80, 0xa8, 0xd7, 0x32, 0x2d
};
constant cmr_u8 kTonV4DataHeader[6] = { 0x00, 0x51, 0x00, 0x00, 0x00, 0x00 };
constant cmr_u8 kTonDataTail[1] = { 0x40 };
constant cmr_u8 kTonV3r2RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0x84, 0xda, 0xfa, 0x44, 0x9f, 0x98, 0xa6, 0x98, 0x77, 0x89, 0xba, 0x23, 0x23, 0x58, 0x07, 0x2b, 0xc0, 0xf7, 0x6d, 0xc4, 0x52, 0x40, 0x02, 0xa5, 0xd0, 0x91, 0x8b, 0x9a, 0x75, 0xd2, 0xd5, 0x99
};
constant cmr_u8 kTonV3r1RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0xb6, 0x10, 0x41, 0xa5, 0x8a, 0x79, 0x80, 0xb9, 0x46, 0xe8, 0xfb, 0x9e, 0x19, 0x8e, 0x3c, 0x90,
    0x4d, 0x24, 0x79, 0x9f, 0xfa, 0x36, 0x57, 0x4e, 0xa4, 0x25, 0x1c, 0x41, 0xa5, 0x66, 0xf5, 0x81
};
constant cmr_u8 kTonV2r1RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0x9A, 0x5E, 0x68, 0xC1, 0x08, 0xE1, 0x87,
    0x21, 0xA0, 0x7C, 0x42, 0xF9, 0x95, 0x6B, 0xFB,
    0x39, 0xAD, 0x77, 0xEC, 0x6D, 0x62, 0x4B, 0x60,
    0xC5, 0x76, 0xEC, 0x88, 0xEE, 0xE6, 0x53, 0x29
};
constant cmr_u8 kTonV2r2RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0xFE, 0x95, 0x30, 0xD3, 0x24, 0x38, 0x53, 0x08,
    0x3E, 0xF2, 0xEF, 0x0B, 0x4C, 0x29, 0x08, 0xC0,
    0xAB, 0xF6, 0xFA, 0x1C, 0x31, 0xEA, 0x24, 0x3A,
    0xAC, 0xAA, 0x5B, 0xF8, 0xC7, 0xD7, 0x53, 0xF1
};
constant cmr_u8 kTonV1r1RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0xA0, 0xCF, 0xC2, 0xC4, 0x8A, 0xEE, 0x16, 0xA2,
    0x71, 0xF2, 0xCF, 0xC0, 0xB7, 0x38, 0x2D, 0x81,
    0x75, 0x6C, 0xEC, 0xB1, 0x01, 0x7D, 0x07, 0x7F,
    0xAA, 0xAB, 0x3B, 0xB6, 0x02, 0xF6, 0x86, 0x8C
};
constant cmr_u8 kTonV1r2RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0xD4, 0x90, 0x2F, 0xCC, 0x9F, 0xAD, 0x74, 0x69,
    0x8F, 0xA8, 0xE3, 0x53, 0x22, 0x0A, 0x68, 0xDA,
    0x0D, 0xCF, 0x72, 0xE3, 0x2B, 0xCB, 0x2E, 0xB9,
    0xEE, 0x04, 0x21, 0x7C, 0x17, 0xD3, 0x06, 0x2C
};
constant cmr_u8 kTonV1r3RootHeader[39] = {
    0x02, 0x01, 0x34, 0x00, 0x00, 0x00, 0x00,
    0x58, 0x7C, 0xC7, 0x89, 0xEF, 0xF1, 0xC8, 0x4F,
    0x46, 0xEC, 0x37, 0x97, 0xE4, 0x5F, 0xC8, 0x09,
    0xA1, 0x4F, 0xF5, 0xAE, 0x24, 0xF1, 0xE0, 0xC7,
    0xA6, 0xA9, 0x9C, 0xC9, 0xDC, 0x90, 0x61, 0xFF
};
constant cmr_u8 kTonV2DataHeader[6] = { 0x00, 0x48, 0x00, 0x00, 0x00, 0x00 };
constant cmr_u8 kTonV1DataHeader[6] = { 0x00, 0x48, 0x00, 0x00, 0x00, 0x00 };
constant cmr_u8 kTonV3DataHeader[6] = { 0x00, 0x50, 0x00, 0x00, 0x00, 0x00 };
constant cmr_u32 kTonSubwalletId = 698983191u;
constant cmr_u32 kTonSubwalletIdV5 = 2147483409u;

REC_DEVICE void sha512_Transform(const thread uint64_t* state_in, const thread uint64_t* data, thread uint64_t* state_out) {
    thread cmr_u8 block[128];
    for (cmr_u32 i = 0u; i < 16u; ++i) {
        recovery_sha512_store_be64(data[i], block + (i * 8u));
    }
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        state_out[i] = state_in[i];
    }
    recovery_sha512_compress(state_out, block);
}

REC_DEVICE void sha512_Init(thread SHA512_CTX* context) {
    recovery_zero_thread_bytes(reinterpret_cast<thread cmr_u8*>(context), sizeof(SHA512_CTX));
    context->state[0] = 0x6a09e667f3bcc908ull;
    context->state[1] = 0xbb67ae8584caa73bull;
    context->state[2] = 0x3c6ef372fe94f82bull;
    context->state[3] = 0xa54ff53a5f1d36f1ull;
    context->state[4] = 0x510e527fade682d1ull;
    context->state[5] = 0x9b05688c2b3e6c1full;
    context->state[6] = 0x1f83d9abfb41bd6bull;
    context->state[7] = 0x5be0cd19137e2179ull;
    context->bitcount[0] = 0ull;
    context->bitcount[1] = 0ull;
}

REC_DEVICE void sha512_Update(thread SHA512_CTX* context, const thread uint8_t* data, size_t len) {
    if (data == nullptr || len == 0u) {
        return;
    }

    context->bitcount[0] += static_cast<uint64_t>(len);
    thread cmr_u8* buffer = reinterpret_cast<thread cmr_u8*>(context->buffer);
    cmr_u32 buffer_len = static_cast<cmr_u32>(context->bitcount[1]);
    cmr_u32 offset = 0u;

    if (buffer_len > 0u) {
        const cmr_u32 space = 128u - buffer_len;
        const cmr_u32 take = cmr_u32(len) < space ? cmr_u32(len) : space;
        recovery_copy_thread_bytes(buffer + buffer_len, data, take);
        buffer_len += take;
        offset += take;
        if (buffer_len == 128u) {
            recovery_sha512_compress(context->state, buffer);
            buffer_len = 0u;
        }
    }

    while ((offset + 128u) <= len) {
        recovery_sha512_compress(context->state, data + offset);
        offset += 128u;
    }

    if (offset < len) {
        const cmr_u32 remaining = cmr_u32(len) - offset;
        recovery_copy_thread_bytes(buffer, data + offset, remaining);
        buffer_len = remaining;
    }

    context->bitcount[1] = buffer_len;
}

REC_DEVICE void sha512_Final(thread SHA512_CTX* context, uint8_t digest[SHA512_DIGEST_LENGTH]) {
    thread cmr_u8 block[128];
    recovery_zero_thread_bytes(block, 128u);
    const cmr_u32 buffer_len = static_cast<cmr_u32>(context->bitcount[1]);
    recovery_copy_thread_bytes(block, reinterpret_cast<const thread cmr_u8*>(context->buffer), buffer_len);
    block[buffer_len] = 0x80u;

    if (buffer_len >= 112u) {
        recovery_sha512_compress(context->state, block);
        recovery_zero_thread_bytes(block, 128u);
    }

    const cmr_u64 bit_len = context->bitcount[0] * 8u;
    recovery_sha512_store_be64(0u, block + 112u);
    recovery_sha512_store_be64(bit_len, block + 120u);
    recovery_sha512_compress(context->state, block);

    for (cmr_u32 i = 0u; i < 8u; ++i) {
        recovery_sha512_store_be64(context->state[i], digest + (i * 8u));
    }
}

REC_DEVICE void sha512_Raw(const thread uint8_t* data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]) {
    SHA512_CTX ctx;
    sha512_Init(&ctx);
    sha512_Update(&ctx, data, len);
    sha512_Final(&ctx, digest);
}

static inline void recovery_ed25519_public_key_from_private(const thread cmr_u8 private_key[32], thread cmr_u8 public_key[32]) {
    thread cmr_u8 private_key_copy[32];
    recovery_copy_thread_bytes(private_key_copy, private_key, 32u);
    ed25519_key_to_pub(private_key_copy, public_key);
}

static inline bool recovery_eq_literal(const constant char* lhs, const constant char* rhs) {
    if (lhs == nullptr || rhs == nullptr) {
        return false;
    }

    while (true) {
        const char a = *lhs++;
        const char b = *rhs++;
        if (a != b) {
            return false;
        }
        if (a == '\0') {
            return true;
        }
    }
}

constant char kRecoveryEd25519SeedLabel[] = "ed25519 seed";

static inline void recovery_ed25519_master_from_seed(
    const thread cmr_u8 seed[64],
    thread RecoveryEd25519ExtendedPrivateKey* out_master) {

    thread cmr_u8 digest[64];
    thread cmr_u8 key_label[12];
    recovery_copy_constant_to_thread_bytes(key_label, reinterpret_cast<const constant cmr_u8*>(kRecoveryEd25519SeedLabel), 12u);
    recovery_hmac_sha512(key_label, 12u, seed, 64u, digest);
    recovery_copy_thread_bytes(out_master->key, digest, 32u);
    recovery_copy_thread_bytes(out_master->chain_code, digest + 32u, 32u);
}

static inline void recovery_ed25519_hardened_child_from_private(
    const thread RecoveryEd25519ExtendedPrivateKey* parent,
    thread RecoveryEd25519ExtendedPrivateKey* child,
    const cmr_u32 hardened_child_number) {

    thread cmr_u8 hmac_input[40];
    hmac_input[0] = 0u;
    recovery_copy_thread_bytes(hmac_input + 1u, parent->key, 32u);
    hmac_input[33] = cmr_u8((hardened_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((hardened_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((hardened_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(hardened_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512(parent->chain_code, 32u, hmac_input, 37u, digest);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

static inline void recovery_ed25519_bip32_ckd_priv_hardened(
    const thread RecoveryEd25519ExtendedPrivateKey* parent,
    thread RecoveryEd25519ExtendedPrivateKey* child,
    const cmr_u32 i_hardened) {

    recovery_ed25519_hardened_child_from_private(parent, child, i_hardened | 0x80000000u);
}

static inline void recovery_ed25519_bip32_ckd_priv_normal_from_public_key(
    const thread RecoveryEd25519ExtendedPrivateKey* parent,
    const thread cmr_u8 parent_public_key[32],
    thread RecoveryEd25519ExtendedPrivateKey* child,
    const cmr_u32 i_normal) {

    thread cmr_u8 in_z[37];
    thread cmr_u8 in_i2[37];
    thread cmr_u8 z64[64];
    thread cmr_u8 i2[64];

    in_z[0] = 0x02u;
    in_i2[0] = 0x03u;
    recovery_copy_thread_bytes(in_z + 1u, parent_public_key, 32u);
    recovery_copy_thread_bytes(in_i2 + 1u, parent_public_key, 32u);
    in_z[33] = cmr_u8((i_normal >> 24u) & 0xFFu);
    in_z[34] = cmr_u8((i_normal >> 16u) & 0xFFu);
    in_z[35] = cmr_u8((i_normal >> 8u) & 0xFFu);
    in_z[36] = cmr_u8(i_normal & 0xFFu);
    recovery_copy_thread_bytes(in_i2 + 33u, in_z + 33u, 4u);

    recovery_hmac_sha512(parent->chain_code, 32u, in_z, 37u, z64);
    recovery_hmac_sha512(parent->chain_code, 32u, in_i2, 37u, i2);
    add_modL_from_bytes(child->key, parent->key, z64);
    recovery_copy_thread_bytes(child->chain_code, i2 + 32u, 32u);
}

static inline bool recovery_ed25519_stage_record_ready(const thread RecoveryEd25519StageRecord* stage) {
    return stage != nullptr && stage->private_key_ready != 0u && stage->public_key_ready != 0u;
}

static inline void recovery_ed25519_unswap_seed_words(
    const thread cmr_u32 master_words[RECOVERY_MASTER_WORDS],
    thread cmr_u8 out_seed[64]) {

    const thread cmr_u8* in_bytes = reinterpret_cast<const thread cmr_u8*>(master_words);
    for (cmr_u32 chunk = 0u; chunk < 8u; ++chunk) {
        const cmr_u32 base = chunk * 8u;
        for (cmr_u32 i = 0u; i < 8u; ++i) {
            out_seed[base + i] = in_bytes[base + (7u - i)];
        }
    }
}

static inline void recovery_ed25519_seed_record_to_stage_found(
    const thread MasterSeedRecord* source,
    const thread RecoveryEd25519DerivationProgram* program,
    thread RecoveryEd25519StageRecord* out_stage) {

    recovery_zero_thread_bytes((thread cmr_u8*)out_stage, sizeof(RecoveryEd25519StageRecord));
    out_stage->found.word_count = cmr_u32(source->hit.word_count);
    for (cmr_u32 i = 0u; i < out_stage->found.word_count && i < RECOVERY_MAX_WORDS; ++i) {
        out_stage->found.word_ids[i] = cmr_u32(source->hit.word_ids[i] & 0x07FFu);
    }
    out_stage->found.derivation_index = program->derivation_index;
    out_stage->found.derivation_type = program->derivation_type;
    out_stage->found.coin_type = program->coin_type;
    out_stage->found.match_len = source->hit.match_len != 0u ? source->hit.match_len : recovery_match_size_for_type(program->coin_type);
    out_stage->found.flags = source->hit.flags | RECOVERY_RECORD_FLAG_STAGE_READY | RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS;
    out_stage->found.round_delta = source->hit.round_delta;
    out_stage->found.passphrase_index = program->passphrase_index != 0u ? program->passphrase_index : source->hit.passphrase_index;
}

static inline bool recovery_ed25519_derive_stage_record(
    const thread MasterSeedRecord* source,
    const thread RecoveryEd25519DerivationProgram* program,
    thread RecoveryEd25519StageRecord* out_stage) {

    if (source == nullptr || program == nullptr || out_stage == nullptr) {
        return false;
    }
    if ((source->hit.flags & RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS) == 0u) {
        recovery_zero_thread_bytes((thread cmr_u8*)out_stage, sizeof(RecoveryEd25519StageRecord));
        return false;
    }

    recovery_ed25519_seed_record_to_stage_found(source, program, out_stage);

    thread cmr_u8 seed[64];
    recovery_ed25519_unswap_seed_words(source->master_words, seed);

    thread RecoveryEd25519ExtendedPrivateKey current;
    recovery_ed25519_master_from_seed(seed, &current);

    const cmr_u32 derivation_type = program->derivation_type;
    const cmr_u32 path_count = recovery_ed25519_program_path_count(*program);
    for (cmr_u32 i = 0u; i < path_count; ++i) {
        const cmr_u32 component = recovery_ed25519_program_path_component(*program, i);
        thread RecoveryEd25519ExtendedPrivateKey child;

        if (derivation_type == RESULT_DERIVATION_SLIP0010_ED25519) {
            if (!recovery_ed25519_program_component_is_hardened(component)) {
                return false;
            }
            recovery_ed25519_bip32_ckd_priv_hardened(&current, &child, recovery_ed25519_program_component_index(component));
        } else if (derivation_type == RESULT_DERIVATION_ED25519_BIP32_TEST) {
            if (recovery_ed25519_program_component_is_hardened(component)) {
                recovery_ed25519_bip32_ckd_priv_hardened(&current, &child, recovery_ed25519_program_component_index(component));
            } else {
                thread cmr_u8 parent_public_key[32];
                recovery_ed25519_public_key_from_private(current.key, parent_public_key);
                recovery_ed25519_bip32_ckd_priv_normal_from_public_key(
                    &current,
                    parent_public_key,
                    &child,
                    recovery_ed25519_program_component_index(component));
            }
        } else {
            return false;
        }

        current = child;
    }

    out_stage->private_key = current;
    out_stage->private_key_ready = 1u;
    recovery_copy_thread_bytes(out_stage->found.private_key, current.key, 32u);
    recovery_ed25519_public_key_from_private(current.key, out_stage->public_key);
    out_stage->public_key_ready = 1u;
    return true;
}

static inline cmr_u32 recovery_ed25519_resolve_derivation_type(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params) {

    if (source != nullptr && source->found.derivation_type != 0u) {
        return source->found.derivation_type;
    }
    if (params.derivation_type != 0u) {
        return params.derivation_type;
    }
    return recovery_default_derivation_type_for_type(source != nullptr ? source->found.coin_type : 0u);
}

static inline bool recovery_ed25519_derivation_allowed(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params) {

    return recovery_ed25519_derivation_enabled(
        params.derivation_type_mask,
        recovery_ed25519_resolve_derivation_type(source, params));
}

static inline bool recovery_prefix_matches(const thread cmr_u8* lhs, const constant cmr_u8* rhs, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }
    return true;
}

static inline void recovery_put_bit(thread cmr_u8* buf, thread cmr_u32* len, thread cmr_u8* cur, thread int* bitpos, const cmr_u32 bit) {
    *cur |= cmr_u8((bit & 1u) << (7 - *bitpos));
    (*bitpos)++;
    if (*bitpos == 8) {
        buf[(*len)++] = *cur;
        *cur = 0u;
        *bitpos = 0;
    }
}

static inline void recovery_put_bits_be32(thread cmr_u8* buf, thread cmr_u32* len, thread cmr_u8* cur, thread int* bitpos, const cmr_u32 value) {
    for (int bit = 31; bit >= 0; --bit) {
        recovery_put_bit(buf, len, cur, bitpos, (value >> cmr_u32(bit)) & 1u);
    }
}

static inline void recovery_put_bytes_bits_be(thread cmr_u8* buf, thread cmr_u32* len, thread cmr_u8* cur, thread int* bitpos, const thread cmr_u8* src, const cmr_u32 src_len) {
    for (cmr_u32 i = 0u; i < src_len; ++i) {
        const cmr_u8 byte = src[i];
        for (int bit = 7; bit >= 0; --bit) {
            recovery_put_bit(buf, len, cur, bitpos, (byte >> cmr_u32(bit)) & 1u);
        }
    }
}

// Exact CUDA parity for TON wallet hashes.
static inline bool recovery_pubkey_to_hash_ton(const thread cmr_u8* public_key, const constant char* type, thread cmr_u8* out, const cmr_u32 out_len) {
    if (public_key == nullptr || out == nullptr || out_len < 32u) {
        return false;
    }

    thread cmr_u8 inner[32];
    recovery_zero_thread_bytes(inner, 32u);

    if (recovery_eq_literal(type, "v1r1") || recovery_eq_literal(type, "v1r2") || recovery_eq_literal(type, "v1r3")) {
        thread cmr_u8 data1[128];
        recovery_zero_thread_bytes(data1, 128u);
        recovery_copy_constant_to_thread_bytes(data1, kTonV1DataHeader, 6u);
        recovery_copy_thread_bytes(data1 + 6u, public_key, 32u);
        recovery_sha256_digest(data1, 38u, inner);

        const constant cmr_u8* root_header = nullptr;
        if (recovery_eq_literal(type, "v1r1")) {
            root_header = kTonV1r1RootHeader;
        } else if (recovery_eq_literal(type, "v1r2")) {
            root_header = kTonV1r2RootHeader;
        } else {
            root_header = kTonV1r3RootHeader;
        }

        thread cmr_u8 data2[128];
        recovery_zero_thread_bytes(data2, 128u);
        recovery_copy_constant_to_thread_bytes(data2, root_header, 39u);
        recovery_copy_thread_bytes(data2 + 39u, inner, 32u);
        recovery_sha256_digest(data2, 71u, out);
        return true;
    }

    if (recovery_eq_literal(type, "v2r1") || recovery_eq_literal(type, "v2r2")) {
        thread cmr_u8 data1[128];
        recovery_zero_thread_bytes(data1, 128u);
        recovery_copy_constant_to_thread_bytes(data1, kTonV2DataHeader, 6u);
        recovery_copy_thread_bytes(data1 + 6u, public_key, 32u);
        recovery_sha256_digest(data1, 38u, inner);

        const constant cmr_u8* root_header = recovery_eq_literal(type, "v2r1") ? kTonV2r1RootHeader : kTonV2r2RootHeader;
        thread cmr_u8 data2[128];
        recovery_zero_thread_bytes(data2, 128u);
        recovery_copy_constant_to_thread_bytes(data2, root_header, 39u);
        recovery_copy_thread_bytes(data2 + 39u, inner, 32u);
        recovery_sha256_digest(data2, 71u, out);
        return true;
    }

    if (recovery_eq_literal(type, "v3r1") || recovery_eq_literal(type, "v3r2")) {
        thread cmr_u8 data1[128];
        recovery_zero_thread_bytes(data1, 128u);
        recovery_copy_constant_to_thread_bytes(data1, kTonV3DataHeader, 6u);

        thread cmr_u8 subwallet_buf[4];
        subwallet_buf[0] = cmr_u8((kTonSubwalletId >> 24u) & 0xFFu);
        subwallet_buf[1] = cmr_u8((kTonSubwalletId >> 16u) & 0xFFu);
        subwallet_buf[2] = cmr_u8((kTonSubwalletId >> 8u) & 0xFFu);
        subwallet_buf[3] = cmr_u8(kTonSubwalletId & 0xFFu);

        recovery_copy_thread_bytes(data1 + 6u, subwallet_buf, 4u);
        recovery_copy_thread_bytes(data1 + 10u, public_key, 32u);
        recovery_sha256_digest(data1, 42u, inner);

        const constant cmr_u8* root_header = recovery_eq_literal(type, "v3r1") ? kTonV3r1RootHeader : kTonV3r2RootHeader;
        thread cmr_u8 data2[128];
        recovery_zero_thread_bytes(data2, 128u);
        recovery_copy_constant_to_thread_bytes(data2, root_header, 39u);
        recovery_copy_thread_bytes(data2 + 39u, inner, 32u);
        recovery_sha256_digest(data2, 71u, out);
        return true;
    }

    if (recovery_eq_literal(type, "v4r1") || recovery_eq_literal(type, "v4r2")) {
        thread cmr_u8 data1[128];
        recovery_zero_thread_bytes(data1, 128u);
        recovery_copy_constant_to_thread_bytes(data1, kTonV4DataHeader, 6u);

        thread cmr_u8 subwallet_buf[4];
        subwallet_buf[0] = cmr_u8((kTonSubwalletId >> 24u) & 0xFFu);
        subwallet_buf[1] = cmr_u8((kTonSubwalletId >> 16u) & 0xFFu);
        subwallet_buf[2] = cmr_u8((kTonSubwalletId >> 8u) & 0xFFu);
        subwallet_buf[3] = cmr_u8(kTonSubwalletId & 0xFFu);

        recovery_copy_thread_bytes(data1 + 6u, subwallet_buf, 4u);
        recovery_copy_thread_bytes(data1 + 10u, public_key, 32u);
        recovery_copy_constant_to_thread_bytes(data1 + 42u, kTonDataTail, 1u);
        recovery_sha256_digest(data1, 43u, inner);

        const constant cmr_u8* root_header = recovery_eq_literal(type, "v4r1") ? kTonV4r1RootHeader : kTonV4r2RootHeader;
        thread cmr_u8 data2[128];
        recovery_zero_thread_bytes(data2, 128u);
        recovery_copy_constant_to_thread_bytes(data2, root_header, 39u);
        recovery_copy_thread_bytes(data2 + 39u, inner, 32u);
        recovery_sha256_digest(data2, 71u, out);
        return true;
    }

    if (recovery_eq_literal(type, "v5r1")) {
        thread cmr_u8 data1[128];
        recovery_zero_thread_bytes(data1, 128u);

        cmr_u32 data_len = 0u;
        cmr_u8 cur = 0u;
        int bitpos = 0;

        data1[data_len++] = 0x00u;
        data1[data_len++] = 0x51u;
        recovery_put_bit(data1, &data_len, &cur, &bitpos, 1u);
        recovery_put_bits_be32(data1, &data_len, &cur, &bitpos, 0u);
        recovery_put_bits_be32(data1, &data_len, &cur, &bitpos, kTonSubwalletIdV5);
        recovery_put_bytes_bits_be(data1, &data_len, &cur, &bitpos, public_key, 32u);
        recovery_put_bit(data1, &data_len, &cur, &bitpos, 0u);
        recovery_put_bit(data1, &data_len, &cur, &bitpos, 1u);
        if (bitpos != 0) {
            data1[data_len++] = cur;
        }

        recovery_sha256_digest(data1, data_len, inner);
        thread cmr_u8 data2[128];
        recovery_zero_thread_bytes(data2, 128u);
        recovery_copy_constant_to_thread_bytes(data2, kTonV5r1RootHeader, 39u);
        recovery_copy_thread_bytes(data2 + 39u, inner, 32u);
        recovery_sha256_digest(data2, 71u, out);
        return true;
    }

    return false;
}

static inline void recovery_prepare_emitted_record(
    thread FoundRecord* out_record,
    const thread RecoveryEd25519EvalRecord* source,
    const cmr_u32 coin_type,
    const cmr_u32 derivation_type,
    const cmr_u32 match_len,
    const thread cmr_u8* match_bytes,
    const cmr_i64 round_delta,
    const cmr_u32 passphrase_index) {

    thread FoundRecord hit = source->found;
    hit.coin_type = coin_type;
    hit.derivation_index = source->found.derivation_index;
    hit.derivation_type = source->found.derivation_type != 0u
        ? source->found.derivation_type
        : (derivation_type != 0u ? derivation_type : recovery_default_derivation_type_for_type(coin_type));
    hit.match_len = match_len != 0u ? match_len : recovery_match_size_for_type(coin_type);
    hit.round_delta = source->found.round_delta != 0 ? source->found.round_delta : round_delta;
    hit.passphrase_index = source->found.passphrase_index != 0u ? source->found.passphrase_index : passphrase_index;
    hit.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;

    for (cmr_u32 i = hit.match_len; i < 32u; ++i) {
        hit.match_bytes[i] = 0u;
    }
    for (cmr_u32 i = 0u; i < hit.match_len && i < 32u; ++i) {
        hit.match_bytes[i] = match_bytes[i];
    }

    *out_record = hit;
}

static inline void recovery_emit_found_record(
    const thread FoundRecord* record,
    device FoundRecord* out_records,
    device atomic_uint* out_count,
    const cmr_u32 out_capacity) {

    const uint slot = atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed);
    if (slot >= out_capacity) {
        return;
    }

    recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[slot], (const thread cmr_u8*)record, sizeof(FoundRecord));
}

static inline cmr_u32 recovery_bloom_get_bit(const device cmr_u8* bloom, const cmr_u32 bit_index) {
    return cmr_u32((bloom[bit_index >> 3u] >> (bit_index & 7u)) & 1u);
}

static inline bool recovery_bloom_matches_hash_words(const device cmr_u8* bloom, const thread cmr_u32* h) {
    if (bloom == nullptr) {
        return false;
    }

#define RECOVERY_BLOOM_CHECK(v) do { if (recovery_bloom_get_bit(bloom, (v)) == 0u) return false; } while (0)
    RECOVERY_BLOOM_CHECK(h[0]);
    RECOVERY_BLOOM_CHECK(h[1]);
    RECOVERY_BLOOM_CHECK(h[2]);
    RECOVERY_BLOOM_CHECK(h[3]);
    RECOVERY_BLOOM_CHECK(h[4]);
    RECOVERY_BLOOM_CHECK((h[0] << 16u) | (h[1] >> 16u));
    RECOVERY_BLOOM_CHECK((h[1] << 16u) | (h[2] >> 16u));
    RECOVERY_BLOOM_CHECK((h[2] << 16u) | (h[3] >> 16u));
    RECOVERY_BLOOM_CHECK((h[3] << 16u) | (h[4] >> 16u));
    RECOVERY_BLOOM_CHECK((h[4] << 16u) | (h[0] >> 16u));
    RECOVERY_BLOOM_CHECK((h[0] << 8u) | (h[1] >> 24u));
    RECOVERY_BLOOM_CHECK((h[1] << 8u) | (h[2] >> 24u));
    RECOVERY_BLOOM_CHECK((h[2] << 8u) | (h[3] >> 24u));
    RECOVERY_BLOOM_CHECK((h[3] << 8u) | (h[4] >> 24u));
    RECOVERY_BLOOM_CHECK((h[4] << 8u) | (h[0] >> 24u));
    RECOVERY_BLOOM_CHECK((h[0] << 24u) | (h[1] >> 8u));
    RECOVERY_BLOOM_CHECK((h[1] << 24u) | (h[2] >> 8u));
    RECOVERY_BLOOM_CHECK((h[2] << 24u) | (h[3] >> 8u));
    RECOVERY_BLOOM_CHECK((h[3] << 24u) | (h[4] >> 8u));
    RECOVERY_BLOOM_CHECK((h[4] << 24u) | (h[0] >> 8u));
#undef RECOVERY_BLOOM_CHECK
    return true;
}

static inline cmr_u64 recovery_murmur64(cmr_u64 h) {
    h ^= h >> 33u;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33u;
    h *= 0xc4ceb9fe1a85ec53ull;
    h ^= h >> 33u;
    return h;
}

static inline cmr_u32 recovery_xor_fingerprint(const cmr_u64 hash) {
    return cmr_u32(hash ^ (hash >> 32u));
}

static inline bool recovery_xor_contains_half_hash(
    const cmr_u64 hash,
    const device cmr_u32* fingerprints,
    const cmr_u64 array_length,
    const cmr_u64 segment_count_length,
    const cmr_u64 segment_length,
    const cmr_u64 segment_mask) {

    if (fingerprints == nullptr || array_length == 0ull) {
        return false;
    }

    cmr_u32 f = recovery_xor_fingerprint(hash);
    const cmr_u64 base = mulhi(hash, segment_count_length);
    const cmr_u64 hh = hash & ((1ull << 32u) - 1ull);
    const cmr_u64 slots[4] = {
        base,
        (base + segment_length) ^ ((hh >> 18u) & segment_mask),
        (base + (segment_length << 1u)) ^ (hh & segment_mask),
        base + segment_length * 3ull
    };

    for (cmr_u32 i = 0u; i < 4u; ++i) {
        if (slots[i] >= array_length) {
            return false;
        }
        f ^= fingerprints[slots[i]];
    }
    return f == 0u;
}

static inline void recovery_record_filter_hash_words(const thread FoundRecord* record, thread cmr_u32 hash_words[5]) {
    for (cmr_u32 i = 0u; i < 5u; ++i) {
        const cmr_u32 base = i * 4u;
        hash_words[i] =
            cmr_u32(record->match_bytes[base + 0u]) |
            (cmr_u32(record->match_bytes[base + 1u]) << 8u) |
            (cmr_u32(record->match_bytes[base + 2u]) << 16u) |
            (cmr_u32(record->match_bytes[base + 3u]) << 24u);
    }
}

static inline void recovery_record_filter_xor_bytes(const thread FoundRecord* record, thread cmr_u8 out_bytes[20]) {
    for (cmr_u32 i = 0u; i < 20u; ++i) {
        out_bytes[i] = record->match_bytes[i];
    }
    out_bytes[3] = cmr_u8(out_bytes[3] & out_bytes[16]);
    out_bytes[7] = cmr_u8(out_bytes[7] & out_bytes[17]);
    out_bytes[11] = cmr_u8(out_bytes[11] & out_bytes[18]);
    out_bytes[15] = cmr_u8(out_bytes[15] & out_bytes[19]);
}

static inline cmr_u64 recovery_load_le64_from_thread_bytes(const thread cmr_u8* data) {
    cmr_u64 value = 0ull;
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        value |= cmr_u64(data[i]) << (8u * i);
    }
    return value;
}

static inline const device cmr_u32* recovery_xor_filter_buffer_at(
    const device cmr_u32* xor_fingerprints,
    const constant RecoveryFilterParams& filter_params,
    const cmr_u32 index) {

    if (xor_fingerprints == nullptr || index >= RECOVERY_ED25519_MAX_XOR_FILTERS) {
        return nullptr;
    }
    return xor_fingerprints + filter_params.xor_buffer_offset[index];
}

static inline bool recovery_filter_matches_record(
    const thread FoundRecord* record,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints) {

    const bool bloom_enabled = filter_params.bloom_enabled != 0u;
    const cmr_u32 xor_count = filter_params.xor_count <= RECOVERY_ED25519_MAX_XOR_FILTERS
        ? filter_params.xor_count
        : RECOVERY_ED25519_MAX_XOR_FILTERS;
    if (!bloom_enabled && xor_count == 0u) {
        return true;
    }

    thread cmr_u32 hash_words[5];
    recovery_record_filter_hash_words(record, hash_words);
    if (bloom_enabled && recovery_bloom_matches_hash_words(bloom_bytes, hash_words)) {
        return true;
    }
    if (xor_count == 0u) {
        return false;
    }

    thread cmr_u8 xor_bytes[20];
    recovery_record_filter_xor_bytes(record, xor_bytes);
    const cmr_u64 item_lo = recovery_load_le64_from_thread_bytes(xor_bytes + 0u);
    const cmr_u64 item_hi = recovery_load_le64_from_thread_bytes(xor_bytes + 8u);
    const cmr_u64 hash_hi = recovery_murmur64(item_hi + filter_params.xor_seed);
    const cmr_u64 hash_lo = recovery_murmur64(item_lo + filter_params.xor_seed);

    for (cmr_u32 i = 0u; i < xor_count; ++i) {
        const device cmr_u32* xor_buffer = recovery_xor_filter_buffer_at(xor_fingerprints, filter_params, i);
        if (!recovery_xor_contains_half_hash(
                hash_hi,
                xor_buffer,
                filter_params.xor_array_length[i],
                filter_params.xor_segment_count_length[i],
                filter_params.xor_segment_length[i],
                filter_params.xor_segment_length_mask[i])) {
            continue;
        }
        if (recovery_xor_contains_half_hash(
                hash_lo,
                xor_buffer,
                filter_params.xor_array_length[i],
                filter_params.xor_segment_count_length[i],
                filter_params.xor_segment_length[i],
                filter_params.xor_segment_length_mask[i])) {
            return true;
        }
    }
    return false;
}

static inline void recovery_emit_found_record_filtered(
    const thread FoundRecord* record,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count,
    const cmr_u32 out_capacity) {

    if (!recovery_filter_matches_record(record, filter_params, bloom_bytes, xor_fingerprints)) {
        return;
    }
    recovery_emit_found_record(record, out_records, out_count, out_capacity);
}

static inline bool recovery_ed25519_emit_all_enabled(const constant RecoveryEd25519EvalParams& params) {
    return (params.target_flags & RECOVERY_ED25519_TARGET_FLAG_EMIT_ALL) != 0u;
}

static inline void recovery_eval_solana_target(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    if ((params.target_flags & RECOVERY_ED25519_TARGET_FLAG_SOLANA) == 0u) {
        return;
    }

    const cmr_u32 compare_len = params.match_len != 0u ? params.match_len : 32u;
    if (!recovery_ed25519_emit_all_enabled(params) &&
        !recovery_prefix_matches(source->public_key, params.target_bytes, compare_len)) {
        return;
    }

    thread FoundRecord hit;
    recovery_prepare_emitted_record(
        &hit,
        source,
        0x60u,
        params.derivation_type,
        recovery_match_size_for_type(0x60u),
        source->public_key,
        params.round_delta,
        params.passphrase_index);
    recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count, params.out_capacity);
}

static inline void recovery_eval_ton_variant(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    const constant RecoveryFilterParams& filter_params,
    const constant char* wallet_type,
    const cmr_u32 wallet_coin_type,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    thread cmr_u8 wallet_hash[32];
    recovery_zero_thread_bytes(wallet_hash, 32u);
    if (!recovery_pubkey_to_hash_ton(source->public_key, wallet_type, wallet_hash, 32u)) {
        return;
    }

    const cmr_u32 compare_len = params.match_len != 0u ? params.match_len : recovery_match_size_for_type(wallet_coin_type);
    if (!recovery_ed25519_emit_all_enabled(params) &&
        !recovery_prefix_matches(wallet_hash, params.target_bytes, compare_len)) {
        return;
    }

    thread FoundRecord hit;
    recovery_prepare_emitted_record(
        &hit,
        source,
        wallet_coin_type,
        params.derivation_type,
        recovery_match_size_for_type(wallet_coin_type),
        wallet_hash,
        params.round_delta,
        params.passphrase_index);
    recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count, params.out_capacity);
}

static inline void recovery_eval_ton_targets(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    if ((params.target_flags & RECOVERY_ED25519_TARGET_FLAG_TON_ALL) != 0u) {
        recovery_eval_ton_variant(source, params, filter_params, "v1r1", 0x80u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v1r2", 0x81u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v1r3", 0x82u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v2r1", 0x83u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v2r2", 0x84u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v3r1", 0x85u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v3r2", 0x86u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v4r1", 0x87u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v4r2", 0x88u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v5r1", 0x89u, bloom_bytes, xor_fingerprints, out_records, out_count);
        return;
    }

    if ((params.target_flags & RECOVERY_ED25519_TARGET_FLAG_TON_SHORT) != 0u) {
        recovery_eval_ton_variant(source, params, filter_params, "v3r1", 0x85u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v3r2", 0x86u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v4r2", 0x88u, bloom_bytes, xor_fingerprints, out_records, out_count);
        recovery_eval_ton_variant(source, params, filter_params, "v5r1", 0x89u, bloom_bytes, xor_fingerprints, out_records, out_count);
    }
}

static inline void recovery_eval_ed25519_candidate(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    if (source == nullptr || source->public_key_ready == 0u) {
        return;
    }
    if (!recovery_ed25519_derivation_allowed(source, params)) {
        return;
    }

    recovery_eval_solana_target(source, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
    recovery_eval_ton_targets(source, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
}

static inline void recovery_eval_ed25519_candidate_nofilter(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    recovery_eval_ed25519_candidate(source, params, kRecoveryEmptyFilterParams, nullptr, nullptr, out_records, out_count);
}

static inline void recovery_eval_ed25519_candidate_bloom_only(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    const device cmr_u8* bloom_bytes,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    recovery_eval_ed25519_candidate(source, params, kRecoveryBloomOnlyFilterParams, bloom_bytes, nullptr, out_records, out_count);
}

static inline void recovery_eval_ed25519_candidate_xor_single(
    const thread RecoveryEd25519EvalRecord* source,
    const constant RecoveryEd25519EvalParams& params,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    recovery_eval_ed25519_candidate(source, params, filter_params, nullptr, xor_fingerprints, out_records, out_count);
}

static inline void recovery_promote_stage_record_to_eval_record(
    const thread RecoveryEd25519StageRecord* stage,
    thread RecoveryEd25519EvalRecord* out_eval) {

    recovery_zero_thread_bytes((thread cmr_u8*)out_eval, sizeof(RecoveryEd25519EvalRecord));
    out_eval->found = stage->found;
    recovery_copy_thread_bytes(out_eval->public_key, stage->public_key, 32u);
    out_eval->public_key_ready = stage->public_key_ready;
}

kernel void workerRecoveryDeriveEd25519Stage(
    const device MasterSeedRecord* seed_records [[buffer(0)]],
    const device RecoveryEd25519DerivationProgram* programs [[buffer(1)]],
    device RecoveryEd25519StageRecord* out_records [[buffer(2)]],
    constant RecoveryEd25519StageKernelParams& params [[buffer(3)]],
    const device atomic_uint* seed_count_buffer [[buffer(4)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count < params.out_capacity ? params.record_count : params.out_capacity;
    const cmr_u32 seed_count = (seed_count_buffer == nullptr)
        ? 0u
        : min(params.seed_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.program_count;
    if (seed_count == 0u || program_count == 0u) {
        return;
    }
    const cmr_u64 active_pair_count = min(cmr_u64(limit), cmr_u64(seed_count) * cmr_u64(program_count));
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        if (idx >= active_pair_count) {
            thread RecoveryEd25519StageRecord empty_record;
            recovery_zero_thread_bytes((thread cmr_u8*)&empty_record, sizeof(RecoveryEd25519StageRecord));
            recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx], (const thread cmr_u8*)&empty_record, sizeof(RecoveryEd25519StageRecord));
            continue;
        }
        const cmr_u32 seed_index = static_cast<cmr_u32>(idx / cmr_u64(program_count));
        const cmr_u32 program_index = static_cast<cmr_u32>(idx % cmr_u64(program_count));
        if (seed_index >= seed_count) {
            thread RecoveryEd25519StageRecord empty_record;
            recovery_zero_thread_bytes((thread cmr_u8*)&empty_record, sizeof(RecoveryEd25519StageRecord));
            recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx], (const thread cmr_u8*)&empty_record, sizeof(RecoveryEd25519StageRecord));
            continue;
        }

        thread MasterSeedRecord seed_record;
        thread RecoveryEd25519DerivationProgram program;
        thread RecoveryEd25519StageRecord stage_record;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&seed_record, (const device cmr_u8*)&seed_records[seed_index], sizeof(MasterSeedRecord));
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&program, (const device cmr_u8*)&programs[program_index], sizeof(RecoveryEd25519DerivationProgram));

        if (!recovery_ed25519_derive_stage_record(&seed_record, &program, &stage_record)) {
            recovery_zero_thread_bytes((thread cmr_u8*)&stage_record, sizeof(RecoveryEd25519StageRecord));
        }

        recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx], (const thread cmr_u8*)&stage_record, sizeof(RecoveryEd25519StageRecord));
    }
}

kernel void workerRecoveryPromoteSecpToEd25519Stage(
    const device RecoverySecpEvalRecord* secp_records [[buffer(0)]],
    device RecoveryEd25519StageRecord* out_records [[buffer(1)]],
    constant RecoveryEd25519StageKernelParams& params [[buffer(2)]],
    const device atomic_uint* seed_count_buffer [[buffer(3)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count < params.out_capacity ? params.record_count : params.out_capacity;
    const cmr_u32 seed_count = (seed_count_buffer == nullptr)
        ? 0u
        : min(params.seed_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.program_count;
    const cmr_u64 active_pair_count = (seed_count == 0u || program_count == 0u)
        ? 0u
        : min(cmr_u64(limit), cmr_u64(seed_count) * cmr_u64(program_count));
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        if (idx >= active_pair_count) {
            thread RecoveryEd25519StageRecord empty_stage;
            recovery_zero_thread_bytes((thread cmr_u8*)&empty_stage, sizeof(RecoveryEd25519StageRecord));
            recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx], (const thread cmr_u8*)&empty_stage, sizeof(RecoveryEd25519StageRecord));
            continue;
        }
        thread RecoverySecpEvalRecord secp_stage;
        thread RecoveryEd25519StageRecord ed_stage;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&secp_stage, (const device cmr_u8*)&secp_records[idx], sizeof(RecoverySecpEvalRecord));
        recovery_zero_thread_bytes((thread cmr_u8*)&ed_stage, sizeof(RecoveryEd25519StageRecord));

        if (secp_stage.private_key_ready != 0u) {
            ed_stage.found = secp_stage.found;
            ed_stage.found.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;
            recovery_copy_thread_bytes(ed_stage.private_key.key, secp_stage.private_key, 32u);
            recovery_zero_thread_bytes(ed_stage.private_key.chain_code, 32u);
            recovery_copy_thread_bytes(ed_stage.found.private_key, secp_stage.private_key, 32u);
            ed_stage.private_key_ready = 1u;
            recovery_ed25519_public_key_from_private(secp_stage.private_key, ed_stage.public_key);
            ed_stage.public_key_ready = 1u;
        }

        recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx], (const thread cmr_u8*)&ed_stage, sizeof(RecoveryEd25519StageRecord));
    }
}

kernel void workerRecoveryRuntimeConsumeEdSeeds(
    const device MasterSeedRecord* seed_records [[buffer(0)]],
    device RecoveryRingHeader* seed_ring [[buffer(1)]],
    const device RecoveryEd25519DerivationProgram* programs [[buffer(2)]],
    constant RecoveryEd25519StageKernelParams& derive_params [[buffer(3)]],
    constant RecoveryEd25519EvalParams& eval_params [[buffer(4)]],
    device RecoveryRuntimeState* runtime_state [[buffer(5)]],
    device FoundRecord* out_records [[buffer(6)]],
    device atomic_uint* out_count [[buffer(7)]],
    constant RecoveryFilterParams& filter_params [[buffer(8)]],
    const device cmr_u8* bloom_bytes [[buffer(9)]],
    const device cmr_u32* xor_fingerprints [[buffer(10)]],
    device RecoveryRingHeader* promote_ring [[buffer(11)]],
    device RecoveryEd25519StageRecord* promote_records [[buffer(12)]],
    uint lid [[thread_position_in_threadgroup]]) {

    if (seed_records == nullptr || seed_ring == nullptr || programs == nullptr || runtime_state == nullptr ||
        out_records == nullptr || out_count == nullptr) {
        return;
    }

    const cmr_u32 program_count = derive_params.program_count;
    const bool run_ed_eval = eval_params.out_capacity != 0u && eval_params.target_flags != 0u;
    const bool want_promote = promote_ring != nullptr && promote_records != nullptr && promote_ring->capacity != 0u;

    while (true) {
        if (recovery_runtime_should_stop(runtime_state) != 0u && recovery_ring_is_drained(seed_ring)) {
            break;
        }

        cmr_u32 reservation = 0u;
        if (!recovery_ring_try_reserve_read(seed_ring, &reservation)) {
            if (recovery_ring_is_closed(seed_ring) != 0u && recovery_ring_is_drained(seed_ring)) {
                break;
            }
            continue;
        }

        const cmr_u32 seed_slot = reservation % seed_ring->capacity;
        thread MasterSeedRecord seed_record;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&seed_record,
                                             (const device cmr_u8*)&seed_records[seed_slot],
                                             sizeof(MasterSeedRecord));
        if ((seed_record.hit.flags & RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS) == 0u || program_count == 0u) {
            continue;
        }

        for (cmr_u32 program_index = 0u; program_index < program_count; ++program_index) {
            if (recovery_runtime_should_stop(runtime_state) != 0u) {
                break;
            }

            thread RecoveryEd25519DerivationProgram program;
            recovery_copy_device_to_thread_bytes((thread cmr_u8*)&program,
                                                 (const device cmr_u8*)&programs[program_index],
                                                 sizeof(RecoveryEd25519DerivationProgram));

            thread RecoveryEd25519StageRecord stage_record;
            if (!recovery_ed25519_derive_stage_record(&seed_record, &program, &stage_record)) {
                recovery_zero_thread_bytes((thread cmr_u8*)&stage_record, sizeof(RecoveryEd25519StageRecord));
            }

            if (run_ed_eval && recovery_ed25519_stage_record_ready(&stage_record)) {
                thread RecoveryEd25519EvalRecord record;
                recovery_promote_stage_record_to_eval_record(&stage_record, &record);
                recovery_eval_ed25519_candidate(&record, eval_params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
                if (atomic_load_explicit(out_count, memory_order_relaxed) >= eval_params.out_capacity) {
                    recovery_runtime_request_stop(runtime_state);
                }
            }

            if (want_promote && recovery_ed25519_stage_record_ready(&stage_record)) {
                while (recovery_runtime_should_stop(runtime_state) == 0u) {
                    cmr_u32 out_reservation = 0u;
                    if (!recovery_ring_try_reserve_write(promote_ring, &out_reservation)) {
                        continue;
                    }
                    const cmr_u32 out_slot = out_reservation % promote_ring->capacity;
                    recovery_copy_thread_to_device_bytes((device cmr_u8*)&promote_records[out_slot],
                                                         (const thread cmr_u8*)&stage_record,
                                                         sizeof(RecoveryEd25519StageRecord));
                    recovery_ring_publish_write(promote_ring, out_reservation);
                    break;
                }
            }
        }
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (lid == 0u && recovery_runtime_group_done(&runtime_state->ed_groups_live) != 0u && want_promote) {
        recovery_ring_close(promote_ring);
    }
}

kernel void workerRecoveryRuntimeConsumePromotedSecpStages(
    const device RecoverySecpEvalRecord* secp_records [[buffer(0)]],
    device RecoveryRingHeader* stage_ring [[buffer(1)]],
    constant RecoveryEd25519EvalParams& params [[buffer(2)]],
    device RecoveryRuntimeState* runtime_state [[buffer(3)]],
    device FoundRecord* out_records [[buffer(4)]],
    device atomic_uint* out_count [[buffer(5)]],
    constant RecoveryFilterParams& filter_params [[buffer(6)]],
    const device cmr_u8* bloom_bytes [[buffer(7)]],
    const device cmr_u32* xor_fingerprints [[buffer(8)]]) {

    if (secp_records == nullptr || stage_ring == nullptr || runtime_state == nullptr ||
        out_records == nullptr || out_count == nullptr || params.out_capacity == 0u || params.target_flags == 0u) {
        return;
    }

    while (true) {
        if (recovery_runtime_should_stop(runtime_state) != 0u && recovery_ring_is_drained(stage_ring)) {
            break;
        }

        cmr_u32 reservation = 0u;
        if (!recovery_ring_try_reserve_read(stage_ring, &reservation)) {
            if (recovery_ring_is_closed(stage_ring) != 0u && recovery_ring_is_drained(stage_ring)) {
                break;
            }
            continue;
        }

        const cmr_u32 slot = reservation % stage_ring->capacity;
        thread RecoverySecpEvalRecord secp_stage;
        thread RecoveryEd25519StageRecord ed_stage;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&secp_stage,
                                             (const device cmr_u8*)&secp_records[slot],
                                             sizeof(RecoverySecpEvalRecord));
        recovery_zero_thread_bytes((thread cmr_u8*)&ed_stage, sizeof(RecoveryEd25519StageRecord));

        if (secp_stage.private_key_ready != 0u) {
            ed_stage.found = secp_stage.found;
            ed_stage.found.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;
            recovery_copy_thread_bytes(ed_stage.private_key.key, secp_stage.private_key, 32u);
            recovery_zero_thread_bytes(ed_stage.private_key.chain_code, 32u);
            recovery_copy_thread_bytes(ed_stage.found.private_key, secp_stage.private_key, 32u);
            ed_stage.private_key_ready = 1u;
            recovery_ed25519_public_key_from_private(secp_stage.private_key, ed_stage.public_key);
            ed_stage.public_key_ready = 1u;
        }

        if (recovery_ed25519_stage_record_ready(&ed_stage)) {
            thread RecoveryEd25519EvalRecord record;
            recovery_promote_stage_record_to_eval_record(&ed_stage, &record);
            recovery_eval_ed25519_candidate(&record, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
            if (atomic_load_explicit(out_count, memory_order_relaxed) >= params.out_capacity) {
                recovery_runtime_request_stop(runtime_state);
            }
        }
    }
}

kernel void workerRecoveryEvalEd25519Stage(
    const device RecoveryEd25519StageRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEd25519EvalParams& params [[buffer(3)]],
    constant RecoveryFilterParams& filter_params [[buffer(4)]],
    const device cmr_u8* bloom_bytes [[buffer(5)]],
    const device cmr_u32* xor_fingerprints [[buffer(6)]],
    uint gid [[thread_position_in_grid]]) {

    if (gid >= params.candidate_count) {
        return;
    }

    thread RecoveryEd25519StageRecord stage;
    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&stage, (const device cmr_u8*)&stage_records[gid], sizeof(RecoveryEd25519StageRecord));
    if (!recovery_ed25519_stage_record_ready(&stage)) {
        return;
    }

    thread RecoveryEd25519EvalRecord record;
    recovery_promote_stage_record_to_eval_record(&stage, &record);
    recovery_eval_ed25519_candidate(&record, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
}

kernel void workerRecoveryEvalEd25519StageBloomOnly(
    const device RecoveryEd25519StageRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEd25519EvalParams& params [[buffer(3)]],
    const device cmr_u8* bloom_bytes [[buffer(4)]],
    uint gid [[thread_position_in_grid]]) {

    if (gid >= params.candidate_count) {
        return;
    }

    thread RecoveryEd25519StageRecord stage;
    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&stage, (const device cmr_u8*)&stage_records[gid], sizeof(RecoveryEd25519StageRecord));
    if (!recovery_ed25519_stage_record_ready(&stage)) {
        return;
    }

    thread RecoveryEd25519EvalRecord record;
    recovery_promote_stage_record_to_eval_record(&stage, &record);
    recovery_eval_ed25519_candidate_bloom_only(&record, params, bloom_bytes, out_records, out_count);
}

kernel void workerRecoveryEvalEd25519StageXorSingle(
    const device RecoveryEd25519StageRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEd25519EvalParams& params [[buffer(3)]],
    constant RecoveryFilterParams& filter_params [[buffer(4)]],
    const device cmr_u32* xor_fingerprints [[buffer(5)]],
    uint gid [[thread_position_in_grid]]) {

    if (gid >= params.candidate_count) {
        return;
    }

    thread RecoveryEd25519StageRecord stage;
    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&stage, (const device cmr_u8*)&stage_records[gid], sizeof(RecoveryEd25519StageRecord));
    if (!recovery_ed25519_stage_record_ready(&stage)) {
        return;
    }

    thread RecoveryEd25519EvalRecord record;
    recovery_promote_stage_record_to_eval_record(&stage, &record);
    recovery_eval_ed25519_candidate_xor_single(&record, params, filter_params, xor_fingerprints, out_records, out_count);
}

kernel void workerRecoveryEvalEd25519StageNoFilter(
    const device RecoveryEd25519StageRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEd25519EvalParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]) {

    if (gid >= params.candidate_count) {
        return;
    }

    thread RecoveryEd25519StageRecord stage;
    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&stage, (const device cmr_u8*)&stage_records[gid], sizeof(RecoveryEd25519StageRecord));
    if (!recovery_ed25519_stage_record_ready(&stage)) {
        return;
    }

    thread RecoveryEd25519EvalRecord record;
    recovery_promote_stage_record_to_eval_record(&stage, &record);
    recovery_eval_ed25519_candidate_nofilter(&record, params, out_records, out_count);
}
