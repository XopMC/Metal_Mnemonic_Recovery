#include <metal_stdlib>
using namespace metal;

#include "metal/RecoveryCryptoCommon.h"
#include "metal/RecoveryMetalTypes.h"
#include "metal/RecoveryEvalEd25519.h"
#include "metal/RecoveryEvalSecp.h"

#include "third_party/secp256k1/secp256k1.inc"
#include "metal/RecoverySecpDerivationCompat.h"
#include "metal/RecoveryDerivationHelpers.h"

constant RecoveryFilterParams kRecoveryEmptyFilterParams = {};
constant RecoveryFilterParams kRecoveryBloomOnlyFilterParams = {
    1u, 0u, 0u, 0u, 0ull
};

constant char kRecoverySecpSeedLabel[] = "Bitcoin seed";

static inline void recovery_zero_found_record(thread FoundRecord& record) {
    for (cmr_u32 i = 0u; i < RECOVERY_MAX_WORDS; ++i) {
        record.word_ids[i] = 0u;
    }
    record.word_count = 0u;
    record.derivation_index = 0u;
    record.derivation_type = 0u;
    record.coin_type = 0u;
    record.match_len = 0u;
    record.flags = 0u;
    record.round_delta = 0;
    record.passphrase_index = 0u;
    record.reserved = 0u;
    recovery_zero_thread_bytes(record.private_key, 32u);
    recovery_zero_thread_bytes(record.match_bytes, 32u);
}

static inline void recovery_zero_secp_eval_record(thread RecoverySecpEvalRecord& record) {
    recovery_zero_found_record(record.found);
    recovery_zero_thread_bytes(record.private_key, 32u);
    recovery_zero_thread_bytes(record.public_key, 65u);
    recovery_zero_thread_bytes(record.taproot_xonly, 32u);
    record.private_key_ready = 0u;
    record.public_key_ready = 0u;
    record.derivation_ready = 0u;
    record.target_ready = 0u;
}

static inline void recovery_copy_private_key(thread FoundRecord& record, const thread cmr_u8* private_key) {
    for (cmr_u32 i = 0u; i < 32u; ++i) {
        record.private_key[i] = private_key[i];
    }
}

static inline void recovery_copy_match_bytes(thread FoundRecord& record, const thread cmr_u8* match_bytes, const cmr_u32 match_len) {
    const cmr_u32 len = match_len > 32u ? 32u : match_len;
    record.match_len = len;
    for (cmr_u32 i = 0u; i < 32u; ++i) {
        record.match_bytes[i] = (i < len) ? match_bytes[i] : 0u;
    }
}

static inline void recovery_copy_found_record_to_device(device FoundRecord* dst, const thread FoundRecord& src) {
    recovery_copy_thread_to_device_bytes((device cmr_u8*)dst, (const thread cmr_u8*)&src, sizeof(FoundRecord));
}

static inline void recovery_copy_eval_record_from_device(thread RecoverySecpEvalRecord& dst, const device RecoverySecpEvalRecord* src) {
    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&dst, (const device cmr_u8*)src, sizeof(RecoverySecpEvalRecord));
}

static inline void recovery_copy_eval_record_to_device(device RecoverySecpEvalRecord* dst, const thread RecoverySecpEvalRecord& src) {
    recovery_copy_thread_to_device_bytes((device cmr_u8*)dst, (const thread cmr_u8*)&src, sizeof(RecoverySecpEvalRecord));
}

static inline bool recovery_prefix_matches_constant(const thread cmr_u8* lhs, const constant cmr_u8* rhs, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }
    return true;
}

static inline bool recovery_secp_emit_all_enabled(const constant RecoveryEvalSecpKernelParams& params) {
    return (params.flags & RECOVERY_SECP_FLAG_EMIT_ALL) != 0u;
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
    recovery_copy_found_record_to_device(&out_records[slot], *record);
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

static inline void recovery_seed_hit_to_found(const thread ChecksumHitRecord& hit, thread FoundRecord& out) {
    recovery_zero_found_record(out);
    out.word_count = cmr_u32(hit.word_count);
    out.derivation_index = hit.derivation_index;
    out.derivation_type = hit.derivation_type;
    out.coin_type = hit.coin_type;
    out.match_len = hit.match_len;
    out.flags = hit.flags;
    out.round_delta = hit.round_delta;
    out.passphrase_index = hit.passphrase_index;
    for (cmr_u32 i = 0u; i < out.word_count && i < RECOVERY_MAX_WORDS; ++i) {
        out.word_ids[i] = cmr_u32(hit.word_ids[i] & 0x07FFu);
    }
}

static inline void recovery_seed_hit_to_found(const device ChecksumHitRecord& hit, thread FoundRecord& out) {
    recovery_zero_found_record(out);
    out.word_count = cmr_u32(hit.word_count);
    out.derivation_index = hit.derivation_index;
    out.derivation_type = hit.derivation_type;
    out.coin_type = hit.coin_type;
    out.match_len = hit.match_len;
    out.flags = hit.flags;
    out.round_delta = hit.round_delta;
    out.passphrase_index = hit.passphrase_index;
    for (cmr_u32 i = 0u; i < out.word_count && i < RECOVERY_MAX_WORDS; ++i) {
        out.word_ids[i] = cmr_u32(hit.word_ids[i] & 0x07FFu);
    }
}

static inline void recovery_derive_secp_master_key(const thread cmr_u32 seed_words[RECOVERY_MASTER_WORDS], thread extended_private_key_t& master) {
    thread cmr_u8 seed[64];
    thread cmr_u8 digest[64];
    thread cmr_u8 key_label[12];
    const thread cmr_u8* in_bytes = reinterpret_cast<const thread cmr_u8*>(seed_words);
    for (cmr_u32 chunk = 0u; chunk < 8u; ++chunk) {
        const cmr_u32 base = chunk * 8u;
        for (cmr_u32 i = 0u; i < 8u; ++i) {
            seed[base + i] = in_bytes[base + (7u - i)];
        }
    }
    recovery_copy_constant_to_thread_bytes(key_label, reinterpret_cast<const constant cmr_u8*>(kRecoverySecpSeedLabel), 12u);
    recovery_hmac_sha512(key_label, 12u, seed, 64u, digest);
    recovery_copy_thread_bytes(master.key, digest, 32u);
    recovery_copy_thread_bytes(master.chain_code, digest + 32u, 32u);
}

static inline void recovery_build_compressed_pubkey(const thread cmr_u8* pub65, thread cmr_u8 out33[33]) {
    out33[0] = cmr_u8(0x02u + (pub65[64] & 1u));
    for (cmr_u32 i = 0u; i < 32u; ++i) {
        out33[i + 1u] = pub65[i + 1u];
    }
}

static inline void recovery_build_p2sh_script_from_hash160(const thread cmr_u8 hash160[20], thread cmr_u8 script[22]) {
    script[0] = 0x00u;
    script[1] = 0x14u;
    for (cmr_u32 i = 0u; i < 20u; ++i) {
        script[i + 2u] = hash160[i];
    }
}

static inline void recovery_prepare_secp_emitted_record(
    thread FoundRecord& out_record,
    const thread RecoverySecpEvalRecord& source,
    const cmr_u32 coin_type,
    const thread cmr_u8* match_bytes,
    const cmr_u32 match_len) {

    out_record = source.found;
    out_record.coin_type = coin_type;
    out_record.derivation_type = source.found.derivation_type != 0u
        ? source.found.derivation_type
        : RESULT_DERIVATION_BIP32_SECP256K1;
    out_record.match_len = match_len != 0u ? match_len : recovery_match_size_for_type(coin_type);
    out_record.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;
    recovery_copy_private_key(out_record, source.private_key);
    recovery_copy_match_bytes(out_record, match_bytes, out_record.match_len);
}

static inline void recovery_prepare_secp_emitted_record_direct(
    thread FoundRecord& out_record,
    const thread FoundRecord& base_found,
    const cmr_u32 derivation_index,
    const cmr_u32 derivation_type,
    const cmr_u32 passphrase_index,
    const thread cmr_u8* private_key,
    const cmr_u32 coin_type,
    const thread cmr_u8* match_bytes,
    const cmr_u32 match_len) {

    out_record = base_found;
    out_record.derivation_index = derivation_index;
    out_record.derivation_type = derivation_type != 0u
        ? derivation_type
        : RESULT_DERIVATION_BIP32_SECP256K1;
    out_record.passphrase_index = passphrase_index;
    out_record.coin_type = coin_type;
    out_record.match_len = match_len != 0u ? match_len : recovery_match_size_for_type(coin_type);
    out_record.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;
    recovery_copy_private_key(out_record, private_key);
    recovery_copy_match_bytes(out_record, match_bytes, out_record.match_len);
}

static inline bool recovery_secp_target_prefix_matches(
    const thread cmr_u8* match_bytes,
    const cmr_u32 match_len,
    const constant RecoveryEvalSecpKernelParams& params) {

    const cmr_u32 compare_len = params.target_len != 0u ? min(params.target_len, match_len) : 0u;
    if (compare_len == 0u) {
        return true;
    }
    return recovery_prefix_matches_constant(match_bytes, params.target_bytes, compare_len);
}

static inline void recovery_eval_secp_target(
    const thread RecoverySecpEvalRecord& source,
    const constant RecoveryEvalSecpKernelParams& params,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u8* bloom_bytes,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    if (source.public_key_ready == 0u) {
        return;
    }
    if (!recovery_secp_derivation_type_enabled(params.derivation_type_mask,
                                               source.found.derivation_type != 0u ? source.found.derivation_type : RESULT_DERIVATION_BIP32_SECP256K1)) {
        return;
    }

    thread cmr_u8 compressed_pub[33];
    recovery_build_compressed_pubkey(source.public_key, compressed_pub);

    thread cmr_u8 compressed_hash160[20];
    thread cmr_u8 uncompressed_hash160[20];
    thread cmr_u8 segwit_hash160[20];
    thread cmr_u8 eth_hash[32];
    thread cmr_u8 p2sh_script[22];

    if ((params.target_mask & RecoverySecpTargetBitCompressed) != 0u ||
        (params.target_mask & RecoverySecpTargetBitSegwit) != 0u) {
        recovery_hash160_digest(compressed_pub, 33u, compressed_hash160);
    }
    if ((params.target_mask & RecoverySecpTargetBitUncompressed) != 0u) {
        recovery_hash160_digest(source.public_key, 65u, uncompressed_hash160);
    }
    if ((params.target_mask & RecoverySecpTargetBitSegwit) != 0u) {
        recovery_build_p2sh_script_from_hash160(compressed_hash160, p2sh_script);
        recovery_hash160_digest(p2sh_script, 22u, segwit_hash160);
    }
    if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u) {
        if ((source.target_ready & RecoverySecpTargetBitTaproot) == 0u) {
            return;
        }
    }
    if ((params.target_mask & RecoverySecpTargetBitEth) != 0u) {
        recovery_keccak256_digest(source.public_key + 1u, 64u, eth_hash);
    }

    if ((params.target_mask & RecoverySecpTargetBitCompressed) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(compressed_hash160, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record(hit, source, 0x02u, compressed_hash160, 20u);
        recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints,
                                            out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitUncompressed) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(uncompressed_hash160, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record(hit, source, 0x01u, uncompressed_hash160, 20u);
        recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints,
                                            out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitSegwit) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(segwit_hash160, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record(hit, source, 0x03u, segwit_hash160, 20u);
        recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints,
                                            out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(source.taproot_xonly, 32u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record(hit, source, 0x04u, source.taproot_xonly, 32u);
        recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints,
                                            out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitXPoint) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(source.public_key + 1u, 32u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record(hit, source, 0x05u, source.public_key + 1u, 32u);
        recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints,
                                            out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitEth) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(eth_hash + 12u, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record(hit, source, 0x06u, eth_hash + 12u, 20u);
        recovery_emit_found_record_filtered(&hit, filter_params, bloom_bytes, xor_fingerprints,
                                            out_records, out_count, params.out_capacity);
    }
}

static inline void recovery_eval_secp_target_nofilter(
    const thread RecoverySecpEvalRecord& source,
    const constant RecoveryEvalSecpKernelParams& params,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    recovery_eval_secp_target(source, params, kRecoveryEmptyFilterParams, nullptr, nullptr, out_records, out_count);
}

static inline void recovery_eval_secp_target_nofilter_direct(
    const thread FoundRecord& base_found,
    const thread cmr_u8* private_key,
    const thread cmr_u8* public_key,
    const thread cmr_u8* taproot_xonly,
    const cmr_u32 target_ready,
    const cmr_u32 derivation_index,
    const cmr_u32 derivation_type,
    const cmr_u32 passphrase_index,
    const constant RecoveryEvalSecpKernelParams& params,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    const cmr_u32 effective_derivation_type =
        derivation_type != 0u ? derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
    if (!recovery_secp_derivation_type_enabled(params.derivation_type_mask, effective_derivation_type)) {
        return;
    }

    thread cmr_u8 compressed_pub[33];
    recovery_build_compressed_pubkey(public_key, compressed_pub);

    thread cmr_u8 compressed_hash160[20];
    thread cmr_u8 uncompressed_hash160[20];
    thread cmr_u8 segwit_hash160[20];
    thread cmr_u8 eth_hash[32];
    thread cmr_u8 p2sh_script[22];

    if ((params.target_mask & RecoverySecpTargetBitCompressed) != 0u ||
        (params.target_mask & RecoverySecpTargetBitSegwit) != 0u) {
        recovery_hash160_digest(compressed_pub, 33u, compressed_hash160);
    }
    if ((params.target_mask & RecoverySecpTargetBitUncompressed) != 0u) {
        recovery_hash160_digest(public_key, 65u, uncompressed_hash160);
    }
    if ((params.target_mask & RecoverySecpTargetBitSegwit) != 0u) {
        recovery_build_p2sh_script_from_hash160(compressed_hash160, p2sh_script);
        recovery_hash160_digest(p2sh_script, 22u, segwit_hash160);
    }
    if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u &&
        (target_ready & RecoverySecpTargetBitTaproot) == 0u) {
        return;
    }
    if ((params.target_mask & RecoverySecpTargetBitEth) != 0u) {
        recovery_keccak256_digest(public_key + 1u, 64u, eth_hash);
    }

    if ((params.target_mask & RecoverySecpTargetBitCompressed) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(compressed_hash160, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record_direct(hit,
                                                    base_found,
                                                    derivation_index,
                                                    effective_derivation_type,
                                                    passphrase_index,
                                                    private_key,
                                                    0x02u,
                                                    compressed_hash160,
                                                    20u);
        recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitUncompressed) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(uncompressed_hash160, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record_direct(hit,
                                                    base_found,
                                                    derivation_index,
                                                    effective_derivation_type,
                                                    passphrase_index,
                                                    private_key,
                                                    0x01u,
                                                    uncompressed_hash160,
                                                    20u);
        recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitSegwit) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(segwit_hash160, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record_direct(hit,
                                                    base_found,
                                                    derivation_index,
                                                    effective_derivation_type,
                                                    passphrase_index,
                                                    private_key,
                                                    0x03u,
                                                    segwit_hash160,
                                                    20u);
        recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(taproot_xonly, 32u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record_direct(hit,
                                                    base_found,
                                                    derivation_index,
                                                    effective_derivation_type,
                                                    passphrase_index,
                                                    private_key,
                                                    0x04u,
                                                    taproot_xonly,
                                                    32u);
        recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitXPoint) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(public_key + 1u, 32u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record_direct(hit,
                                                    base_found,
                                                    derivation_index,
                                                    effective_derivation_type,
                                                    passphrase_index,
                                                    private_key,
                                                    0x05u,
                                                    public_key + 1u,
                                                    32u);
        recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
    }

    if ((params.target_mask & RecoverySecpTargetBitEth) != 0u &&
        (recovery_secp_emit_all_enabled(params) || recovery_secp_target_prefix_matches(eth_hash + 12u, 20u, params))) {
        thread FoundRecord hit;
        recovery_prepare_secp_emitted_record_direct(hit,
                                                    base_found,
                                                    derivation_index,
                                                    effective_derivation_type,
                                                    passphrase_index,
                                                    private_key,
                                                    0x06u,
                                                    eth_hash + 12u,
                                                    20u);
        recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
    }
}

static inline void recovery_eval_secp_target_nofilter_direct_compressed_only(
    const thread FoundRecord& base_found,
    const thread cmr_u8* private_key,
    const thread cmr_u8 compressed_pub[33],
    const cmr_u32 derivation_index,
    const cmr_u32 derivation_type,
    const cmr_u32 passphrase_index,
    const constant RecoveryEvalSecpKernelParams& params,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    const cmr_u32 effective_derivation_type =
        derivation_type != 0u ? derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
    if (!recovery_secp_derivation_type_enabled(params.derivation_type_mask, effective_derivation_type)) {
        return;
    }

    thread cmr_u8 compressed_hash160[20];
    recovery_hash160_digest(compressed_pub, 33u, compressed_hash160);
    if (!recovery_secp_emit_all_enabled(params) &&
        !recovery_secp_target_prefix_matches(compressed_hash160, 20u, params)) {
        return;
    }

    thread FoundRecord hit;
    recovery_prepare_secp_emitted_record_direct(hit,
                                                base_found,
                                                derivation_index,
                                                effective_derivation_type,
                                                passphrase_index,
                                                private_key,
                                                0x02u,
                                                compressed_hash160,
                                                20u);
    recovery_emit_found_record(&hit, out_records, out_count, params.out_capacity);
}

static inline void recovery_eval_secp_target_bloom_only(
    const thread RecoverySecpEvalRecord& source,
    const constant RecoveryEvalSecpKernelParams& params,
    const device cmr_u8* bloom_bytes,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    recovery_eval_secp_target(source, params, kRecoveryBloomOnlyFilterParams, bloom_bytes, nullptr, out_records, out_count);
}

static inline void recovery_eval_secp_target_xor_single(
    const thread RecoverySecpEvalRecord& source,
    const constant RecoveryEvalSecpKernelParams& params,
    const constant RecoveryFilterParams& filter_params,
    const device cmr_u32* xor_fingerprints,
    device FoundRecord* out_records,
    device atomic_uint* out_count) {

    recovery_eval_secp_target(source, params, filter_params, nullptr, xor_fingerprints, out_records, out_count);
}

kernel void workerRecoveryDeriveSecpStage(
    const device MasterSeedRecord* seed_records [[buffer(0)]],
    const device RecoverySecpDerivationProgram* programs [[buffer(1)]],
    device RecoverySecpEvalRecord* out_records [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(4)]],
    const device atomic_uint* seed_count_buffer [[buffer(5)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count;
    const cmr_u32 seed_count = (seed_count_buffer == nullptr)
        ? 0u
        : min(params.passphrase_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.words_count;
    if (seed_count == 0u || program_count == 0u) {
        return;
    }
    const cmr_u64 active_pair_count = min(cmr_u64(limit), cmr_u64(seed_count) * cmr_u64(program_count));
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        if (idx >= active_pair_count) {
            thread RecoverySecpEvalRecord empty_stage;
            recovery_zero_secp_eval_record(empty_stage);
            recovery_copy_eval_record_to_device(&out_records[idx], empty_stage);
            continue;
        }
        const cmr_u32 seed_index = static_cast<cmr_u32>(idx / cmr_u64(program_count));
        const cmr_u32 program_index = static_cast<cmr_u32>(idx % cmr_u64(program_count));
        if (seed_index >= seed_count) {
            thread RecoverySecpEvalRecord empty_stage;
            recovery_zero_secp_eval_record(empty_stage);
            recovery_copy_eval_record_to_device(&out_records[idx], empty_stage);
            continue;
        }

        thread MasterSeedRecord seed_record;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&seed_record, (const device cmr_u8*)&seed_records[seed_index], sizeof(MasterSeedRecord));
        if ((seed_record.hit.flags & RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS) == 0u) {
            thread RecoverySecpEvalRecord empty_stage;
            recovery_zero_secp_eval_record(empty_stage);
            recovery_copy_eval_record_to_device(&out_records[idx], empty_stage);
            continue;
        }

        thread RecoverySecpDerivationProgram program;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&program, (const device cmr_u8*)&programs[program_index], sizeof(RecoverySecpDerivationProgram));

        thread RecoverySecpEvalRecord stage;
        recovery_zero_secp_eval_record(stage);
        recovery_seed_hit_to_found(seed_record.hit, stage.found);
        stage.found.derivation_index = program.derivation_index;
        stage.found.derivation_type = program.derivation_type != 0u ? program.derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
        stage.found.coin_type = 0u;
        stage.found.match_len = 0u;
        stage.found.passphrase_index = program.passphrase_index != 0u ? program.passphrase_index : seed_record.hit.passphrase_index;
        stage.found.flags |= RECOVERY_RECORD_FLAG_STAGE_READY | RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS;
        stage.derivation_ready = 1u;

        thread extended_private_key_t master;
        recovery_derive_secp_master_key(seed_record.master_words, master);
        uint32_t processed = 0u;
        get_child_key_secp256k1(secp_precompute,
                                params.precompute_pitch,
                                &master,
                                program.path_words,
                                recovery_secp_program_path_count(program),
                                processed,
                                stage.private_key,
                                nullptr);
        stage.private_key_ready = 1u;
        recovery_copy_private_key(stage.found, stage.private_key);

        thread secp256k1_pubkey pubkey;
        (void)secp256k1_ec_pubkey_create(&pubkey, stage.private_key, secp_precompute, params.precompute_pitch);
        (void)secp256k1_ec_pubkey_serialize(stage.public_key, 65u, &pubkey, false);
        stage.public_key_ready = 1u;
        if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u) {
            TweakTaproot(stage.taproot_xonly, stage.public_key, secp_precompute, params.precompute_pitch);
            stage.target_ready |= RecoverySecpTargetBitTaproot;
        }

        recovery_copy_eval_record_to_device(&out_records[idx], stage);
    }
}

kernel void workerRecoveryEvalSecpMasterBatchNoFilter(
    const device RecoverySecpMasterRecord* master_records [[buffer(0)]],
    const device atomic_uint* seed_count_buffer [[buffer(1)]],
    const device RecoverySecpDerivationProgram* programs [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(4)]],
    device FoundRecord* out_records [[buffer(5)]],
    device atomic_uint* out_count [[buffer(6)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (master_records == nullptr || programs == nullptr || seed_count_buffer == nullptr ||
        secp_precompute == nullptr || out_records == nullptr || out_count == nullptr ||
        params.out_capacity == 0u || params.target_mask == 0u) {
        return;
    }

    const cmr_u32 seed_count =
        min(params.passphrase_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.words_count;
    if (seed_count == 0u || program_count == 0u) {
        return;
    }

    const cmr_u32 kPathSlotStride = RECOVERY_SECP_MAX_DERIVATION_SEGMENTS;
    const cmr_u32 kPathSlotMask = DERIV_CACHE_SLOTS - 1u;
    const bool compressed_only_target = params.target_mask == RecoverySecpTargetBitCompressed;

    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(seed_count); idx += cmr_u64(threads_per_grid)) {
        thread RecoverySecpMasterRecord master_record;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&master_record,
                                             (const device cmr_u8*)&master_records[idx],
                                             sizeof(RecoverySecpMasterRecord));
        if ((master_record.hit.flags & RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS) == 0u) {
            continue;
        }
        thread FoundRecord base_found;
        recovery_seed_hit_to_found(master_record.hit, base_found);

        thread extended_private_key_t master;
        recovery_copy_thread_bytes(master.key, master_record.master_private_key, 32u);
        recovery_copy_thread_bytes(master.chain_code, master_record.master_chain_code, 32u);

        thread deriv_cache_secp256k1_t deriv_cache;
        deriv_cache_reset(&deriv_cache);
        thread cmr_u32 path_slots[DERIV_CACHE_SLOTS * RECOVERY_SECP_MAX_DERIVATION_SEGMENTS];

        for (cmr_u32 program_index = 0u; program_index < program_count; ++program_index) {
            const device RecoverySecpDerivationProgram& program = programs[program_index];
            const cmr_u32 program_derivation_type =
                program.derivation_type != 0u ? program.derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
            if (!recovery_secp_derivation_type_enabled(params.derivation_type_mask, program_derivation_type)) {
                continue;
            }

            const cmr_u32 path_count =
                program.path_word_count < RECOVERY_SECP_MAX_DERIVATION_SEGMENTS
                    ? program.path_word_count
                    : RECOVERY_SECP_MAX_DERIVATION_SEGMENTS;
            const cmr_u32 slot_index = program_index & kPathSlotMask;
            const cmr_u32 slot_offset = slot_index * kPathSlotStride;

            for (cmr_u32 s = 0u; s < DERIV_CACHE_SLOTS; ++s) {
                if (deriv_cache.valid[s] != 0u && deriv_cache.prev_offset[s] == slot_offset) {
                    deriv_cache.valid[s] = 0u;
                    deriv_cache.hmac_precomp_valid[s] = 0u;
                }
            }
            for (cmr_u32 i = 0u; i < path_count; ++i) {
                path_slots[slot_offset + i] = program.path_words[i];
            }

            const cmr_u32 program_passphrase_index =
                program.passphrase_index != 0u ? program.passphrase_index : master_record.hit.passphrase_index;
            thread cmr_u8 private_key[32];

            cmr_u32 processed = slot_offset;
            get_child_key_secp256k1(secp_precompute,
                                    params.precompute_pitch,
                                    &master,
                                    path_slots,
                                    path_count,
                                    processed,
                                    private_key,
                                    &deriv_cache);

            thread secp256k1_pubkey pubkey;
            (void)secp256k1_ec_pubkey_create(&pubkey, private_key, secp_precompute, params.precompute_pitch);
            if (compressed_only_target) {
                thread cmr_u8 compressed_pub[33];
                (void)secp256k1_ec_pubkey_serialize(compressed_pub, 33u, &pubkey, true);
                recovery_eval_secp_target_nofilter_direct_compressed_only(base_found,
                                                                          private_key,
                                                                          compressed_pub,
                                                                          program.derivation_index,
                                                                          program_derivation_type,
                                                                          program_passphrase_index,
                                                                          params,
                                                                          out_records,
                                                                          out_count);
                continue;
            }

            thread cmr_u8 public_key[65];
            (void)secp256k1_ec_pubkey_serialize(public_key, 65u, &pubkey, false);
            thread cmr_u8 taproot_xonly[32];
            cmr_u32 target_ready = 0u;
            if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u) {
                TweakTaproot(taproot_xonly, public_key, secp_precompute, params.precompute_pitch);
                target_ready |= RecoverySecpTargetBitTaproot;
            }

            recovery_eval_secp_target_nofilter_direct(base_found,
                                                      private_key,
                                                      public_key,
                                                      taproot_xonly,
                                                      target_ready,
                                                      program.derivation_index,
                                                      program_derivation_type,
                                                      program_passphrase_index,
                                                      params,
                                                      out_records,
                                                      out_count);
        }
    }
}

kernel void workerRecoveryEvalSecpMasterBatchCompressedOnly(
    const device RecoverySecpMasterRecord* master_records [[buffer(0)]],
    const device atomic_uint* seed_count_buffer [[buffer(1)]],
    const device RecoverySecpDerivationProgram* programs [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(4)]],
    device FoundRecord* out_records [[buffer(5)]],
    device atomic_uint* out_count [[buffer(6)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (master_records == nullptr || programs == nullptr || seed_count_buffer == nullptr ||
        secp_precompute == nullptr || out_records == nullptr || out_count == nullptr ||
        params.out_capacity == 0u || params.target_mask != RecoverySecpTargetBitCompressed) {
        return;
    }

    const cmr_u32 seed_count =
        min(params.passphrase_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.words_count;
    if (seed_count == 0u || program_count == 0u) {
        return;
    }

    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(seed_count); idx += cmr_u64(threads_per_grid)) {
        const device RecoverySecpMasterRecord& master_record = master_records[idx];
        if ((master_record.hit.flags & RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS) == 0u) {
            continue;
        }

        thread FoundRecord base_found;
        recovery_seed_hit_to_found(master_record.hit, base_found);

        thread extended_private_key_t master;
        recovery_copy_device_to_thread_bytes(master.key, master_record.master_private_key, 32u);
        recovery_copy_device_to_thread_bytes(master.chain_code, master_record.master_chain_code, 32u);

        thread extended_private_key_t prev_parent_key;
        thread extended_private_key_t prev_path_end_key;
        thread cmr_u8 prev_cached_pubkey[33];
        thread hmac_sha512_precomp_t prev_hmac_precomp;
        cmr_u32 prev_program_index = 0u;
        cmr_u32 prev_len = 0u;
        cmr_u32 prev_valid = 0u;
        cmr_u32 prev_last_was_normal = 0u;
        cmr_u32 prev_hmac_precomp_valid = 0u;

        for (cmr_u32 program_index = 0u; program_index < program_count; ++program_index) {
            const device RecoverySecpDerivationProgram& program = programs[program_index];
            const cmr_u32 program_derivation_type =
                program.derivation_type != 0u ? program.derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
            if (!recovery_secp_derivation_type_enabled(params.derivation_type_mask, program_derivation_type)) {
                continue;
            }

            const cmr_u32 path_count =
                program.path_word_count < RECOVERY_SECP_MAX_DERIVATION_SEGMENTS
                    ? program.path_word_count
                    : RECOVERY_SECP_MAX_DERIVATION_SEGMENTS;

            thread extended_private_key_t start_key = master;
            thread extended_private_key_t parent_before_last = master;
            cmr_u32 start_i = 0u;
            bool use_cached_pub = false;
            bool use_hmac_precomp = false;

            if (prev_valid != 0u && path_count > 0u) {
                const device RecoverySecpDerivationProgram& prev_program = programs[prev_program_index];
                const bool same_except_last =
                    path_count == prev_len &&
                    deriv_prefix_equal(program.path_words, prev_program.path_words, path_count - 1u);
                const bool extends_previous =
                    prev_len < path_count &&
                    deriv_prefix_equal(program.path_words, prev_program.path_words, prev_len);

                if (same_except_last) {
                    start_key = prev_parent_key;
                    parent_before_last = prev_parent_key;
                    start_i = path_count - 1u;
                    use_cached_pub =
                        prev_last_was_normal != 0u && program.path_words[path_count - 1u] < 0x80000000u;
                    use_hmac_precomp = prev_hmac_precomp_valid != 0u;
                } else if (extends_previous) {
                    start_key = prev_path_end_key;
                    parent_before_last = prev_path_end_key;
                    start_i = prev_len;
                }
            }

            for (cmr_u32 i = start_i; i < path_count; ++i) {
                if (i == path_count - 1u) {
                    parent_before_last = start_key;
                }
                const cmr_u32 derivation_value = program.path_words[i];
                if (derivation_value < 0x80000000u) {
                    if (i == path_count - 1u && use_cached_pub && use_hmac_precomp) {
                        normal_private_child_from_private_cached_pub_precomp(&start_key,
                                                                             &start_key,
                                                                             derivation_value,
                                                                             prev_cached_pubkey,
                                                                             &prev_hmac_precomp);
                    } else if (i == path_count - 1u && use_cached_pub) {
                        normal_private_child_from_private_cached_pub(&start_key,
                                                                     &start_key,
                                                                     derivation_value,
                                                                     prev_cached_pubkey);
                    } else if (i == path_count - 1u) {
                        normal_private_child_from_private_save_pub(secp_precompute,
                                                                   params.precompute_pitch,
                                                                   &start_key,
                                                                   &start_key,
                                                                   derivation_value,
                                                                   prev_cached_pubkey);
                    } else {
                        normal_private_child_from_private(secp_precompute,
                                                          params.precompute_pitch,
                                                          &start_key,
                                                          &start_key,
                                                          derivation_value);
                    }
                } else {
                    if (i == path_count - 1u && use_hmac_precomp) {
                        hardened_private_child_from_private_precomp(&start_key,
                                                                    &start_key,
                                                                    derivation_value,
                                                                    &prev_hmac_precomp);
                    } else {
                        hardened_private_child_from_private(&start_key, &start_key, derivation_value);
                    }
                }
            }

            thread secp256k1_pubkey pubkey;
            (void)secp256k1_ec_pubkey_create(&pubkey, start_key.key, secp_precompute, params.precompute_pitch);
            thread cmr_u8 compressed_pub[33];
            (void)secp256k1_ec_pubkey_serialize(compressed_pub, 33u, &pubkey, true);

            const cmr_u32 program_passphrase_index =
                program.passphrase_index != 0u ? program.passphrase_index : master_record.hit.passphrase_index;
            recovery_eval_secp_target_nofilter_direct_compressed_only(base_found,
                                                                      start_key.key,
                                                                      compressed_pub,
                                                                      program.derivation_index,
                                                                      program_derivation_type,
                                                                      program_passphrase_index,
                                                                      params,
                                                                      out_records,
                                                                      out_count);

            prev_program_index = program_index;
            prev_len = path_count;
            prev_valid = 1u;
            prev_last_was_normal =
                (path_count != 0u && program.path_words[path_count - 1u] < 0x80000000u) ? 1u : 0u;
            prev_parent_key = parent_before_last;
            prev_path_end_key = start_key;
            hmac_sha512_const_precompute(reinterpret_cast<const thread cmr_u32*>(parent_before_last.chain_code),
                                         &prev_hmac_precomp);
            prev_hmac_precomp_valid = 1u;
        }
    }
}

kernel void workerRecoveryEvalSecpMasterBatchCompressedOnlyNoReuse(
    const device RecoverySecpMasterRecord* master_records [[buffer(0)]],
    const device atomic_uint* seed_count_buffer [[buffer(1)]],
    const device RecoverySecpDerivationProgram* programs [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(4)]],
    device FoundRecord* out_records [[buffer(5)]],
    device atomic_uint* out_count [[buffer(6)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (master_records == nullptr || programs == nullptr || seed_count_buffer == nullptr ||
        secp_precompute == nullptr || out_records == nullptr || out_count == nullptr ||
        params.out_capacity == 0u || params.target_mask != RecoverySecpTargetBitCompressed) {
        return;
    }

    const cmr_u32 seed_count =
        min(params.passphrase_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.words_count;
    if (seed_count == 0u || program_count == 0u) {
        return;
    }

    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(seed_count); idx += cmr_u64(threads_per_grid)) {
        const device RecoverySecpMasterRecord& master_record = master_records[idx];
        if ((master_record.hit.flags & RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS) == 0u) {
            continue;
        }

        thread FoundRecord base_found;
        recovery_seed_hit_to_found(master_record.hit, base_found);

        thread extended_private_key_t master;
        recovery_copy_device_to_thread_bytes(master.key, master_record.master_private_key, 32u);
        recovery_copy_device_to_thread_bytes(master.chain_code, master_record.master_chain_code, 32u);

        for (cmr_u32 program_index = 0u; program_index < program_count; ++program_index) {
            const device RecoverySecpDerivationProgram& program = programs[program_index];
            const cmr_u32 program_derivation_type =
                program.derivation_type != 0u ? program.derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
            if (!recovery_secp_derivation_type_enabled(params.derivation_type_mask, program_derivation_type)) {
                continue;
            }

            const cmr_u32 path_count =
                program.path_word_count < RECOVERY_SECP_MAX_DERIVATION_SEGMENTS
                    ? program.path_word_count
                    : RECOVERY_SECP_MAX_DERIVATION_SEGMENTS;
            thread extended_private_key_t child = master;
            for (cmr_u32 i = 0u; i < path_count; ++i) {
                const cmr_u32 derivation_value = program.path_words[i];
                if (derivation_value < 0x80000000u) {
                    normal_private_child_from_private(secp_precompute,
                                                      params.precompute_pitch,
                                                      &child,
                                                      &child,
                                                      derivation_value);
                } else {
                    hardened_private_child_from_private(&child, &child, derivation_value);
                }
            }

            thread secp256k1_pubkey pubkey;
            (void)secp256k1_ec_pubkey_create(&pubkey, child.key, secp_precompute, params.precompute_pitch);
            thread cmr_u8 compressed_pub[33];
            (void)secp256k1_ec_pubkey_serialize(compressed_pub, 33u, &pubkey, true);

            const cmr_u32 program_passphrase_index =
                program.passphrase_index != 0u ? program.passphrase_index : master_record.hit.passphrase_index;
            recovery_eval_secp_target_nofilter_direct_compressed_only(base_found,
                                                                      child.key,
                                                                      compressed_pub,
                                                                      program.derivation_index,
                                                                      program_derivation_type,
                                                                      program_passphrase_index,
                                                                      params,
                                                                      out_records,
                                                                      out_count);
        }
    }
}

kernel void workerRecoveryPromoteEd25519ToSecpStage(
    const device RecoveryEd25519StageRecord* ed_stage_records [[buffer(0)]],
    device RecoverySecpEvalRecord* out_records [[buffer(1)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(2)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(3)]],
    const device atomic_uint* seed_count_buffer [[buffer(4)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count < params.out_capacity ? params.record_count : params.out_capacity;
    const cmr_u32 seed_count = (seed_count_buffer == nullptr)
        ? 0u
        : min(params.passphrase_count, atomic_load_explicit(seed_count_buffer, memory_order_relaxed));
    const cmr_u32 program_count = params.words_count;
    const cmr_u64 active_pair_count = (seed_count == 0u || program_count == 0u)
        ? 0u
        : min(cmr_u64(limit), cmr_u64(seed_count) * cmr_u64(program_count));
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        if (idx >= active_pair_count) {
            thread RecoverySecpEvalRecord empty_stage;
            recovery_zero_secp_eval_record(empty_stage);
            recovery_copy_eval_record_to_device(&out_records[idx], empty_stage);
            continue;
        }
        thread RecoveryEd25519StageRecord ed_stage;
        thread RecoverySecpEvalRecord secp_stage;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&ed_stage, (const device cmr_u8*)&ed_stage_records[idx], sizeof(RecoveryEd25519StageRecord));
        recovery_zero_secp_eval_record(secp_stage);

        if (ed_stage.private_key_ready != 0u) {
            secp_stage.found = ed_stage.found;
            secp_stage.found.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;
            recovery_copy_thread_bytes(secp_stage.private_key, ed_stage.found.private_key, 32u);
            recovery_copy_private_key(secp_stage.found, secp_stage.private_key);
            secp_stage.private_key_ready = 1u;
            secp_stage.derivation_ready = 1u;

            thread secp256k1_pubkey pubkey;
            (void)secp256k1_ec_pubkey_create(&pubkey, secp_stage.private_key, secp_precompute, params.precompute_pitch);
            (void)secp256k1_ec_pubkey_serialize(secp_stage.public_key, 65u, &pubkey, false);
            secp_stage.public_key_ready = 1u;
            if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u) {
                TweakTaproot(secp_stage.taproot_xonly, secp_stage.public_key, secp_precompute, params.precompute_pitch);
                secp_stage.target_ready |= RecoverySecpTargetBitTaproot;
            }
        }

        recovery_copy_eval_record_to_device(&out_records[idx], secp_stage);
    }
}

kernel void workerRecoveryRuntimeConsumeSecpSeeds(
    const device MasterSeedRecord* seed_records [[buffer(0)]],
    device RecoveryRingHeader* seed_ring [[buffer(1)]],
    const device RecoverySecpDerivationProgram* programs [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(4)]],
    device RecoveryRuntimeState* runtime_state [[buffer(5)]],
    device FoundRecord* out_records [[buffer(6)]],
    device atomic_uint* out_count [[buffer(7)]],
    constant RecoveryFilterParams& filter_params [[buffer(8)]],
    const device cmr_u8* bloom_bytes [[buffer(9)]],
    const device cmr_u32* xor_fingerprints [[buffer(10)]],
    device RecoveryRingHeader* promote_ring [[buffer(11)]],
    device RecoverySecpEvalRecord* promote_records [[buffer(12)]],
    uint lid [[thread_position_in_threadgroup]]) {

    if (seed_records == nullptr || seed_ring == nullptr || programs == nullptr || runtime_state == nullptr ||
        secp_precompute == nullptr || out_records == nullptr || out_count == nullptr) {
        return;
    }

    const cmr_u32 program_count = params.words_count;
    const bool want_promote = promote_ring != nullptr && promote_records != nullptr && promote_ring->capacity != 0u;
    const bool run_secp_eval = params.target_mask != 0u && params.out_capacity != 0u;

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

            thread RecoverySecpDerivationProgram program;
            recovery_copy_device_to_thread_bytes((thread cmr_u8*)&program,
                                                 (const device cmr_u8*)&programs[program_index],
                                                 sizeof(RecoverySecpDerivationProgram));

            thread RecoverySecpEvalRecord stage;
            recovery_zero_secp_eval_record(stage);
            recovery_seed_hit_to_found(seed_record.hit, stage.found);
            stage.found.derivation_index = program.derivation_index;
            stage.found.derivation_type = program.derivation_type != 0u ? program.derivation_type : RESULT_DERIVATION_BIP32_SECP256K1;
            stage.found.coin_type = 0u;
            stage.found.match_len = 0u;
            stage.found.passphrase_index = program.passphrase_index != 0u ? program.passphrase_index : seed_record.hit.passphrase_index;
            stage.found.flags |= RECOVERY_RECORD_FLAG_STAGE_READY | RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS;
            stage.derivation_ready = 1u;

            thread extended_private_key_t master;
            recovery_derive_secp_master_key(seed_record.master_words, master);
            uint32_t processed = 0u;
            get_child_key_secp256k1(secp_precompute,
                                    params.precompute_pitch,
                                    &master,
                                    program.path_words,
                                    recovery_secp_program_path_count(program),
                                    processed,
                                    stage.private_key,
                                    nullptr);
            stage.private_key_ready = 1u;
            recovery_copy_private_key(stage.found, stage.private_key);

            thread secp256k1_pubkey pubkey;
            (void)secp256k1_ec_pubkey_create(&pubkey, stage.private_key, secp_precompute, params.precompute_pitch);
            (void)secp256k1_ec_pubkey_serialize(stage.public_key, 65u, &pubkey, false);
            stage.public_key_ready = 1u;
            if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u) {
                TweakTaproot(stage.taproot_xonly, stage.public_key, secp_precompute, params.precompute_pitch);
                stage.target_ready |= RecoverySecpTargetBitTaproot;
            }

            if (run_secp_eval) {
                recovery_eval_secp_target(stage, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
                if (atomic_load_explicit(out_count, memory_order_relaxed) >= params.out_capacity) {
                    recovery_runtime_request_stop(runtime_state);
                }
            }

            if (want_promote) {
                while (recovery_runtime_should_stop(runtime_state) == 0u) {
                    cmr_u32 out_reservation = 0u;
                    if (!recovery_ring_try_reserve_write(promote_ring, &out_reservation)) {
                        continue;
                    }
                    const cmr_u32 out_slot = out_reservation % promote_ring->capacity;
                    recovery_copy_eval_record_to_device(&promote_records[out_slot], stage);
                    recovery_ring_publish_write(promote_ring, out_reservation);
                    break;
                }
            }
        }
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (lid == 0u && recovery_runtime_group_done(&runtime_state->secp_groups_live) != 0u && want_promote) {
        recovery_ring_close(promote_ring);
    }
}

kernel void workerRecoveryRuntimeConsumePromotedEdStages(
    const device RecoveryEd25519StageRecord* ed_stage_records [[buffer(0)]],
    device RecoveryRingHeader* stage_ring [[buffer(1)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(2)]],
    constant secp256k1_ge_storage* secp_precompute [[buffer(3)]],
    device RecoveryRuntimeState* runtime_state [[buffer(4)]],
    device FoundRecord* out_records [[buffer(5)]],
    device atomic_uint* out_count [[buffer(6)]],
    constant RecoveryFilterParams& filter_params [[buffer(7)]],
    const device cmr_u8* bloom_bytes [[buffer(8)]],
    const device cmr_u32* xor_fingerprints [[buffer(9)]]) {

    if (ed_stage_records == nullptr || stage_ring == nullptr || runtime_state == nullptr ||
        secp_precompute == nullptr || out_records == nullptr || out_count == nullptr ||
        params.out_capacity == 0u || params.target_mask == 0u) {
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
        thread RecoveryEd25519StageRecord ed_stage;
        thread RecoverySecpEvalRecord secp_stage;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&ed_stage,
                                             (const device cmr_u8*)&ed_stage_records[slot],
                                             sizeof(RecoveryEd25519StageRecord));
        recovery_zero_secp_eval_record(secp_stage);

        if (ed_stage.private_key_ready != 0u) {
            secp_stage.found = ed_stage.found;
            secp_stage.found.flags |= RECOVERY_RECORD_FLAG_STAGE_READY;
            recovery_copy_thread_bytes(secp_stage.private_key, ed_stage.found.private_key, 32u);
            recovery_copy_private_key(secp_stage.found, secp_stage.private_key);
            secp_stage.private_key_ready = 1u;
            secp_stage.derivation_ready = 1u;

            thread secp256k1_pubkey pubkey;
            (void)secp256k1_ec_pubkey_create(&pubkey, secp_stage.private_key, secp_precompute, params.precompute_pitch);
            (void)secp256k1_ec_pubkey_serialize(secp_stage.public_key, 65u, &pubkey, false);
            secp_stage.public_key_ready = 1u;
            if ((params.target_mask & RecoverySecpTargetBitTaproot) != 0u) {
                TweakTaproot(secp_stage.taproot_xonly, secp_stage.public_key, secp_precompute, params.precompute_pitch);
                secp_stage.target_ready |= RecoverySecpTargetBitTaproot;
            }
        }

        recovery_eval_secp_target(secp_stage, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
        if (atomic_load_explicit(out_count, memory_order_relaxed) >= params.out_capacity) {
            recovery_runtime_request_stop(runtime_state);
        }
    }
}

kernel void workerRecoveryEvalSecpStage(
    const device RecoverySecpEvalRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant RecoveryFilterParams& filter_params [[buffer(4)]],
    const device cmr_u8* bloom_bytes [[buffer(5)]],
    const device cmr_u32* xor_fingerprints [[buffer(6)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count;
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        thread RecoverySecpEvalRecord stage;
        recovery_copy_eval_record_from_device(stage, &stage_records[idx]);
        recovery_eval_secp_target(stage, params, filter_params, bloom_bytes, xor_fingerprints, out_records, out_count);
    }
}

kernel void workerRecoveryEvalSecpStageBloomOnly(
    const device RecoverySecpEvalRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    const device cmr_u8* bloom_bytes [[buffer(4)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count;
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        thread RecoverySecpEvalRecord stage;
        recovery_copy_eval_record_from_device(stage, &stage_records[idx]);
        recovery_eval_secp_target_bloom_only(stage, params, bloom_bytes, out_records, out_count);
    }
}

kernel void workerRecoveryEvalSecpStageXorSingle(
    const device RecoverySecpEvalRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    constant RecoveryFilterParams& filter_params [[buffer(4)]],
    const device cmr_u32* xor_fingerprints [[buffer(5)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count;
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        thread RecoverySecpEvalRecord stage;
        recovery_copy_eval_record_from_device(stage, &stage_records[idx]);
        recovery_eval_secp_target_xor_single(stage, params, filter_params, xor_fingerprints, out_records, out_count);
    }
}

kernel void workerRecoveryEvalSecpStageNoFilter(
    const device RecoverySecpEvalRecord* stage_records [[buffer(0)]],
    device FoundRecord* out_records [[buffer(1)]],
    device atomic_uint* out_count [[buffer(2)]],
    constant RecoveryEvalSecpKernelParams& params [[buffer(3)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    const cmr_u32 limit = params.record_count;
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        thread RecoverySecpEvalRecord stage;
        recovery_copy_eval_record_from_device(stage, &stage_records[idx]);
        recovery_eval_secp_target_nofilter(stage, params, out_records, out_count);
    }
}
