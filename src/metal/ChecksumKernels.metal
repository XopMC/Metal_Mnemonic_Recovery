#include <metal_stdlib>
using namespace metal;

#include "metal/RecoveryCryptoCommon.h"
#include "metal/RecoveryMetalTypes.h"

constant char kRecoverySecpSeedLabel[] = "Bitcoin seed";

static inline bool checksum_valid(const thread ushort ids[48], const uint words_count) {
    if (words_count == 0u || words_count > 48u || (words_count % 3u) != 0u) {
        return false;
    }

    const uint total_bits = words_count * 11u;
    const uint ent_bits = (total_bits * 32u) / 33u;
    const uint cs_bits = total_bits - ent_bits;
    const uint ent_bytes = (ent_bits + 7u) >> 3u;

    uchar bits[68];
    uchar entropy[68];
    uchar digest[32];

    for (uint i = 0; i < 68u; ++i) {
        bits[i] = 0u;
        entropy[i] = 0u;
    }

    uint bitpos = 0u;
    for (uint i = 0; i < words_count; ++i) {
        const uint value = uint(ids[i] & 0x7FFu);
        for (int bit = 10; bit >= 0; --bit) {
            const uchar current = uchar((value >> uint(bit)) & 1u);
            bits[bitpos >> 3u] |= uchar(current << (7u - (bitpos & 7u)));
            ++bitpos;
        }
    }

    for (uint i = 0; i < ent_bytes; ++i) {
        entropy[i] = bits[i];
    }
    if ((ent_bits & 7u) != 0u && ent_bytes > 0u) {
        entropy[ent_bytes - 1u] &= uchar(0xFFu << (8u - (ent_bits & 7u)));
    }

    recovery_sha256_digest(entropy, ent_bytes, digest);

    for (uint i = 0; i < cs_bits; ++i) {
        const uint phrase_bit_pos = ent_bits + i;
        const uchar phrase_bit = uchar((bits[phrase_bit_pos >> 3u] >> (7u - (phrase_bit_pos & 7u))) & 1u);
        const uchar digest_bit = uchar((digest[i >> 3u] >> (7u - (i & 7u))) & 1u);
        if (phrase_bit != digest_bit) {
            return false;
        }
    }
    return true;
}

kernel void workerRecoveryChecksum(
    const device ushort* base_ids [[buffer(0)]],
    const device int* missing_positions [[buffer(1)]],
    device ushort* out_ids [[buffer(2)]],
    device atomic_uint* out_count [[buffer(3)]],
    constant ChecksumParams& params [[buffer(4)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    thread ushort ids[48];
    for (uint i = 0; i < params.words_count; ++i) {
        ids[i] = base_ids[i];
    }

    for (ulong local = ulong(gid); local < params.range_count; local += ulong(threads_per_grid)) {
        ulong combo = params.range_start + local;

        for (uint miss = 0; miss < params.missing_count; ++miss) {
            const int position = missing_positions[miss];
            ids[position] = ushort(combo & 0x7FFul);
            combo >>= 11u;
        }

        if (!checksum_valid(ids, params.words_count)) {
            continue;
        }

        const uint slot = atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed);
        if (slot >= params.out_capacity) {
            continue;
        }

        const uint offset = slot * 48u;
        for (uint i = 0; i < params.words_count; ++i) {
            out_ids[offset + i] = ids[i];
        }
    }
}

static inline void recovery_pbkdf2_copy_salt_count_bytes(
    thread cmr_u8* dst,
    const cmr_u32 len,
    const thread cmr_u8* salt,
    const cmr_u32 nsalt,
    const cmr_u8 countbuf[4],
    const cmr_u32 offset) {

    cmr_u32 copied = 0u;
    if (offset < nsalt) {
        const cmr_u32 salt_avail = nsalt - offset;
        const cmr_u32 take_salt = len < salt_avail ? len : salt_avail;
        recovery_copy_thread_bytes(dst, salt + offset, take_salt);
        copied = take_salt;
    }
    const cmr_u32 rem = len - copied;
    if (rem != 0u) {
        const cmr_u32 count_off = offset + copied - nsalt;
        recovery_copy_thread_bytes(dst + copied, countbuf + count_off, rem);
    }
}

static inline void recovery_pbkdf2_u1_sha512_words(
    const thread RecoveryHmacSha512Precomp* startctx,
    const cmr_u32 counter,
    const thread cmr_u8* salt,
    const cmr_u32 nsalt,
    thread cmr_u64 out_words[8]) {

    cmr_u8 countbuf[4];
    recovery_sha256_store_be32(counter, countbuf);
    const cmr_u32 msg_len = nsalt + 4u;
    const cmr_u32 total_inner_bits = (128u + msg_len) * 8u;

    if (msg_len < 112u) {
        cmr_u64 block_words[16];
        for (cmr_u32 i = 0u; i < 16u; ++i) {
            cmr_u64 word = 0ull;
            const cmr_u32 word_base = i * 8u;
            for (cmr_u32 j = 0u; j < 8u; ++j) {
                const cmr_u32 byte_offset = word_base + j;
                cmr_u8 byte = 0u;
                if (byte_offset < nsalt) {
                    byte = salt[byte_offset];
                } else if (byte_offset < msg_len) {
                    byte = countbuf[byte_offset - nsalt];
                } else if (byte_offset == msg_len) {
                    byte = 0x80u;
                } else if (byte_offset >= 120u) {
                    const cmr_u32 shift = (127u - byte_offset) * 8u;
                    byte = cmr_u8((cmr_u64(total_inner_bits) >> shift) & 0xFFull);
                }
                word = (word << 8u) | cmr_u64(byte);
            }
            block_words[i] = word;
        }

        thread cmr_u64 inner_out[8];
        recovery_sha512_transform_words(startctx->inner_H, inner_out, block_words);

        cmr_u64 outer_block[16] = { 0 };
        for (cmr_u32 j = 0u; j < 8u; ++j) {
            outer_block[j] = inner_out[j];
        }
        outer_block[8] = 0x8000000000000000ull;
        outer_block[15] = 0x0000000000000600ull;
        recovery_sha512_transform_words(startctx->outer_H, out_words, outer_block);
        return;
    }

    thread cmr_u8 block_bytes[128];
    cmr_u64 block_words[16];
    cmr_u64 inner_a[8];
    cmr_u64 inner_b[8];
    const thread cmr_u64* in_state = startctx->inner_H;
    thread cmr_u64* out_state = inner_a;
    cmr_u32 offset = 0u;
    cmr_u32 remaining = msg_len;

    while (remaining >= 128u) {
        recovery_pbkdf2_copy_salt_count_bytes(block_bytes, 128u, salt, nsalt, countbuf, offset);
        for (cmr_u32 i = 0u; i < 16u; ++i) {
            block_words[i] = recovery_sha512_load_be64(block_bytes, i * 8u);
        }
        recovery_sha512_transform_words(in_state, out_state, block_words);
        in_state = out_state;
        out_state = (out_state == inner_a) ? inner_b : inner_a;
        offset += 128u;
        remaining -= 128u;
    }

    recovery_zero_thread_bytes(block_bytes, 128u);
    if (remaining != 0u) {
        recovery_pbkdf2_copy_salt_count_bytes(block_bytes, remaining, salt, nsalt, countbuf, offset);
    }
    block_bytes[remaining] = 0x80u;
    if (remaining >= 112u) {
        for (cmr_u32 i = 0u; i < 16u; ++i) {
            block_words[i] = recovery_sha512_load_be64(block_bytes, i * 8u);
        }
        recovery_sha512_transform_words(in_state, out_state, block_words);
        in_state = out_state;
        out_state = (out_state == inner_a) ? inner_b : inner_a;
        recovery_zero_thread_bytes(block_bytes, 128u);
    }
    recovery_sha512_store_be64(cmr_u64(total_inner_bits), block_bytes + 120u);
    for (cmr_u32 i = 0u; i < 16u; ++i) {
        block_words[i] = recovery_sha512_load_be64(block_bytes, i * 8u);
    }
    recovery_sha512_transform_words(in_state, out_state, block_words);

    cmr_u64 outer_block[16] = { 0 };
    for (cmr_u32 j = 0u; j < 8u; ++j) {
        outer_block[j] = out_state[j];
    }
    outer_block[8] = 0x8000000000000000ull;
    outer_block[15] = 0x0000000000000600ull;
    recovery_sha512_transform_words(startctx->outer_H, out_words, outer_block);
}

static inline void recovery_pbkdf2_hmac_sha512_64(
    const thread cmr_u8* password,
    const cmr_u32 password_len,
    const thread cmr_u8* salt,
    const cmr_u32 salt_len,
    const cmr_u64 iterations,
    thread cmr_u8 out[64]) {

    if (password == nullptr || salt == nullptr || password_len == 0u || iterations == 0u) {
        recovery_zero_thread_bytes(out, 64u);
        return;
    }

    thread RecoveryHmacSha512Precomp ctx;
    recovery_hmac_sha512_precompute(password, password_len, &ctx);

    thread cmr_u64 resultH[8];
    recovery_pbkdf2_u1_sha512_words(&ctx, 1u, salt, salt_len, resultH);

    thread cmr_u64 u_prev_words[8];
    thread cmr_u64 u_curr_words[8];
    for (cmr_u32 j = 0u; j < 8u; ++j) {
        u_prev_words[j] = resultH[j];
    }

    for (cmr_u64 i = 1u; i < iterations; ++i) {
        recovery_hmac_sha512_from_precomp_64_words(&ctx, u_prev_words, u_curr_words);
        for (cmr_u32 j = 0u; j < 8u; ++j) {
            resultH[j] ^= u_curr_words[j];
            u_prev_words[j] = u_curr_words[j];
        }
    }

    for (cmr_u32 j = 0u; j < 8u; ++j) {
        recovery_sha512_store_be64(resultH[j], out + (j * 8u));
    }
}

static inline cmr_u32 recovery_build_phrase_from_ids(
    const thread cmr_u32* ids,
    const cmr_u32 words_count,
    const device char* dict_words,
    const cmr_u32 dict_stride,
    thread char* out,
    const cmr_u32 out_capacity) {

    if (ids == nullptr || dict_words == nullptr || out == nullptr || out_capacity < 2u || words_count == 0u || words_count > RECOVERY_MAX_WORDS) {
        return 0u;
    }

    cmr_u32 out_len = 0u;
    const cmr_u32 limit = out_capacity - 1u;

    for (cmr_u32 i = 0u; i < words_count; ++i) {
        const cmr_u32 word_index = ids[i] & 0x7FFu;
        const device char* word = dict_words + (cmr_u64(word_index) * cmr_u64(dict_stride));
        for (cmr_u32 j = 0u; j < dict_stride; ++j) {
            const char c = word[j];
            if (c == '\0') {
                break;
            }
            if (out_len >= limit) {
                out[0] = '\0';
                return 0u;
            }
            out[out_len++] = c;
        }

        if ((i + 1u) < words_count) {
            if (out_len >= limit) {
                out[0] = '\0';
                return 0u;
            }
            out[out_len++] = ' ';
        }
    }

    out[out_len] = '\0';
    return out_len;
}

static inline cmr_u32 recovery_build_phrase_from_hit_ids(
    const thread cmr_u16* ids,
    const cmr_u32 words_count,
    const device char* dict_words,
    const cmr_u32 dict_stride,
    thread char* out,
    const cmr_u32 out_capacity) {

    if (ids == nullptr || dict_words == nullptr || out == nullptr || out_capacity < 2u || words_count == 0u || words_count > RECOVERY_MAX_WORDS) {
        return 0u;
    }

    cmr_u32 out_len = 0u;
    const cmr_u32 limit = out_capacity - 1u;

    for (cmr_u32 i = 0u; i < words_count; ++i) {
        const cmr_u32 word_index = cmr_u32(ids[i] & 0x07FFu);
        const device char* word = dict_words + (cmr_u64(word_index) * cmr_u64(dict_stride));
        for (cmr_u32 j = 0u; j < dict_stride; ++j) {
            const char c = word[j];
            if (c == '\0') {
                break;
            }
            if (out_len >= limit) {
                out[0] = '\0';
                return 0u;
            }
            out[out_len++] = c;
        }

        if ((i + 1u) < words_count) {
            if (out_len >= limit) {
                out[0] = '\0';
                return 0u;
            }
            out[out_len++] = ' ';
        }
    }

    out[out_len] = '\0';
    return out_len;
}

static inline bool recovery_phrase_to_master_words(
    const thread char* phrase,
    const cmr_u32 phrase_len,
    const device char* passphrase,
    const cmr_u32 pass_size,
    const cmr_u64 iterations,
    thread cmr_u32 out_master_words[RECOVERY_MASTER_WORDS]) {

    if (phrase == nullptr || out_master_words == nullptr || phrase_len == 0u || iterations == 0u || pass_size > RECOVERY_MAX_PASSPHRASE_BYTES) {
        recovery_zero_thread_bytes((thread cmr_u8*)out_master_words, RECOVERY_MASTER_WORDS * sizeof(cmr_u32));
        return false;
    }
    if (pass_size > 0u && passphrase == nullptr) {
        recovery_zero_thread_bytes((thread cmr_u8*)out_master_words, RECOVERY_MASTER_WORDS * sizeof(cmr_u32));
        return false;
    }

    thread cmr_u8 salt[RECOVERY_MAX_PASSPHRASE_BYTES + 8u];
    salt[0] = 'm';
    salt[1] = 'n';
    salt[2] = 'e';
    salt[3] = 'm';
    salt[4] = 'o';
    salt[5] = 'n';
    salt[6] = 'i';
    salt[7] = 'c';
    for (cmr_u32 i = 0u; i < pass_size; ++i) {
        salt[8u + i] = cmr_u8(passphrase[i]);
    }

    thread cmr_u8 seed[64];
    recovery_pbkdf2_hmac_sha512_64(
        (const thread cmr_u8*)phrase,
        phrase_len,
        salt,
        8u + pass_size,
        iterations,
        seed);

    thread cmr_u8* out_seed_bytes = reinterpret_cast<thread cmr_u8*>(out_master_words);
    for (cmr_u32 chunk = 0u; chunk < 8u; ++chunk) {
        const cmr_u32 base = chunk * 8u;
        for (cmr_u32 i = 0u; i < 8u; ++i) {
            out_seed_bytes[base + i] = seed[base + (7u - i)];
        }
    }
    return true;
}

static inline void recovery_write_checksum_hit_record(
    const thread ushort* ids,
    const cmr_u32 words_count,
    constant ChecksumStageParams& params,
    const cmr_u64 candidate_index,
    thread ChecksumHitRecord* out_record) {

    recovery_zero_thread_bytes((thread cmr_u8*)out_record, sizeof(ChecksumHitRecord));
    out_record->word_count = cmr_u16(words_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : words_count);
    for (cmr_u32 i = 0u; i < cmr_u32(out_record->word_count); ++i) {
        out_record->word_ids[i] = cmr_u16(ids[i] & 0x07FFu);
    }
    out_record->derivation_index = params.derivation_index;
    out_record->derivation_type = params.derivation_type;
    out_record->coin_type = params.coin_type;
    out_record->flags = params.flags | RECOVERY_RECORD_FLAG_CHECKSUM_VALID | RECOVERY_RECORD_FLAG_STAGE_READY;
    out_record->passphrase_index = params.passphrase_index;
    out_record->match_len = params.match_len != 0u ? params.match_len : recovery_match_size_for_type(params.coin_type);
    out_record->round_delta = params.round_delta;
    out_record->candidate_index = candidate_index;
}

static inline bool recovery_expand_checksum_tile_candidate(
    const device ushort* base_ids,
    const device int* missing_positions,
    const device ushort* start_digits,
    const cmr_u32 words_count,
    const cmr_u32 missing_count,
    const cmr_u64 local_index,
    thread ushort* out_ids) {

    for (cmr_u32 i = 0u; i < words_count; ++i) {
        out_ids[i] = base_ids[i];
    }

    cmr_u64 carry = local_index;
    for (cmr_u32 miss = 0u; miss < missing_count; ++miss) {
        const cmr_u32 position = cmr_u32(missing_positions[miss]);
        const cmr_u64 digit_add = carry & 0x7FFull;
        carry >>= 11u;

        cmr_u64 digit = cmr_u64(start_digits[miss] & 0x07FFu) + digit_add;
        if (digit >= 2048ull) {
            digit -= 2048ull;
            carry += 1ull;
        }
        out_ids[position] = ushort(digit);
    }

    return carry == 0ull;
}

static inline bool recovery_expand_checksum_tile_candidate(
    const device ushort* base_ids,
    const device int* missing_positions,
    const threadgroup ushort* start_digits,
    const uint words_count,
    const uint missing_count,
    const cmr_u64 local_index,
    thread ushort out_ids[RECOVERY_MAX_WORDS]) {

    for (uint i = 0u; i < words_count && i < RECOVERY_MAX_WORDS; ++i) {
        out_ids[i] = base_ids[i];
    }

    cmr_u64 carry = local_index;
    for (cmr_u32 miss = 0u; miss < missing_count; ++miss) {
        const cmr_u32 position = cmr_u32(missing_positions[miss]);
        const cmr_u64 digit_add = carry & 0x7FFull;
        carry >>= 11u;

        cmr_u64 digit = cmr_u64(start_digits[miss] & 0x07FFu) + digit_add;
        if (digit >= 2048ull) {
            digit -= 2048ull;
            carry += 1ull;
        }
        out_ids[position] = ushort(digit);
    }

    return carry == 0ull;
}

static inline bool recovery_checksum_cursor_advance(thread ChecksumCursorState& cursor,
                                                    const cmr_u64 advance_by) {
    cmr_u64 carry = advance_by;
    const cmr_u32 digit_count = cursor.missing_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : cursor.missing_count;
    for (cmr_u32 index = 0u; index < digit_count; ++index) {
        const cmr_u64 digit_add = carry & 0x7FFull;
        carry >>= 11u;

        cmr_u64 value = cmr_u64(cursor.digit_cursor[index] & 0x07FFu) + digit_add;
        if (value >= 2048ull) {
            value -= 2048ull;
            carry += 1ull;
        }
        cursor.digit_cursor[index] = cmr_u16(value);
        if (carry == 0ull) {
            return false;
        }
    }

    cursor.exhausted = carry != 0ull ? 1u : 0u;
    return cursor.exhausted != 0u;
}

static inline cmr_u64 recovery_checksum_runtime_u64(const cmr_u32 lo, const cmr_u32 hi) {
    return (cmr_u64(hi) << 32u) | cmr_u64(lo);
}

static inline cmr_u64 recovery_checksum_cursor_prepare_next_batch(thread ChecksumCursorState& cursor) {
    if (cursor.exhausted != 0u) {
        return 0ull;
    }

    cmr_u64 range_count = 0ull;
    const bool batch_limit_enabled = cursor.remaining_batches != 0ull;
    if (batch_limit_enabled) {
        cursor.remaining_batches -= 1ull;
    }
    if (cursor.missing_count == 0u) {
        range_count = 1ull;
        cursor.exhausted = 1u;
    } else {
        range_count = cursor.batch_candidate_capacity == 0ull ? 1ull : cursor.batch_candidate_capacity;
        (void)recovery_checksum_cursor_advance(cursor, range_count);
    }

    if (batch_limit_enabled && cursor.remaining_batches == 0ull) {
        cursor.exhausted = 1u;
    }

    return range_count;
}

static inline bool recovery_master_seed_from_hit(const thread ChecksumHitRecord& hit,
                                                 const device char* dict_words,
                                                 const device char* passphrase,
                                                 const constant SeedBatchParams& params,
                                                 thread MasterSeedRecord* out_record) {
    if (out_record == nullptr) {
        return false;
    }

    recovery_zero_thread_bytes((thread cmr_u8*)out_record, sizeof(MasterSeedRecord));
    recovery_copy_thread_bytes((thread cmr_u8*)&out_record->hit, (const thread cmr_u8*)&hit, sizeof(ChecksumHitRecord));

    const cmr_u32 words_count = cmr_u32(hit.word_count);
    if (dict_words == nullptr || words_count == 0u || words_count > RECOVERY_MAX_WORDS) {
        return false;
    }

    thread char phrase[RECOVERY_MAX_PHRASE_BYTES];
    const cmr_u32 phrase_len = recovery_build_phrase_from_hit_ids(
        hit.word_ids,
        words_count,
        dict_words,
        params.dict_stride != 0u ? params.dict_stride : RECOVERY_DICT_WORD_STRIDE,
        phrase,
        RECOVERY_MAX_PHRASE_BYTES);
    if (phrase_len == 0u) {
        return false;
    }

    const cmr_u32 pass_size =
        params.pass_size > RECOVERY_MAX_PASSPHRASE_BYTES ? RECOVERY_MAX_PASSPHRASE_BYTES : params.pass_size;
    if (!recovery_phrase_to_master_words(phrase, phrase_len, passphrase, pass_size, params.iterations, out_record->master_words)) {
        return false;
    }

    out_record->hit.flags |= RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS;
    return true;
}

static inline void recovery_derive_secp_master_from_master_words_precomp(
    const thread cmr_u32 master_words[RECOVERY_MASTER_WORDS],
    const thread RecoveryHmacSha512Precomp* secp_seed_ctx,
    thread cmr_u8 out_private_key[32],
    thread cmr_u8 out_chain_code[32]) {

    thread cmr_u8 seed[64];
    thread cmr_u8 digest[64];
    const thread cmr_u8* in_bytes = reinterpret_cast<const thread cmr_u8*>(master_words);
    for (cmr_u32 chunk = 0u; chunk < 8u; ++chunk) {
        const cmr_u32 base = chunk * 8u;
        for (cmr_u32 i = 0u; i < 8u; ++i) {
            seed[base + i] = in_bytes[base + (7u - i)];
        }
    }

    recovery_hmac_sha512_from_precomp(secp_seed_ctx, seed, 64u, digest);
    recovery_copy_thread_bytes(out_private_key, digest, 32u);
    recovery_copy_thread_bytes(out_chain_code, digest + 32u, 32u);
}

static inline bool recovery_secp_master_from_hit(const thread ChecksumHitRecord& hit,
                                                 const device char* dict_words,
                                                 const device char* passphrase,
                                                 const constant SeedBatchParams& params,
                                                 const thread RecoveryHmacSha512Precomp* secp_seed_ctx,
                                                 thread RecoverySecpMasterRecord* out_record) {
    if (out_record == nullptr) {
        return false;
    }

    recovery_zero_thread_bytes((thread cmr_u8*)out_record, sizeof(RecoverySecpMasterRecord));
    const cmr_u32 words_count = cmr_u32(hit.word_count);
    if (dict_words == nullptr || words_count == 0u || words_count > RECOVERY_MAX_WORDS) {
        return false;
    }

    thread char phrase[RECOVERY_MAX_PHRASE_BYTES];
    const cmr_u32 phrase_len = recovery_build_phrase_from_hit_ids(
        hit.word_ids,
        words_count,
        dict_words,
        params.dict_stride != 0u ? params.dict_stride : RECOVERY_DICT_WORD_STRIDE,
        phrase,
        RECOVERY_MAX_PHRASE_BYTES);
    if (phrase_len == 0u) {
        return false;
    }

    const cmr_u32 pass_size =
        params.pass_size > RECOVERY_MAX_PASSPHRASE_BYTES ? RECOVERY_MAX_PASSPHRASE_BYTES : params.pass_size;
    thread cmr_u32 master_words[RECOVERY_MASTER_WORDS];
    if (!recovery_phrase_to_master_words(phrase, phrase_len, passphrase, pass_size, params.iterations, master_words)) {
        recovery_zero_thread_bytes((thread cmr_u8*)out_record, sizeof(RecoverySecpMasterRecord));
        return false;
    }

    recovery_copy_thread_bytes((thread cmr_u8*)&out_record->hit, (const thread cmr_u8*)&hit, sizeof(ChecksumHitRecord));
    out_record->hit.flags |= RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS;
    recovery_derive_secp_master_from_master_words_precomp(master_words,
                                                          secp_seed_ctx,
                                                          out_record->master_private_key,
                                                          out_record->master_chain_code);
    return true;
}

kernel void workerRecoveryChecksumPrepareBatch(
    device ChecksumCursorState* cursor [[buffer(0)]],
    device ushort* start_digits [[buffer(1)]],
    device ChecksumStageParams* params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]) {

    if (gid != 0u || cursor == nullptr || start_digits == nullptr || params == nullptr) {
        return;
    }

    thread ChecksumCursorState local_cursor;
    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&local_cursor, (const device cmr_u8*)cursor, sizeof(ChecksumCursorState));
    for (cmr_u32 i = 0u; i < RECOVERY_MAX_WORDS; ++i) {
        start_digits[i] = local_cursor.digit_cursor[i];
    }

    params->range_start = 0ull;
    if (local_cursor.exhausted != 0u) {
        params->range_count = 0ull;
        return;
    }

    const cmr_u64 range_count = recovery_checksum_cursor_prepare_next_batch(local_cursor);
    params->range_count = range_count;
    recovery_copy_thread_to_device_bytes((device cmr_u8*)cursor, (const thread cmr_u8*)&local_cursor, sizeof(ChecksumCursorState));
}

static inline void recovery_checksum_hit_records_impl(
    const device ushort* base_ids,
    const device int* missing_positions,
    const device ushort* start_digits,
    device ChecksumHitRecord* out_records,
    device atomic_uint* out_count,
    constant ChecksumStageParams& params,
    const cmr_u32 words_count,
    const cmr_u32 missing_count,
    const uint gid,
    const uint threads_per_grid) {

    if (base_ids == nullptr || out_records == nullptr || out_count == nullptr ||
        params.out_capacity == 0u || words_count == 0u) {
        return;
    }

    if (missing_count != 0u && (missing_positions == nullptr || start_digits == nullptr)) {
        return;
    }

    for (cmr_u64 local = cmr_u64(gid); local < params.range_count; local += cmr_u64(threads_per_grid)) {
        const cmr_u64 candidate_index = params.range_start + local;
        thread ushort ids[RECOVERY_MAX_WORDS];
        if (!recovery_expand_checksum_tile_candidate(base_ids,
                                                     missing_positions,
                                                     start_digits,
                                                     words_count,
                                                     missing_count,
                                                     candidate_index,
                                                     ids)) {
            continue;
        }

        if (!checksum_valid(ids, words_count)) {
            continue;
        }

        const uint slot = atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed);
        if (slot >= params.out_capacity) {
            continue;
        }

        thread ChecksumHitRecord record;
        recovery_write_checksum_hit_record(ids, words_count, params, candidate_index, &record);
        recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[slot], (const thread cmr_u8*)&record, sizeof(ChecksumHitRecord));
    }
}

kernel void workerRecoveryChecksumHitRecords(
    const device ushort* base_ids [[buffer(0)]],
    const device int* missing_positions [[buffer(1)]],
    const device ushort* start_digits [[buffer(2)]],
    device ChecksumHitRecord* out_records [[buffer(3)]],
    device atomic_uint* out_count [[buffer(4)]],
    constant ChecksumStageParams& params [[buffer(5)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (params.words_count == 0u) {
        return;
    }
    const cmr_u32 words_count = params.words_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : params.words_count;
    const cmr_u32 missing_count = params.missing_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : params.missing_count;
    recovery_checksum_hit_records_impl(base_ids,
                                       missing_positions,
                                       start_digits,
                                       out_records,
                                       out_count,
                                       params,
                                       words_count,
                                       missing_count,
                                       gid,
                                       threads_per_grid);
}

#define RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL(NAME, WORDS) \
kernel void NAME( \
    const device ushort* base_ids [[buffer(0)]], \
    const device int* missing_positions [[buffer(1)]], \
    const device ushort* start_digits [[buffer(2)]], \
    device ChecksumHitRecord* out_records [[buffer(3)]], \
    device atomic_uint* out_count [[buffer(4)]], \
    constant ChecksumStageParams& params [[buffer(5)]], \
    uint gid [[thread_position_in_grid]], \
    uint threads_per_grid [[threads_per_grid]]) { \
    if (params.words_count != (WORDS)) { \
        return; \
    } \
    const cmr_u32 missing_count = params.missing_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : params.missing_count; \
    recovery_checksum_hit_records_impl(base_ids, \
                                       missing_positions, \
                                       start_digits, \
                                       out_records, \
                                       out_count, \
                                       params, \
                                       (WORDS), \
                                       missing_count, \
                                       gid, \
                                       threads_per_grid); \
}

RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL(workerRecoveryChecksumHitRecords12, 12u)
RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL(workerRecoveryChecksumHitRecords15, 15u)
RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL(workerRecoveryChecksumHitRecords18, 18u)
RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL(workerRecoveryChecksumHitRecords21, 21u)
RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL(workerRecoveryChecksumHitRecords24, 24u)

#undef RECOVERY_DEFINE_FIXED_CHECKSUM_KERNEL

kernel void workerRecoveryRuntimeScheduleChecksumBatches(
    device ChecksumCursorState* cursor [[buffer(0)]],
    device RecoveryRuntimeState* runtime_state [[buffer(1)]],
    device RecoveryRingHeader* batch_ring [[buffer(2)]],
    device RecoveryChecksumBatchRecord* batch_records [[buffer(3)]],
    uint lid [[thread_position_in_threadgroup]]) {

    if (lid != 0u || cursor == nullptr || runtime_state == nullptr ||
        batch_ring == nullptr || batch_records == nullptr) {
        return;
    }

    while (recovery_runtime_should_stop(runtime_state) == 0u) {
        thread ChecksumCursorState local_cursor;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&local_cursor,
                                             (const device cmr_u8*)cursor,
                                             sizeof(ChecksumCursorState));
        if (local_cursor.exhausted != 0u) {
            break;
        }

        thread RecoveryChecksumBatchRecord batch_record;
        recovery_zero_thread_bytes((thread cmr_u8*)&batch_record, sizeof(RecoveryChecksumBatchRecord));
        for (cmr_u32 i = 0u; i < RECOVERY_MAX_WORDS; ++i) {
            batch_record.start_digits[i] = local_cursor.digit_cursor[i];
        }
        batch_record.range_count = recovery_checksum_cursor_prepare_next_batch(local_cursor);
        batch_record.batch_index_lo = runtime_state->checksum_batch_next_lo;
        batch_record.batch_index_hi = runtime_state->checksum_batch_next_hi;

        if (batch_record.range_count == 0ull) {
            recovery_copy_thread_to_device_bytes((device cmr_u8*)cursor,
                                                 (const thread cmr_u8*)&local_cursor,
                                                 sizeof(ChecksumCursorState));
            break;
        }

        const cmr_u64 next_batch_index =
            recovery_checksum_runtime_u64(batch_record.batch_index_lo, batch_record.batch_index_hi) + 1ull;
        runtime_state->checksum_batch_next_lo = cmr_u32(next_batch_index & 0xFFFFFFFFull);
        runtime_state->checksum_batch_next_hi = cmr_u32(next_batch_index >> 32u);
        recovery_copy_thread_to_device_bytes((device cmr_u8*)cursor,
                                             (const thread cmr_u8*)&local_cursor,
                                             sizeof(ChecksumCursorState));

        while (recovery_runtime_should_stop(runtime_state) == 0u) {
            cmr_u32 reservation = 0u;
            if (!recovery_ring_try_reserve_write(batch_ring, &reservation)) {
                if (recovery_ring_is_closed(batch_ring) != 0u) {
                    recovery_runtime_request_stop(runtime_state);
                }
                continue;
            }
            const cmr_u32 slot = reservation % batch_ring->capacity;
            recovery_copy_thread_to_device_bytes((device cmr_u8*)&batch_records[slot],
                                                 (const thread cmr_u8*)&batch_record,
                                                 sizeof(RecoveryChecksumBatchRecord));
            recovery_ring_publish_write(batch_ring, reservation);
            break;
        }
    }

    recovery_ring_close(batch_ring);
}

kernel void workerRecoveryRuntimeConsumeChecksumBatches(
    const device ushort* base_ids [[buffer(0)]],
    const device int* missing_positions [[buffer(1)]],
    constant ChecksumStageParams& params [[buffer(2)]],
    device RecoveryRuntimeState* runtime_state [[buffer(3)]],
    device RecoveryRingHeader* batch_ring [[buffer(4)]],
    const device RecoveryChecksumBatchRecord* batch_records [[buffer(5)]],
    device RecoveryRingHeader* checksum_ring [[buffer(6)]],
    device ChecksumHitRecord* checksum_records [[buffer(7)]],
    uint3 lid3 [[thread_position_in_threadgroup]],
    uint3 threads_per_tg [[threads_per_threadgroup]]) {

    if (base_ids == nullptr || runtime_state == nullptr || batch_ring == nullptr ||
        batch_records == nullptr || checksum_ring == nullptr || checksum_records == nullptr ||
        params.words_count == 0u) {
        return;
    }

    const cmr_u32 words_count = params.words_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : params.words_count;
    const cmr_u32 missing_count = params.missing_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : params.missing_count;
    const uint lid = lid3.x;
    if (missing_count != 0u && missing_positions == nullptr) {
        return;
    }

    threadgroup ushort start_digits[RECOVERY_MAX_WORDS];
    threadgroup cmr_u64 range_count;
    threadgroup cmr_u32 batch_state;

    while (true) {
        if (lid == 0u) {
            batch_state = 0u;
            range_count = 0ull;

            if (recovery_runtime_should_stop(runtime_state) != 0u && recovery_ring_is_drained(batch_ring)) {
                batch_state = 0u;
            } else {
                cmr_u32 reservation = 0u;
                if (!recovery_ring_try_reserve_read(batch_ring, &reservation)) {
                    if (recovery_ring_is_closed(batch_ring) != 0u && recovery_ring_is_drained(batch_ring)) {
                        batch_state = 0u;
                    } else {
                        batch_state = 2u;
                    }
                } else {
                    const cmr_u32 slot = reservation % batch_ring->capacity;
                    thread RecoveryChecksumBatchRecord batch_record;
                    recovery_copy_device_to_thread_bytes((thread cmr_u8*)&batch_record,
                                                         (const device cmr_u8*)&batch_records[slot],
                                                         sizeof(RecoveryChecksumBatchRecord));
                    for (cmr_u32 i = 0u; i < RECOVERY_MAX_WORDS; ++i) {
                        start_digits[i] = batch_record.start_digits[i];
                    }
                    range_count = batch_record.range_count;
                    batch_state = 1u;
                }
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        if (batch_state == 0u) {
            break;
        }
        if (batch_state == 2u) {
            threadgroup_barrier(mem_flags::mem_threadgroup);
            continue;
        }

        for (cmr_u64 local = cmr_u64(lid); local < range_count; local += cmr_u64(threads_per_tg.x)) {
            if (recovery_runtime_should_stop(runtime_state) != 0u) {
                break;
            }
            thread ushort ids[RECOVERY_MAX_WORDS];
            if (!recovery_expand_checksum_tile_candidate(base_ids,
                                                         missing_positions,
                                                         start_digits,
                                                         words_count,
                                                         missing_count,
                                                         local,
                                                         ids)) {
                continue;
            }
            if (!checksum_valid(ids, words_count)) {
                continue;
            }

            thread ChecksumHitRecord record;
            recovery_write_checksum_hit_record(ids, words_count, params, local, &record);

            while (recovery_runtime_should_stop(runtime_state) == 0u) {
                cmr_u32 reservation = 0u;
                if (!recovery_ring_try_reserve_write(checksum_ring, &reservation)) {
                    continue;
                }
                const cmr_u32 slot = reservation % checksum_ring->capacity;
                recovery_copy_thread_to_device_bytes((device cmr_u8*)&checksum_records[slot],
                                                     (const thread cmr_u8*)&record,
                                                     sizeof(ChecksumHitRecord));
                recovery_ring_publish_write(checksum_ring, reservation);
                break;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (lid == 0u && recovery_runtime_group_done(&runtime_state->checksum_groups_live) != 0u) {
        recovery_ring_close(checksum_ring);
    }
}

kernel void workerRecoveryRuntimeProduceSeeds(
    const device ChecksumHitRecord* checksum_records [[buffer(0)]],
    device RecoveryRingHeader* checksum_ring [[buffer(1)]],
    const device char* dict_words [[buffer(2)]],
    const device char* passphrase [[buffer(3)]],
    constant SeedBatchParams& params [[buffer(4)]],
    device RecoveryRuntimeState* runtime_state [[buffer(5)]],
    device RecoveryRingHeader* secp_seed_ring [[buffer(6)]],
    device MasterSeedRecord* secp_seed_records [[buffer(7)]],
    device RecoveryRingHeader* ed_seed_ring [[buffer(8)]],
    device MasterSeedRecord* ed_seed_records [[buffer(9)]],
    uint lid [[thread_position_in_threadgroup]]) {

    if (checksum_records == nullptr || checksum_ring == nullptr || dict_words == nullptr ||
        runtime_state == nullptr) {
        return;
    }

    const bool want_secp = secp_seed_ring != nullptr && secp_seed_records != nullptr && secp_seed_ring->capacity != 0ull;
    const bool want_ed = ed_seed_ring != nullptr && ed_seed_records != nullptr && ed_seed_ring->capacity != 0ull;

    while (true) {
        if (recovery_runtime_should_stop(runtime_state) != 0u && recovery_ring_is_drained(checksum_ring)) {
            break;
        }

        cmr_u32 reservation = 0u;
        if (!recovery_ring_try_reserve_read(checksum_ring, &reservation)) {
            if (recovery_ring_is_closed(checksum_ring) != 0u && recovery_ring_is_drained(checksum_ring)) {
                break;
            }
            continue;
        }

        const cmr_u32 slot = reservation % checksum_ring->capacity;
        thread ChecksumHitRecord hit;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&hit,
                                             (const device cmr_u8*)&checksum_records[slot],
                                             sizeof(ChecksumHitRecord));

        thread MasterSeedRecord seed_record;
        if (!recovery_master_seed_from_hit(hit, dict_words, passphrase, params, &seed_record)) {
            continue;
        }

        if (want_secp) {
            while (recovery_runtime_should_stop(runtime_state) == 0u) {
                cmr_u32 out_reservation = 0u;
                if (!recovery_ring_try_reserve_write(secp_seed_ring, &out_reservation)) {
                    continue;
                }
                const cmr_u32 out_slot = out_reservation % secp_seed_ring->capacity;
                recovery_copy_thread_to_device_bytes((device cmr_u8*)&secp_seed_records[out_slot],
                                                     (const thread cmr_u8*)&seed_record,
                                                     sizeof(MasterSeedRecord));
                recovery_ring_publish_write(secp_seed_ring, out_reservation);
                break;
            }
        }

        if (want_ed) {
            while (recovery_runtime_should_stop(runtime_state) == 0u) {
                cmr_u32 out_reservation = 0u;
                if (!recovery_ring_try_reserve_write(ed_seed_ring, &out_reservation)) {
                    continue;
                }
                const cmr_u32 out_slot = out_reservation % ed_seed_ring->capacity;
                recovery_copy_thread_to_device_bytes((device cmr_u8*)&ed_seed_records[out_slot],
                                                     (const thread cmr_u8*)&seed_record,
                                                     sizeof(MasterSeedRecord));
                recovery_ring_publish_write(ed_seed_ring, out_reservation);
                break;
            }
        }
    }

    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (lid == 0u && recovery_runtime_group_done(&runtime_state->seed_groups_live) != 0u) {
        if (want_secp) {
            recovery_ring_close(secp_seed_ring);
        }
        if (want_ed) {
            recovery_ring_close(ed_seed_ring);
        }
    }
}

kernel void workerRecoveryMasterSeedBatch(
    const device ChecksumHitRecord* hits [[buffer(0)]],
    const device char* dict_words [[buffer(1)]],
    const device char* passphrase [[buffer(2)]],
    constant SeedBatchParams& params [[buffer(3)]],
    device MasterSeedRecord* out_records [[buffer(4)]],
    const device atomic_uint* input_count [[buffer(5)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (hits == nullptr || dict_words == nullptr || out_records == nullptr || input_count == nullptr ||
        params.record_count == 0u || params.out_capacity == 0u) {
        return;
    }

    const cmr_u32 input_total = atomic_load_explicit(input_count, memory_order_relaxed);
    const cmr_u32 limit = min(min(params.record_count, params.out_capacity), input_total);
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        thread ChecksumHitRecord hit;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&hit, (const device cmr_u8*)&hits[idx], sizeof(ChecksumHitRecord));

        thread MasterSeedRecord out_record;
        (void)recovery_master_seed_from_hit(hit, dict_words, passphrase, params, &out_record);
        recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx], (const thread cmr_u8*)&out_record, sizeof(MasterSeedRecord));
    }
}

kernel void workerRecoverySecpMasterBatch(
    const device ChecksumHitRecord* hits [[buffer(0)]],
    const device char* dict_words [[buffer(1)]],
    const device char* passphrase [[buffer(2)]],
    constant SeedBatchParams& params [[buffer(3)]],
    device RecoverySecpMasterRecord* out_records [[buffer(4)]],
    const device atomic_uint* input_count [[buffer(5)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (hits == nullptr || dict_words == nullptr || out_records == nullptr || input_count == nullptr ||
        params.record_count == 0u || params.out_capacity == 0u) {
        return;
    }

    const cmr_u32 input_total = atomic_load_explicit(input_count, memory_order_relaxed);
    const cmr_u32 limit = min(min(params.record_count, params.out_capacity), input_total);
    thread cmr_u8 key_label[12];
    thread RecoveryHmacSha512Precomp secp_seed_ctx;
    recovery_copy_constant_to_thread_bytes(key_label,
                                           reinterpret_cast<const constant cmr_u8*>(kRecoverySecpSeedLabel),
                                           12u);
    recovery_hmac_sha512_precompute(key_label, 12u, &secp_seed_ctx);
    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        thread ChecksumHitRecord hit;
        recovery_copy_device_to_thread_bytes((thread cmr_u8*)&hit,
                                             (const device cmr_u8*)&hits[idx],
                                             sizeof(ChecksumHitRecord));

        thread RecoverySecpMasterRecord out_record;
        (void)recovery_secp_master_from_hit(hit, dict_words, passphrase, params, &secp_seed_ctx, &out_record);
        recovery_copy_thread_to_device_bytes((device cmr_u8*)&out_records[idx],
                                             (const thread cmr_u8*)&out_record,
                                             sizeof(RecoverySecpMasterRecord));
    }
}

kernel void workerRecoveryPrepareIndirectDispatch(
    const device atomic_uint* input_count [[buffer(0)]],
    constant RecoveryIndirectDispatchParams& params [[buffer(1)]],
    device uint* indirect_threadgroups [[buffer(2)]],
    uint gid [[thread_position_in_grid]]) {

    if (gid != 0u || input_count == nullptr || indirect_threadgroups == nullptr) {
        return;
    }

    const cmr_u32 threads_per_group = params.threads_per_group == 0u ? 1u : params.threads_per_group;
    const cmr_u32 clamped_count =
        min(params.record_capacity, atomic_load_explicit(input_count, memory_order_relaxed));
    const cmr_u32 groups =
        max(1u, (clamped_count + threads_per_group - 1u) / threads_per_group);

    indirect_threadgroups[0] = groups;
    indirect_threadgroups[1] = 1u;
    indirect_threadgroups[2] = 1u;
}

kernel void workerRecoverySeedBatch(
    const device ushort* batch_ids [[buffer(0)]],
    const device char* dict_words [[buffer(1)]],
    const device char* passphrase [[buffer(2)]],
    constant SeedBatchParams& params [[buffer(3)]],
    device uint* batch_master_words [[buffer(4)]],
    uint gid [[thread_position_in_grid]],
    uint threads_per_grid [[threads_per_grid]]) {

    if (batch_ids == nullptr || dict_words == nullptr || batch_master_words == nullptr || params.record_count == 0u || params.words_count == 0u || params.out_capacity == 0u) {
        return;
    }

    const cmr_u32 words_count = params.words_count > RECOVERY_MAX_WORDS ? RECOVERY_MAX_WORDS : params.words_count;
    const cmr_u32 limit = params.record_count < params.out_capacity ? params.record_count : params.out_capacity;
    thread cmr_u32 ids[RECOVERY_MAX_WORDS];
    thread char phrase[RECOVERY_MAX_PHRASE_BYTES];
    thread cmr_u32 master_words[RECOVERY_MASTER_WORDS];

    for (cmr_u64 idx = cmr_u64(gid); idx < cmr_u64(limit); idx += cmr_u64(threads_per_grid)) {
        const device ushort* candidate = batch_ids + (idx * cmr_u64(words_count));
        for (cmr_u32 i = 0u; i < words_count; ++i) {
            ids[i] = cmr_u32(candidate[i] & 0x7FFu);
        }

        const cmr_u32 phrase_len = recovery_build_phrase_from_ids(
            ids,
            words_count,
            dict_words,
            params.dict_stride != 0u ? params.dict_stride : RECOVERY_DICT_WORD_STRIDE,
            phrase,
            RECOVERY_MAX_PHRASE_BYTES);

        if (phrase_len == 0u || !recovery_phrase_to_master_words(
                phrase,
                phrase_len,
                passphrase,
                params.pass_size > RECOVERY_MAX_PASSPHRASE_BYTES ? RECOVERY_MAX_PASSPHRASE_BYTES : params.pass_size,
                params.iterations,
                master_words)) {
            for (cmr_u32 i = 0u; i < RECOVERY_MASTER_WORDS; ++i) {
                batch_master_words[(idx * RECOVERY_MASTER_WORDS) + i] = 0u;
            }
            continue;
        }

        for (cmr_u32 i = 0u; i < RECOVERY_MASTER_WORDS; ++i) {
            batch_master_words[(idx * RECOVERY_MASTER_WORDS) + i] = master_words[i];
        }
    }
}
