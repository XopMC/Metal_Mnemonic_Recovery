#pragma once

#if defined(__METAL_VERSION__)
typedef uchar cmr_u8;
typedef ushort cmr_u16;
typedef uint cmr_u32;
typedef ulong cmr_u64;
typedef long cmr_i64;
#else
#include <cstddef>
#include <cstdint>
typedef std::uint8_t cmr_u8;
typedef std::uint16_t cmr_u16;
typedef std::uint32_t cmr_u32;
typedef std::uint64_t cmr_u64;
typedef std::int64_t cmr_i64;
#endif

#define RECOVERY_MAX_WORDS 48u
#define RECOVERY_MAX_PHRASE_BYTES 512u
#define RECOVERY_MASTER_WORDS 16u
#define RECOVERY_DICT_WORD_STRIDE 34u
#define RECOVERY_MAX_PASSPHRASE_BYTES 128u

#define ENDO_TAG_BASE 0xA0u
#define ENDO_GROUP_STRIDE 8u
#define ENDO_GROUP_COMPRESSED 0u
#define ENDO_GROUP_SEGWIT 1u
#define ENDO_GROUP_UNCOMPRESSED 2u
#define ENDO_GROUP_ETH 3u
#define ENDO_GROUP_TAPROOT 4u
#define ENDO_GROUP_XPOINT 5u

#define RESULT_DERIVATION_BIP32_SECP256K1 1u
#define RESULT_DERIVATION_SLIP0010_ED25519 2u
#define RESULT_DERIVATION_ED25519_BIP32_TEST 3u

#define RECOVERY_RECORD_FLAG_CHECKSUM_VALID (1u << 0)
#define RECOVERY_RECORD_FLAG_STAGE_READY (1u << 1)
#define RECOVERY_RECORD_FLAG_HAS_PASSPHRASE (1u << 2)
#define RECOVERY_RECORD_FLAG_HAS_MASTER_WORDS (1u << 3)

struct ChecksumParams {
    cmr_u32 words_count = 0u;
    cmr_u32 missing_count = 0u;
    cmr_u64 range_start = 0ull;
    cmr_u64 range_count = 0ull;
    cmr_u32 out_capacity = 0u;
    cmr_u32 reserved = 0u;
};

struct ChecksumStageParams {
    cmr_u32 words_count = 0u;
    cmr_u32 missing_count = 0u;
    cmr_u64 range_start = 0ull;
    cmr_u64 range_count = 0ull;
    cmr_u32 out_capacity = 0u;
    cmr_u32 derivation_index = 0u;
    cmr_u32 derivation_type = RESULT_DERIVATION_BIP32_SECP256K1;
    cmr_u32 coin_type = 0u;
    cmr_u32 flags = RECOVERY_RECORD_FLAG_CHECKSUM_VALID | RECOVERY_RECORD_FLAG_STAGE_READY;
    cmr_u32 passphrase_index = 0u;
    cmr_u32 match_len = 0u;
    cmr_u32 reserved = 0u;
    cmr_i64 round_delta = 0;
};

struct SeedBatchParams {
    cmr_u32 words_count = 0u;
    cmr_u32 record_count = 0u;
    cmr_u32 dict_stride = RECOVERY_DICT_WORD_STRIDE;
    cmr_u32 pass_size = 0u;
    cmr_u32 out_capacity = 0u;
    cmr_u32 flags = 0u;
    cmr_u32 reserved = 0u;
    cmr_u64 iterations = 0ull;
};

struct ChecksumCursorState {
    cmr_u16 digit_cursor[RECOVERY_MAX_WORDS];
    cmr_u32 missing_count = 0u;
    cmr_u32 exhausted = 0u;
    cmr_u64 batch_candidate_capacity = 1ull;
    cmr_u64 remaining_batches = 0ull;
};

struct RecoveryRingHeader {
    cmr_u32 read_index = 0u;
    cmr_u32 reserve_index = 0u;
    cmr_u32 publish_index = 0u;
    cmr_u32 capacity = 0u;
    cmr_u32 closed = 0u;
    cmr_u32 overflow = 0u;
    cmr_u32 reserved0 = 0u;
    cmr_u32 reserved1 = 0u;
};

struct RecoveryWorkItemHeader {
    cmr_u32 engine_kind = 0u;
    cmr_u32 derivation_index = 0u;
    cmr_u32 derivation_type = 0u;
    cmr_u32 passphrase_index = 0u;
    cmr_u32 program_slot = 0u;
    cmr_u32 payload_selector = 0u;
};

struct RecoveryRuntimeErrorState {
    cmr_u32 code = 0u;
    cmr_u32 stage = 0u;
    cmr_u64 detail0 = 0ull;
    cmr_u64 detail1 = 0ull;
};

struct RecoveryRuntimeState {
    cmr_u32 stop = 0u;
    cmr_u32 found_limit = 0u;
    cmr_u32 checksum_batch_next_lo = 0u;
    cmr_u32 checksum_batch_next_hi = 0u;
    cmr_u32 checksum_total_batches_lo = 0u;
    cmr_u32 checksum_total_batches_hi = 0u;
    cmr_u32 checksum_batch_lock = 0u;
    cmr_u32 checksum_groups_live = 0u;
    cmr_u32 seed_groups_live = 0u;
    cmr_u32 secp_groups_live = 0u;
    cmr_u32 ed_groups_live = 0u;
    cmr_u32 secp_promote_groups_live = 0u;
    cmr_u32 ed_promote_groups_live = 0u;
    cmr_u32 reserved0 = 0u;
    RecoveryRuntimeErrorState error = {};
};

struct RecoveryChecksumBatchRecord {
    cmr_u16 start_digits[RECOVERY_MAX_WORDS];
    cmr_u64 range_count = 0ull;
    cmr_u32 batch_index_lo = 0u;
    cmr_u32 batch_index_hi = 0u;
};

struct FoundRecord {
    cmr_u32 word_ids[RECOVERY_MAX_WORDS];
    cmr_u32 word_count;
    cmr_u32 derivation_index;
    cmr_u32 derivation_type;
    cmr_u32 coin_type;
    cmr_u32 match_len;
    cmr_u32 flags;
    cmr_u8 private_key[32];
    cmr_u8 match_bytes[32];
    cmr_i64 round_delta;
    cmr_u32 passphrase_index;
    cmr_u32 reserved;
};

struct ChecksumHitRecord {
    cmr_u16 word_ids[RECOVERY_MAX_WORDS];
    cmr_u16 word_count;
    cmr_u16 reserved16;
    cmr_u32 derivation_index;
    cmr_u32 derivation_type;
    cmr_u32 coin_type;
    cmr_u32 flags;
    cmr_u32 passphrase_index;
    cmr_u32 match_len;
    cmr_i64 round_delta;
    cmr_u64 candidate_index;
};

struct MasterSeedRecord {
    ChecksumHitRecord hit;
    cmr_u32 master_words[RECOVERY_MASTER_WORDS];
};

struct RecoverySecpMasterRecord {
    ChecksumHitRecord hit;
    cmr_u8 master_private_key[32];
    cmr_u8 master_chain_code[32];
};

struct RecoveryIndirectDispatchParams {
    cmr_u32 record_capacity;
    cmr_u32 threads_per_group;
    cmr_u32 reserved0;
    cmr_u32 reserved1;
};

static inline cmr_u32 recovery_decode_base_type(const cmr_u32 type) {
    const cmr_u32 base_type = type & 0xFFu;
    if (base_type < ENDO_TAG_BASE) {
        return base_type;
    }

    const cmr_u32 group = (base_type - ENDO_TAG_BASE) / ENDO_GROUP_STRIDE;
    switch (group) {
    case ENDO_GROUP_COMPRESSED:   return 0x02u;
    case ENDO_GROUP_SEGWIT:       return 0x03u;
    case ENDO_GROUP_UNCOMPRESSED: return 0x01u;
    case ENDO_GROUP_ETH:          return 0x06u;
    case ENDO_GROUP_TAPROOT:      return 0x04u;
    case ENDO_GROUP_XPOINT:       return 0x05u;
    default:                      return base_type;
    }
}

static inline cmr_u32 recovery_match_size_for_type(const cmr_u32 type) {
    switch (recovery_decode_base_type(type)) {
    case 0x01u:
    case 0x02u:
    case 0x03u:
    case 0x06u:
        return 20u;
    case 0x04u:
    case 0x05u:
    case 0x60u:
    case 0x80u:
    case 0x81u:
    case 0x82u:
    case 0x83u:
    case 0x84u:
    case 0x85u:
    case 0x86u:
    case 0x87u:
    case 0x88u:
    case 0x89u:
    case 0x8Au:
    case 0x8Bu:
    case 0x8Cu:
        return 32u;
    default:
        return 32u;
    }
}

static inline cmr_u32 recovery_default_derivation_type_for_type(const cmr_u32 type) {
    switch (recovery_decode_base_type(type)) {
    case 0x60u:
    case 0x80u:
    case 0x81u:
    case 0x82u:
    case 0x83u:
    case 0x84u:
    case 0x85u:
    case 0x86u:
    case 0x87u:
    case 0x88u:
    case 0x89u:
        return RESULT_DERIVATION_SLIP0010_ED25519;
    default:
        return RESULT_DERIVATION_BIP32_SECP256K1;
    }
}

#if defined(__METAL_VERSION__)
static inline device atomic_uint* recovery_atomic_u32_ptr(device cmr_u32* value) {
    return reinterpret_cast<device atomic_uint*>(value);
}

static inline cmr_u32 recovery_runtime_should_stop(device RecoveryRuntimeState* state) {
    return (state == nullptr)
        ? 0u
        : atomic_load_explicit(recovery_atomic_u32_ptr(&state->stop), memory_order_relaxed);
}

static inline void recovery_runtime_request_stop(device RecoveryRuntimeState* state) {
    if (state == nullptr) {
        return;
    }
    atomic_store_explicit(recovery_atomic_u32_ptr(&state->stop), 1u, memory_order_relaxed);
}

static inline cmr_u32 recovery_runtime_group_done(device cmr_u32* counter) {
    if (counter == nullptr) {
        return 1u;
    }
    return atomic_fetch_sub_explicit(recovery_atomic_u32_ptr(counter), 1u, memory_order_relaxed) == 1u ? 1u : 0u;
}

static inline cmr_u32 recovery_ring_is_closed(device RecoveryRingHeader* header) {
    return (header == nullptr)
        ? 1u
        : atomic_load_explicit(recovery_atomic_u32_ptr(&header->closed), memory_order_relaxed);
}

static inline void recovery_ring_close(device RecoveryRingHeader* header) {
    if (header == nullptr) {
        return;
    }
    atomic_store_explicit(recovery_atomic_u32_ptr(&header->closed), 1u, memory_order_relaxed);
}

static inline void recovery_ring_mark_overflow(device RecoveryRingHeader* header) {
    if (header == nullptr) {
        return;
    }
    atomic_store_explicit(recovery_atomic_u32_ptr(&header->overflow), 1u, memory_order_relaxed);
}

static inline bool recovery_ring_try_reserve_write(device RecoveryRingHeader* header, thread cmr_u32* reservation) {
    if (header == nullptr || reservation == nullptr || header->capacity == 0ull) {
        return false;
    }

    while (true) {
        const cmr_u32 read_index =
            atomic_load_explicit(recovery_atomic_u32_ptr(&header->read_index), memory_order_relaxed);
        cmr_u32 reserve_index =
            atomic_load_explicit(recovery_atomic_u32_ptr(&header->reserve_index), memory_order_relaxed);
        if ((reserve_index - read_index) >= header->capacity) {
            return false;
        }
        const cmr_u32 desired = reserve_index + 1u;
        if (atomic_compare_exchange_weak_explicit(recovery_atomic_u32_ptr(&header->reserve_index),
                                                  &reserve_index,
                                                  desired,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
            *reservation = reserve_index;
            return true;
        }
    }
}

static inline void recovery_ring_publish_write(device RecoveryRingHeader* header, const cmr_u32 reservation) {
    if (header == nullptr) {
        return;
    }
    while (true) {
        cmr_u32 publish_index =
            atomic_load_explicit(recovery_atomic_u32_ptr(&header->publish_index), memory_order_relaxed);
        if (publish_index != reservation) {
            continue;
        }
        const cmr_u32 desired = reservation + 1u;
        if (atomic_compare_exchange_weak_explicit(recovery_atomic_u32_ptr(&header->publish_index),
                                                  &publish_index,
                                                  desired,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
            return;
        }
    }
}

static inline bool recovery_ring_try_reserve_read(device RecoveryRingHeader* header, thread cmr_u32* reservation) {
    if (header == nullptr || reservation == nullptr || header->capacity == 0ull) {
        return false;
    }

    while (true) {
        cmr_u32 read_index =
            atomic_load_explicit(recovery_atomic_u32_ptr(&header->read_index), memory_order_relaxed);
        const cmr_u32 publish_index =
            atomic_load_explicit(recovery_atomic_u32_ptr(&header->publish_index), memory_order_relaxed);
        if (read_index == publish_index) {
            return false;
        }
        const cmr_u32 desired = read_index + 1u;
        if (atomic_compare_exchange_weak_explicit(recovery_atomic_u32_ptr(&header->read_index),
                                                  &read_index,
                                                  desired,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
            *reservation = read_index;
            return true;
        }
    }
}

static inline bool recovery_ring_is_drained(device RecoveryRingHeader* header) {
    if (header == nullptr) {
        return true;
    }
    const cmr_u32 read_index =
        atomic_load_explicit(recovery_atomic_u32_ptr(&header->read_index), memory_order_relaxed);
    const cmr_u32 publish_index =
        atomic_load_explicit(recovery_atomic_u32_ptr(&header->publish_index), memory_order_relaxed);
    return read_index == publish_index;
}
#endif

#if !defined(__METAL_VERSION__)
static_assert(sizeof(ChecksumParams) == 32u, "ChecksumParams layout mismatch");
static_assert(sizeof(ChecksumStageParams) == 64u, "ChecksumStageParams layout mismatch");
static_assert(sizeof(SeedBatchParams) == 40u, "SeedBatchParams layout mismatch");
static_assert(sizeof(ChecksumCursorState) == 120u, "ChecksumCursorState layout mismatch");
static_assert(sizeof(RecoveryRingHeader) == 32u, "RecoveryRingHeader layout mismatch");
static_assert(sizeof(RecoveryWorkItemHeader) == 24u, "RecoveryWorkItemHeader layout mismatch");
static_assert(sizeof(RecoveryRuntimeErrorState) == 24u, "RecoveryRuntimeErrorState layout mismatch");
static_assert(sizeof(RecoveryRuntimeState) == 80u, "RecoveryRuntimeState layout mismatch");
static_assert(sizeof(RecoveryChecksumBatchRecord) == 112u, "RecoveryChecksumBatchRecord layout mismatch");
static_assert(sizeof(FoundRecord) == 296u, "FoundRecord layout mismatch");
static_assert(sizeof(ChecksumHitRecord) == 144u, "ChecksumHitRecord layout mismatch");
static_assert(sizeof(MasterSeedRecord) == 208u, "MasterSeedRecord layout mismatch");
static_assert(alignof(ChecksumCursorState) == 8u, "ChecksumCursorState alignment mismatch");
static_assert(alignof(RecoveryRingHeader) == 4u, "RecoveryRingHeader alignment mismatch");
static_assert(alignof(RecoveryRuntimeErrorState) == 8u, "RecoveryRuntimeErrorState alignment mismatch");
static_assert(alignof(RecoveryRuntimeState) == 8u, "RecoveryRuntimeState alignment mismatch");
static_assert(alignof(RecoveryChecksumBatchRecord) == 8u, "RecoveryChecksumBatchRecord alignment mismatch");
static_assert(alignof(FoundRecord) == 8u, "FoundRecord alignment mismatch");
static_assert(alignof(ChecksumHitRecord) == 8u, "ChecksumHitRecord alignment mismatch");
static_assert(alignof(MasterSeedRecord) == 8u, "MasterSeedRecord alignment mismatch");
static_assert(offsetof(ChecksumCursorState, digit_cursor) == 0u, "ChecksumCursorState.digit_cursor offset mismatch");
static_assert(offsetof(ChecksumCursorState, missing_count) == 96u, "ChecksumCursorState.missing_count offset mismatch");
static_assert(offsetof(ChecksumCursorState, exhausted) == 100u, "ChecksumCursorState.exhausted offset mismatch");
static_assert(offsetof(ChecksumCursorState, batch_candidate_capacity) == 104u, "ChecksumCursorState.batch_candidate_capacity offset mismatch");
static_assert(offsetof(ChecksumCursorState, remaining_batches) == 112u, "ChecksumCursorState.remaining_batches offset mismatch");
static_assert(offsetof(RecoveryRingHeader, read_index) == 0u, "RecoveryRingHeader.read_index offset mismatch");
static_assert(offsetof(RecoveryRingHeader, reserve_index) == 4u, "RecoveryRingHeader.reserve_index offset mismatch");
static_assert(offsetof(RecoveryRingHeader, publish_index) == 8u, "RecoveryRingHeader.publish_index offset mismatch");
static_assert(offsetof(RecoveryRingHeader, capacity) == 12u, "RecoveryRingHeader.capacity offset mismatch");
static_assert(offsetof(RecoveryRingHeader, closed) == 16u, "RecoveryRingHeader.closed offset mismatch");
static_assert(offsetof(RecoveryRingHeader, overflow) == 20u, "RecoveryRingHeader.overflow offset mismatch");
static_assert(offsetof(RecoveryRuntimeErrorState, detail0) == 8u, "RecoveryRuntimeErrorState.detail0 offset mismatch");
static_assert(offsetof(RecoveryRuntimeState, checksum_batch_next_lo) == 8u, "RecoveryRuntimeState.checksum_batch_next_lo offset mismatch");
static_assert(offsetof(RecoveryRuntimeState, checksum_total_batches_lo) == 16u, "RecoveryRuntimeState.checksum_total_batches_lo offset mismatch");
static_assert(offsetof(RecoveryRuntimeState, checksum_batch_lock) == 24u, "RecoveryRuntimeState.checksum_batch_lock offset mismatch");
static_assert(offsetof(RecoveryRuntimeState, checksum_groups_live) == 28u, "RecoveryRuntimeState.checksum_groups_live offset mismatch");
static_assert(offsetof(RecoveryRuntimeState, error) == 56u, "RecoveryRuntimeState.error offset mismatch");
static_assert(offsetof(RecoveryChecksumBatchRecord, start_digits) == 0u, "RecoveryChecksumBatchRecord.start_digits offset mismatch");
static_assert(offsetof(RecoveryChecksumBatchRecord, range_count) == 96u, "RecoveryChecksumBatchRecord.range_count offset mismatch");
static_assert(offsetof(RecoveryChecksumBatchRecord, batch_index_lo) == 104u, "RecoveryChecksumBatchRecord.batch_index_lo offset mismatch");
static_assert(offsetof(RecoveryChecksumBatchRecord, batch_index_hi) == 108u, "RecoveryChecksumBatchRecord.batch_index_hi offset mismatch");
static_assert(offsetof(FoundRecord, word_ids) == 0u, "FoundRecord.word_ids offset mismatch");
static_assert(offsetof(FoundRecord, word_count) == 192u, "FoundRecord.word_count offset mismatch");
static_assert(offsetof(FoundRecord, derivation_index) == 196u, "FoundRecord.derivation_index offset mismatch");
static_assert(offsetof(FoundRecord, derivation_type) == 200u, "FoundRecord.derivation_type offset mismatch");
static_assert(offsetof(FoundRecord, coin_type) == 204u, "FoundRecord.coin_type offset mismatch");
static_assert(offsetof(FoundRecord, match_len) == 208u, "FoundRecord.match_len offset mismatch");
static_assert(offsetof(FoundRecord, flags) == 212u, "FoundRecord.flags offset mismatch");
static_assert(offsetof(FoundRecord, private_key) == 216u, "FoundRecord.private_key offset mismatch");
static_assert(offsetof(FoundRecord, match_bytes) == 248u, "FoundRecord.match_bytes offset mismatch");
static_assert(offsetof(FoundRecord, round_delta) == 280u, "FoundRecord.round_delta offset mismatch");
static_assert(offsetof(FoundRecord, passphrase_index) == 288u, "FoundRecord.passphrase_index offset mismatch");
static_assert(offsetof(FoundRecord, reserved) == 292u, "FoundRecord.reserved offset mismatch");
static_assert(offsetof(ChecksumHitRecord, word_ids) == 0u, "ChecksumHitRecord.word_ids offset mismatch");
static_assert(offsetof(ChecksumHitRecord, word_count) == 96u, "ChecksumHitRecord.word_count offset mismatch");
static_assert(offsetof(ChecksumHitRecord, derivation_index) == 100u, "ChecksumHitRecord.derivation_index offset mismatch");
static_assert(offsetof(ChecksumHitRecord, derivation_type) == 104u, "ChecksumHitRecord.derivation_type offset mismatch");
static_assert(offsetof(ChecksumHitRecord, coin_type) == 108u, "ChecksumHitRecord.coin_type offset mismatch");
static_assert(offsetof(ChecksumHitRecord, flags) == 112u, "ChecksumHitRecord.flags offset mismatch");
static_assert(offsetof(ChecksumHitRecord, passphrase_index) == 116u, "ChecksumHitRecord.passphrase_index offset mismatch");
static_assert(offsetof(ChecksumHitRecord, match_len) == 120u, "ChecksumHitRecord.match_len offset mismatch");
static_assert(offsetof(ChecksumHitRecord, round_delta) == 128u, "ChecksumHitRecord.round_delta offset mismatch");
static_assert(offsetof(ChecksumHitRecord, candidate_index) == 136u, "ChecksumHitRecord.candidate_index offset mismatch");
static_assert(offsetof(MasterSeedRecord, hit) == 0u, "MasterSeedRecord.hit offset mismatch");
static_assert(offsetof(MasterSeedRecord, master_words) == 144u, "MasterSeedRecord.master_words offset mismatch");
#endif
