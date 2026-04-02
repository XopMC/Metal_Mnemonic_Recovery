#pragma once

#include "metal/RecoveryDerivationTypes.h"

#if !defined(__METAL_VERSION__)
#include <cstring>
#endif

#if defined(__METAL_VERSION__)
#define DERIV_THREAD_PTR(T) thread T*
#define DERIV_THREAD_CONST_PTR(T) thread const T*
#define DERIV_THREAD_REF(T) thread T&
#else
#define DERIV_THREAD_PTR(T) T*
#define DERIV_THREAD_CONST_PTR(T) const T*
#define DERIV_THREAD_REF(T) T&
#endif

#define DERIV_CACHE_SLOTS 4

#if defined(__METAL_VERSION__)
static inline void recovery_deriv_copy_bytes(thread cmr_u8* dst, const thread cmr_u8* src, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}
#else
static inline void recovery_deriv_copy_bytes(cmr_u8* dst, const cmr_u8* src, const cmr_u32 len) {
    std::memcpy(dst, src, static_cast<std::size_t>(len));
}
#endif

typedef struct REC_ALIGN(16) {
    cmr_u32 prev_offset[DERIV_CACHE_SLOTS];
    cmr_u32 prev_len[DERIV_CACHE_SLOTS];
    cmr_u32 valid[DERIV_CACHE_SLOTS];
    cmr_u32 last_was_normal[DERIV_CACHE_SLOTS];
    cmr_u32 hmac_precomp_valid[DERIV_CACHE_SLOTS];
    extended_private_key_t parent_key[DERIV_CACHE_SLOTS];
    extended_private_key_t path_end_key[DERIV_CACHE_SLOTS];
    cmr_u8 cached_pubkey[DERIV_CACHE_SLOTS][33];
    hmac_sha512_precomp_t hmac_precomp[DERIV_CACHE_SLOTS];
} deriv_cache_secp256k1_t;

typedef struct REC_ALIGN(16) {
    cmr_u32 prev_offset;
    cmr_u32 prev_len;
    cmr_u32 valid;
    cmr_u32 hmac_precomp_valid;
    extended_private_key_t parent_key;
    hmac_sha512_precomp_t hmac_precomp;
} deriv_cache_ed25519_t;

REC_DEVICE REC_FORCEINLINE bool deriv_prefix_equal(DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ lhs,
                                                   DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ rhs,
                                                   const cmr_u32 n) {
    switch (n) {
    case 0: return true;
    case 1: return lhs[0] == rhs[0];
    case 2: return lhs[0] == rhs[0] && lhs[1] == rhs[1];
    case 3: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2];
    case 4: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3];
    case 5: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4];
    case 6: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4] && lhs[5] == rhs[5];
    case 7: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4] && lhs[5] == rhs[5] && lhs[6] == rhs[6];
    case 8: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4] && lhs[5] == rhs[5] && lhs[6] == rhs[6] && lhs[7] == rhs[7];
    default:
        for (cmr_u32 i = 0u; i < n; ++i) {
            if (lhs[i] != rhs[i]) return false;
        }
        return true;
    }
}

#if defined(__METAL_VERSION__)
REC_DEVICE REC_FORCEINLINE bool deriv_prefix_equal(const device cmr_u32* __restrict__ lhs,
                                                   const device cmr_u32* __restrict__ rhs,
                                                   const cmr_u32 n) {
    switch (n) {
    case 0: return true;
    case 1: return lhs[0] == rhs[0];
    case 2: return lhs[0] == rhs[0] && lhs[1] == rhs[1];
    case 3: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2];
    case 4: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3];
    case 5: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4];
    case 6: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4] && lhs[5] == rhs[5];
    case 7: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4] && lhs[5] == rhs[5] && lhs[6] == rhs[6];
    case 8: return lhs[0] == rhs[0] && lhs[1] == rhs[1] && lhs[2] == rhs[2] && lhs[3] == rhs[3] && lhs[4] == rhs[4] && lhs[5] == rhs[5] && lhs[6] == rhs[6] && lhs[7] == rhs[7];
    default:
        for (cmr_u32 i = 0u; i < n; ++i) {
            if (lhs[i] != rhs[i]) return false;
        }
        return true;
    }
}

#endif

REC_DEVICE REC_FORCEINLINE void deriv_cache_reset(DERIV_THREAD_PTR(deriv_cache_secp256k1_t) cache) {
    if (cache) {
        for (int s = 0; s < DERIV_CACHE_SLOTS; ++s) {
            cache->valid[s] = 0u;
        }
    }
}

REC_DEVICE REC_FORCEINLINE void deriv_cache_reset(DERIV_THREAD_PTR(deriv_cache_ed25519_t) cache) {
    if (cache) {
        cache->valid = 0u;
        cache->prev_len = 0u;
        cache->prev_offset = 0u;
        cache->hmac_precomp_valid = 0u;
    }
}

REC_DEVICE REC_FORCEINLINE void get_child_key_secp256k1(
    const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr,
    const size_t precPitch,
    DERIV_THREAD_CONST_PTR(extended_private_key_t) __restrict__ master_private,
    DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ d_derivations,
    const cmr_u32 currentStringLength,
    DERIV_THREAD_REF(cmr_u32) processedElements,
    DERIV_THREAD_PTR(cmr_u8) out,
    DERIV_THREAD_PTR(deriv_cache_secp256k1_t) cache = nullptr) {
    const cmr_u32 path_offset = processedElements;
    DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ deriv = d_derivations + path_offset;
    processedElements += currentStringLength;

    if (currentStringLength == 0u) {
        recovery_deriv_copy_bytes(out, master_private->key, 32u);
        deriv_cache_reset(cache);
        return;
    }

    if (!cache) {
        extended_private_key_t start_key = *master_private;
        for (cmr_u32 i = 0u; i < currentStringLength; ++i) {
            const cmr_u32 derivationValue = deriv[i];
            if (derivationValue < 0x80000000u) {
                normal_private_child_from_private(precPtr, precPitch, &start_key, &start_key, derivationValue);
            } else {
                hardened_private_child_from_private(&start_key, &start_key, derivationValue);
            }
        }
        recovery_deriv_copy_bytes(out, start_key.key, 32u);
        return;
    }

    extended_private_key_t start_key;
    extended_private_key_t parent_before_last = *master_private;
    cmr_u32 i = 0u;
    bool cache_hit = false;
    bool use_cached_pub = false;
    int hit_slot = -1;
    int best_prefix_len = -1;

    for (int s = 0; s < DERIV_CACHE_SLOTS; ++s) {
        if (!cache->valid[s]) continue;
        DERIV_THREAD_CONST_PTR(cmr_u32) slot_deriv = d_derivations + cache->prev_offset[s];
        const cmr_u32 slot_len = cache->prev_len[s];
        int reuse_len = -1;
        bool is_same_except_last = false;

        if (currentStringLength == slot_len && deriv_prefix_equal(deriv, slot_deriv, currentStringLength - 1u)) {
            reuse_len = static_cast<int>(currentStringLength - 1u);
            is_same_except_last = true;
        } else if (slot_len < currentStringLength && deriv_prefix_equal(deriv, slot_deriv, slot_len)) {
            reuse_len = static_cast<int>(slot_len);
        }
        if (reuse_len > best_prefix_len) {
            best_prefix_len = reuse_len;
            hit_slot = s;
            cache_hit = true;
            if (is_same_except_last) {
                start_key = cache->parent_key[s];
                i = currentStringLength - 1u;
                parent_before_last = cache->parent_key[s];
                use_cached_pub = (cache->last_was_normal[s] && deriv[currentStringLength - 1u] < 0x80000000u);
            } else {
                start_key = cache->path_end_key[s];
                i = slot_len;
                parent_before_last = cache->path_end_key[s];
                use_cached_pub = false;
            }
        }
    }

    if (!cache_hit) {
        start_key = *master_private;
    }

    for (; i < currentStringLength; ++i) {
        if (i == currentStringLength - 1u) {
            parent_before_last = start_key;
        }
        const cmr_u32 derivationValue = deriv[i];
        if (derivationValue < 0x80000000u) {
            if (i == currentStringLength - 1u && use_cached_pub && hit_slot >= 0 && cache->hmac_precomp_valid[hit_slot]) {
                normal_private_child_from_private_cached_pub_precomp(&start_key, &start_key, derivationValue, cache->cached_pubkey[hit_slot], &cache->hmac_precomp[hit_slot]);
            } else if (i == currentStringLength - 1u && use_cached_pub && hit_slot >= 0) {
                normal_private_child_from_private_cached_pub(&start_key, &start_key, derivationValue, cache->cached_pubkey[hit_slot]);
            } else if (cache && i == currentStringLength - 1u) {
                normal_private_child_from_private_save_pub(precPtr, precPitch, &start_key, &start_key, derivationValue, cache->cached_pubkey[0]);
            } else {
                normal_private_child_from_private(precPtr, precPitch, &start_key, &start_key, derivationValue);
            }
        } else {
            if (i == currentStringLength - 1u && cache_hit && hit_slot >= 0 && cache->hmac_precomp_valid[hit_slot]) {
                hardened_private_child_from_private_precomp(&start_key, &start_key, derivationValue, &cache->hmac_precomp[hit_slot]);
            } else {
                hardened_private_child_from_private(&start_key, &start_key, derivationValue);
            }
        }
    }

    recovery_deriv_copy_bytes(out, start_key.key, 32u);

    if (cache) {
        int store_slot = -1;
        for (int s = 0; s < DERIV_CACHE_SLOTS; ++s) {
            if (!cache->valid[s]) {
                store_slot = s;
                break;
            }
        }
        if (store_slot < 0) store_slot = 0;

        cache->prev_offset[store_slot] = path_offset;
        cache->prev_len[store_slot] = currentStringLength;
        cache->valid[store_slot] = 1u;
        cache->parent_key[store_slot] = parent_before_last;
        cache->path_end_key[store_slot] = start_key;
        if (deriv[currentStringLength - 1u] < 0x80000000u) {
            DERIV_THREAD_CONST_PTR(cmr_u8) src = (cache_hit && use_cached_pub && hit_slot >= 0) ? cache->cached_pubkey[hit_slot] : cache->cached_pubkey[0];
            recovery_deriv_copy_bytes(cache->cached_pubkey[store_slot], src, 33u);
        }
        cache->last_was_normal[store_slot] = (deriv[currentStringLength - 1u] < 0x80000000u) ? 1u : 0u;
        hmac_sha512_const_precompute((DERIV_THREAD_CONST_PTR(cmr_u32))parent_before_last.chain_code, &cache->hmac_precomp[store_slot]);
        cache->hmac_precomp_valid[store_slot] = 1u;
    }
}

REC_DEVICE REC_FORCEINLINE void get_child_key_ed25519(
    DERIV_THREAD_CONST_PTR(extended_private_key_t) __restrict__ master_private,
    DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ d_derivations,
    const cmr_u32 currentStringLength,
    DERIV_THREAD_REF(cmr_u32) processedElements,
    DERIV_THREAD_PTR(cmr_u8) out,
    DERIV_THREAD_PTR(deriv_cache_ed25519_t) cache = nullptr) {
    const cmr_u32 path_offset = processedElements;
    DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ deriv = d_derivations + path_offset;
    processedElements += currentStringLength;

    if (currentStringLength == 0u) {
        recovery_deriv_copy_bytes(out, master_private->key, 32u);
        deriv_cache_reset(cache);
        return;
    }

    if (!cache) {
        extended_private_key_t start_key = *master_private;
        for (cmr_u32 i = 0u; i < currentStringLength; ++i) {
            cmr_u32 der_ed = deriv[i];
            if (der_ed < 0x80000000u) {
                der_ed |= 0x80000000u;
            }
            hardened_private_child_from_private_ed25519(&start_key, &start_key, der_ed);
        }
        recovery_deriv_copy_bytes(out, start_key.key, 32u);
        return;
    }

    extended_private_key_t start_key;
    extended_private_key_t parent_before_last = *master_private;
    cmr_u32 i = 0u;
    bool cache_hit = false;

    if (cache &&
        cache->valid &&
        currentStringLength == cache->prev_len &&
        deriv_prefix_equal(deriv, d_derivations + cache->prev_offset, currentStringLength - 1u)) {
        cache_hit = true;
        start_key = cache->parent_key;
        i = currentStringLength - 1u;
        parent_before_last = cache->parent_key;
    } else {
        start_key = *master_private;
    }

    for (; i < currentStringLength; ++i) {
        if (i == currentStringLength - 1u) {
            parent_before_last = start_key;
        }
        cmr_u32 der_ed = deriv[i];
        if (der_ed < 0x80000000u) {
            der_ed |= 0x80000000u;
        }
        if (i == currentStringLength - 1u && cache_hit && cache->hmac_precomp_valid) {
            hardened_private_child_from_private_ed25519_precomp(&start_key, &start_key, der_ed, &cache->hmac_precomp);
        } else {
            hardened_private_child_from_private_ed25519(&start_key, &start_key, der_ed);
        }
    }

    recovery_deriv_copy_bytes(out, start_key.key, 32u);

    if (cache) {
        cache->prev_offset = path_offset;
        cache->prev_len = currentStringLength;
        cache->valid = 1u;
        cache->parent_key = parent_before_last;
        hmac_sha512_const_precompute((DERIV_THREAD_CONST_PTR(cmr_u32))parent_before_last.chain_code, &cache->hmac_precomp);
        cache->hmac_precomp_valid = 1u;
    }
}

REC_DEVICE REC_FORCEINLINE void get_child_key_ed25519_bip32(
    DERIV_THREAD_CONST_PTR(extended_private_key_t) __restrict__ master_private,
    DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ d_derivations,
    const cmr_u32 currentStringLength,
    DERIV_THREAD_REF(cmr_u32) processedElements,
    DERIV_THREAD_PTR(cmr_u8) out32) {
    DERIV_THREAD_CONST_PTR(cmr_u32) __restrict__ deriv = d_derivations + processedElements;
    processedElements += currentStringLength;

    extended_private_key_t k = *master_private;
    for (cmr_u32 i = 0u; i < currentStringLength; ++i) {
        const cmr_u32 idx = deriv[i];
        if (idx & 0x80000000u) {
            ed25519_bip32_ckd_priv_hardened(&k, &k, idx);
        } else {
            ed25519_bip32_ckd_priv_normal(&k, &k, idx);
        }
    }
    recovery_deriv_copy_bytes(out32, k.key, 32u);
}
