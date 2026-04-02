#pragma once

#include "metal/RecoveryCryptoCommon.h"
#include "metal/RecoveryDerivationTypes.h"

#include "third_party/secp256k1/secp256k1.h"
#include "third_party/ed25519/ed25519.h"

#if defined(__METAL_VERSION__)
#define REC_DERIV_THREAD_PTR(T) thread T*
#define REC_DERIV_THREAD_CONST_PTR(T) thread const T*
#else
#define REC_DERIV_THREAD_PTR(T) T*
#define REC_DERIV_THREAD_CONST_PTR(T) const T*
#endif

static inline void recovery_hmac_sha512_precomp_import(
    const thread RecoveryHmacSha512Precomp& src,
    REC_DERIV_THREAD_PTR(hmac_sha512_precomp_t) dst) {

    for (cmr_u32 i = 0u; i < 8u; ++i) {
        dst->inner_H[i] = src.inner_H[i];
        dst->outer_H[i] = src.outer_H[i];
    }
}

static inline void recovery_hmac_sha512_precomp_export(
    REC_DERIV_THREAD_CONST_PTR(hmac_sha512_precomp_t) src,
    thread RecoveryHmacSha512Precomp* dst) {

    for (cmr_u32 i = 0u; i < 8u; ++i) {
        dst->inner_H[i] = src->inner_H[i];
        dst->outer_H[i] = src->outer_H[i];
    }
}

static inline void recovery_hmac_sha512_from_compat_precomp(
    REC_DERIV_THREAD_CONST_PTR(hmac_sha512_precomp_t) ctx,
    const thread cmr_u8* data,
    const cmr_u32 data_len,
    thread cmr_u8 out[64]) {
    thread cmr_u8 inner_block[128];
    recovery_zero_thread_bytes(inner_block, 128u);
    recovery_copy_thread_bytes(inner_block, data, data_len);
    inner_block[data_len] = 0x80u;
    recovery_sha512_store_be64(0u, inner_block + 112u);
    recovery_sha512_store_be64(cmr_u64(128u + data_len) * 8u, inner_block + 120u);

    thread cmr_u64 inner_state[8];
    recovery_copy_thread_bytes(reinterpret_cast<thread cmr_u8*>(inner_state),
                               reinterpret_cast<const thread cmr_u8*>(ctx->inner_H),
                               64u);
    recovery_sha512_compress(inner_state, inner_block);

    thread cmr_u8 inner_digest[64];
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        recovery_sha512_store_be64(inner_state[i], inner_digest + (i * 8u));
    }

    thread cmr_u8 outer_block[128];
    recovery_zero_thread_bytes(outer_block, 128u);
    recovery_copy_thread_bytes(outer_block, inner_digest, 64u);
    outer_block[64u] = 0x80u;
    recovery_sha512_store_be64(0u, outer_block + 112u);
    recovery_sha512_store_be64((128u + 64u) * 8u, outer_block + 120u);

    thread cmr_u64 outer_state[8];
    recovery_copy_thread_bytes(reinterpret_cast<thread cmr_u8*>(outer_state),
                               reinterpret_cast<const thread cmr_u8*>(ctx->outer_H),
                               64u);
    recovery_sha512_compress(outer_state, outer_block);
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        recovery_sha512_store_be64(outer_state[i], out + (i * 8u));
    }
}

REC_DEVICE REC_FORCEINLINE void hmac_sha512_const_precompute(
    REC_DERIV_THREAD_CONST_PTR(cmr_u32) key,
    REC_DERIV_THREAD_PTR(hmac_sha512_precomp_t) ctx) {

    thread RecoveryHmacSha512Precomp local_ctx;
    recovery_hmac_sha512_precompute_32(reinterpret_cast<const thread cmr_u8*>(key), &local_ctx);
    recovery_hmac_sha512_precomp_import(local_ctx, ctx);
}

REC_DEVICE REC_FORCEINLINE void hmac_sha512_const_precomp(
    REC_DERIV_THREAD_CONST_PTR(hmac_sha512_precomp_t) ctx,
    REC_DERIV_THREAD_CONST_PTR(cmr_u32) message,
    REC_DERIV_THREAD_PTR(cmr_u32) output) {

    recovery_hmac_sha512_from_precomp_37(ctx->inner_H,
                                         ctx->outer_H,
                                         reinterpret_cast<const thread cmr_u8*>(message),
                                         reinterpret_cast<thread cmr_u8*>(output));
}

REC_DEVICE REC_FORCEINLINE void hmac_sha512_const(
    REC_DERIV_THREAD_CONST_PTR(cmr_u32) key,
    REC_DERIV_THREAD_CONST_PTR(cmr_u32) message,
    REC_DERIV_THREAD_PTR(cmr_u32) output) {

    recovery_hmac_sha512_32_37(reinterpret_cast<const thread cmr_u8*>(key),
                               reinterpret_cast<const thread cmr_u8*>(message),
                               reinterpret_cast<thread cmr_u8*>(output));
}

REC_DEVICE REC_FORCEINLINE void hardened_private_child_from_private(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 hardened_child_number) {

    thread cmr_u8 hmac_input[37];
    hmac_input[0] = 0u;
    recovery_copy_thread_bytes(hmac_input + 1u, parent->key, 32u);
    hmac_input[33] = cmr_u8((hardened_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((hardened_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((hardened_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(hardened_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_32_37(parent->chain_code, hmac_input, digest);
    secp256k1_ec_seckey_tweak_add(digest, parent->key);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void hardened_private_child_from_private_precomp(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 hardened_child_number,
    REC_DERIV_THREAD_CONST_PTR(hmac_sha512_precomp_t) hctx) {

    thread cmr_u8 hmac_input[37];
    hmac_input[0] = 0u;
    recovery_copy_thread_bytes(hmac_input + 1u, parent->key, 32u);
    hmac_input[33] = cmr_u8((hardened_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((hardened_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((hardened_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(hardened_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_from_precomp_37(hctx->inner_H, hctx->outer_H, hmac_input, digest);
    secp256k1_ec_seckey_tweak_add(digest, parent->key);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void normal_private_child_from_private(
    const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr,
    const size_t precPitch,
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 normal_child_number) {

    extended_public_key_t pub;
    secp256k1_ec_pubkey_create(reinterpret_cast<REC_DERIV_THREAD_PTR(secp256k1_pubkey)>(&pub.key), parent->key, precPtr, precPitch);

    thread cmr_u8 hmac_input[37];
    serialized_public_key(reinterpret_cast<SECP_THREAD uint8_t*>(&pub.key), reinterpret_cast<SECP_THREAD uint8_t*>(hmac_input));
    hmac_input[33] = cmr_u8((normal_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((normal_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((normal_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(normal_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_32_37(parent->chain_code, hmac_input, digest);
    secp256k1_ec_seckey_tweak_add(digest, parent->key);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void normal_private_child_from_private_cached_pub(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 normal_child_number,
    REC_DERIV_THREAD_CONST_PTR(cmr_u8) cached_serialized_pub) {

    thread cmr_u8 hmac_input[37];
    recovery_copy_thread_bytes(hmac_input, cached_serialized_pub, 33u);
    hmac_input[33] = cmr_u8((normal_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((normal_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((normal_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(normal_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_32_37(parent->chain_code, hmac_input, digest);
    secp256k1_ec_seckey_tweak_add(digest, parent->key);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void normal_private_child_from_private_cached_pub_precomp(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 normal_child_number,
    REC_DERIV_THREAD_CONST_PTR(cmr_u8) cached_serialized_pub,
    REC_DERIV_THREAD_CONST_PTR(hmac_sha512_precomp_t) hctx) {

    thread cmr_u8 hmac_input[37];
    recovery_copy_thread_bytes(hmac_input, cached_serialized_pub, 33u);
    hmac_input[33] = cmr_u8((normal_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((normal_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((normal_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(normal_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_from_precomp_37(hctx->inner_H, hctx->outer_H, hmac_input, digest);
    secp256k1_ec_seckey_tweak_add(digest, parent->key);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void normal_private_child_from_private_save_pub(
    const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr,
    const size_t precPitch,
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 normal_child_number,
    REC_DERIV_THREAD_PTR(cmr_u8) out_serialized_pub) {

    extended_public_key_t pub;
    secp256k1_ec_pubkey_create(reinterpret_cast<REC_DERIV_THREAD_PTR(secp256k1_pubkey)>(&pub.key), parent->key, precPtr, precPitch);

    thread cmr_u8 hmac_input[37];
    serialized_public_key(reinterpret_cast<SECP_THREAD uint8_t*>(&pub.key), reinterpret_cast<SECP_THREAD uint8_t*>(hmac_input));
    recovery_copy_thread_bytes(out_serialized_pub, hmac_input, 33u);
    hmac_input[33] = cmr_u8((normal_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((normal_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((normal_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(normal_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_32_37(parent->chain_code, hmac_input, digest);
    secp256k1_ec_seckey_tweak_add(digest, parent->key);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void hardened_private_child_from_private_ed25519(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 hardened_child_number) {

    thread cmr_u8 hmac_input[37];
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

REC_DEVICE REC_FORCEINLINE void hardened_private_child_from_private_ed25519_precomp(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 hardened_child_number,
    REC_DERIV_THREAD_CONST_PTR(hmac_sha512_precomp_t) hctx) {

    thread cmr_u8 hmac_input[37];
    hmac_input[0] = 0u;
    recovery_copy_thread_bytes(hmac_input + 1u, parent->key, 32u);
    hmac_input[33] = cmr_u8((hardened_child_number >> 24u) & 0xFFu);
    hmac_input[34] = cmr_u8((hardened_child_number >> 16u) & 0xFFu);
    hmac_input[35] = cmr_u8((hardened_child_number >> 8u) & 0xFFu);
    hmac_input[36] = cmr_u8(hardened_child_number & 0xFFu);

    thread cmr_u8 digest[64];
    recovery_hmac_sha512_from_precomp_37(hctx->inner_H, hctx->outer_H, hmac_input, digest);
    recovery_copy_thread_bytes(child->key, digest, 32u);
    recovery_copy_thread_bytes(child->chain_code, digest + 32u, 32u);
}

REC_DEVICE REC_FORCEINLINE void ed25519_bip32_ckd_priv_hardened(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 i_hardened) {

    hardened_private_child_from_private_ed25519(parent, child, i_hardened);
}

REC_DEVICE REC_FORCEINLINE void ed25519_bip32_ckd_priv_normal(
    REC_DERIV_THREAD_CONST_PTR(extended_private_key_t) parent,
    REC_DERIV_THREAD_PTR(extended_private_key_t) child,
    const cmr_u32 i_normal) {

    thread cmr_u8 parent_public_key[32];
    ed25519_publickey(parent->key, parent_public_key);

    thread cmr_u8 in_z[37];
    thread cmr_u8 in_i2[37];
    in_z[0] = 0x02u;
    in_i2[0] = 0x03u;
    recovery_copy_thread_bytes(in_z + 1u, parent_public_key, 32u);
    recovery_copy_thread_bytes(in_i2 + 1u, parent_public_key, 32u);
    in_z[33] = cmr_u8((i_normal >> 24u) & 0xFFu);
    in_z[34] = cmr_u8((i_normal >> 16u) & 0xFFu);
    in_z[35] = cmr_u8((i_normal >> 8u) & 0xFFu);
    in_z[36] = cmr_u8(i_normal & 0xFFu);
    recovery_copy_thread_bytes(in_i2 + 33u, in_z + 33u, 4u);

    thread cmr_u8 z64[64];
    thread cmr_u8 i2[64];
    recovery_hmac_sha512(parent->chain_code, 32u, in_z, 37u, z64);
    recovery_hmac_sha512(parent->chain_code, 32u, in_i2, 37u, i2);

    add_modL_from_bytes(child->key, parent->key, z64);
    recovery_copy_thread_bytes(child->chain_code, i2 + 32u, 32u);
}

static constant cmr_u8 kRecoveryTapTweakTagHash[32] = {
    0xe8u, 0x0fu, 0xe1u, 0x63u, 0x9cu, 0x9cu, 0xa0u, 0x50u,
    0xe3u, 0xafu, 0x1bu, 0x39u, 0xc1u, 0x43u, 0xc6u, 0x3eu,
    0x42u, 0x9cu, 0xbcu, 0xebu, 0x15u, 0xd9u, 0x40u, 0xfbu,
    0xb5u, 0xc5u, 0xa1u, 0xf4u, 0xafu, 0x57u, 0xc5u, 0xe9u
};

static inline void recovery_sha256_taptweak_px(const thread cmr_u8 px[32], thread cmr_u8 out[32]) {
    thread cmr_u8 input[96];
    recovery_copy_constant_to_thread_bytes(input, kRecoveryTapTweakTagHash, 32u);
    recovery_copy_constant_to_thread_bytes(input + 32u, kRecoveryTapTweakTagHash, 32u);
    recovery_copy_thread_bytes(input + 64u, px, 32u);
    recovery_sha256_digest(input, 96u, out);
}

REC_DEVICE REC_FORCEINLINE void TweakTaproot(
    SECP_THREAD cmr_u8* __restrict__ out,
    const SECP_THREAD cmr_u8* __restrict__ pub_uncomp,
    const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr,
    const size_t precPitch) {

    secp256k1_gej gej;
    secp256k1_fe fe_in;
    secp256k1_fe fe_out;

    if (pub_uncomp[0] != 0x04u) {
        gej.infinity = 1;
        return;
    }

    secp256k1_fe x;
    secp256k1_fe y;
    (void)secp256k1_fe_set_b32(&x, pub_uncomp + 1u);
    (void)secp256k1_fe_set_b32(&y, pub_uncomp + 33u);
    secp256k1_ge p;
    secp256k1_ge_set_xy(&p, &x, &y);

    secp256k1_fe_normalize_var(&p.y);
    if (secp256k1_fe_is_odd(&p.y)) {
        secp256k1_ge pneg = p;
        secp256k1_fe_negate(&pneg.y, &pneg.y, 1);
        p = pneg;
    }

    thread cmr_u8 px[32];
    thread cmr_u8 tweak_hash[32];
    secp256k1_fe_normalize_var(&p.x);
    secp256k1_fe_get_b32(px, &p.x);
    recovery_sha256_taptweak_px(px, tweak_hash);

    secp256k1_scalar tweak_scalar;
    secp256k1_scalar_set_b32(&tweak_scalar, tweak_hash, nullptr);

    secp256k1_gej tweak_point;
#ifdef ECMULT_BIG_TABLE
    if (precPtr == nullptr || precPitch == 0u) {
        secp256k1_ecmult_gen(&tweak_point, &tweak_scalar);
    } else {
        const int window_limit = WINDOWS_SIZE_CONST[0];
        const unsigned int wlimit = ECMULT_WINDOW_SIZE_CONST[0];
        secp256k1_ecmult_big(&tweak_point, &tweak_scalar, precPtr, precPitch, window_limit, wlimit);
    }
#else
    secp256k1_ecmult_gen(&tweak_point, &tweak_scalar);
#endif

    secp256k1_gej_add_ge_var(&gej, &tweak_point, &p, nullptr);
    if (gej.infinity) {
        for (cmr_u32 i = 0u; i < 32u; ++i) {
            out[i] = 0u;
        }
        return;
    }

    fe_in = gej.z;
    secp256k1_fe_inv_all_var(1, &fe_out, &fe_in);

    secp256k1_ge tweaked;
    secp256k1_ge_set_gej_zinv(&tweaked, &gej, &fe_out);
    secp256k1_fe_normalize_var(&tweaked.y);
    if (secp256k1_fe_is_odd(&tweaked.y)) {
        secp256k1_ge_neg(&tweaked, &tweaked);
    }

    secp256k1_fe_normalize_var(&tweaked.x);
    secp256k1_fe_get_b32(out, &tweaked.x);
}

#undef REC_DERIV_THREAD_PTR
#undef REC_DERIV_THREAD_CONST_PTR
