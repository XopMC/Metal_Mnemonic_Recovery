#pragma once

#include "metal/RecoveryMetalTypes.h"

static inline void recovery_zero_thread_bytes(thread cmr_u8* dst, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        dst[i] = 0u;
    }
}

static inline void recovery_copy_thread_bytes(thread cmr_u8* dst, const thread cmr_u8* src, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

static inline void recovery_copy_constant_to_thread_bytes(thread cmr_u8* dst, const constant cmr_u8* src, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

static inline void recovery_copy_device_to_thread_bytes(thread cmr_u8* dst, const device cmr_u8* src, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

static inline void recovery_copy_thread_to_device_bytes(device cmr_u8* dst, const thread cmr_u8* src, const cmr_u32 len) {
    for (cmr_u32 i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

static inline uint recovery_rotr32(const uint x, const uint n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint recovery_ch32(const uint x, const uint y, const uint z) {
    return z ^ (x & (y ^ z));
}

static inline uint recovery_maj32(const uint x, const uint y, const uint z) {
    return (x & y) | (z & (x | y));
}

static inline uint recovery_ep0_32(const uint x) {
    return recovery_rotr32(x, 2u) ^ recovery_rotr32(x, 13u) ^ recovery_rotr32(x, 22u);
}

static inline uint recovery_ep1_32(const uint x) {
    return recovery_rotr32(x, 6u) ^ recovery_rotr32(x, 11u) ^ recovery_rotr32(x, 25u);
}

static inline uint recovery_sig0_32(const uint x) {
    return recovery_rotr32(x, 7u) ^ recovery_rotr32(x, 18u) ^ (x >> 3u);
}

static inline uint recovery_sig1_32(const uint x) {
    return recovery_rotr32(x, 17u) ^ recovery_rotr32(x, 19u) ^ (x >> 10u);
}

static constant uint kRecoverySha256Constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint recovery_sha256_load_be32(const thread cmr_u8* data, const uint offset) {
    return (uint(data[offset + 0u]) << 24u) |
           (uint(data[offset + 1u]) << 16u) |
           (uint(data[offset + 2u]) << 8u) |
            uint(data[offset + 3u]);
}

static inline void recovery_sha256_store_be32(const uint value, thread cmr_u8* out) {
    out[0] = cmr_u8((value >> 24u) & 0xFFu);
    out[1] = cmr_u8((value >> 16u) & 0xFFu);
    out[2] = cmr_u8((value >> 8u) & 0xFFu);
    out[3] = cmr_u8(value & 0xFFu);
}

static inline void recovery_sha256_compress_words(thread uint state[8], const thread uint words[16]) {
    uint w[64];
    for (uint i = 0u; i < 16u; ++i) {
        w[i] = words[i];
    }
    for (uint i = 16u; i < 64u; ++i) {
        w[i] = recovery_sig1_32(w[i - 2u]) + w[i - 7u] + recovery_sig0_32(w[i - 15u]) + w[i - 16u];
    }

    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (uint i = 0u; i < 64u; ++i) {
        const uint t1 = h + recovery_ep1_32(e) + recovery_ch32(e, f, g) + kRecoverySha256Constants[i] + w[i];
        const uint t2 = recovery_ep0_32(a) + recovery_maj32(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static inline void recovery_sha256_compress(thread uint state[8], const thread cmr_u8* block) {
    uint w[16];
    for (uint i = 0u; i < 16u; ++i) {
        w[i] = recovery_sha256_load_be32(block, i * 4u);
    }
    recovery_sha256_compress_words(state, w);
}

#if defined(__METAL_VERSION__)
static inline void SHA256Initialize(thread uint32_t s[8]) {
    s[0] = 0x6a09e667u;
    s[1] = 0xbb67ae85u;
    s[2] = 0x3c6ef372u;
    s[3] = 0xa54ff53au;
    s[4] = 0x510e527fu;
    s[5] = 0x9b05688cu;
    s[6] = 0x1f83d9abu;
    s[7] = 0x5be0cd19u;
}

static inline void SHA256Transform(thread uint32_t s[8], thread uint32_t* w) {
    recovery_sha256_compress_words(s, w);
}
#endif

static inline void recovery_sha256_digest(const thread cmr_u8* data, const cmr_u32 len, thread cmr_u8 out[32]) {
    thread uint state[8];
    SHA256Initialize(state);

    cmr_u32 offset = 0u;
    while ((offset + 64u) <= len) {
        recovery_sha256_compress(state, data + offset);
        offset += 64u;
    }

    thread cmr_u8 final_blocks[128];
    recovery_zero_thread_bytes(final_blocks, 128u);
    const cmr_u32 remainder = len - offset;
    recovery_copy_thread_bytes(final_blocks, data + offset, remainder);
    final_blocks[remainder] = 0x80u;

    const cmr_u64 bit_len = cmr_u64(len) * 8u;
    if (remainder >= 56u) {
        recovery_sha256_compress(state, final_blocks);
        recovery_zero_thread_bytes(final_blocks, 128u);
        recovery_sha256_store_be32(cmr_u32(bit_len >> 32u), final_blocks + 120u);
        recovery_sha256_store_be32(cmr_u32(bit_len & 0xFFFFFFFFu), final_blocks + 124u);
        recovery_sha256_compress(state, final_blocks + 64u);
    } else {
        recovery_sha256_store_be32(cmr_u32(bit_len >> 32u), final_blocks + 56u);
        recovery_sha256_store_be32(cmr_u32(bit_len & 0xFFFFFFFFu), final_blocks + 60u);
        recovery_sha256_compress(state, final_blocks);
    }

    for (uint i = 0u; i < 8u; ++i) {
        recovery_sha256_store_be32(state[i], out + (i * 4u));
    }
}

static inline cmr_u64 recovery_rotr64(const cmr_u64 x, const cmr_u32 n) {
    return (x >> n) | (x << (64u - n));
}

static inline cmr_u64 recovery_sha512_ch(const cmr_u64 x, const cmr_u64 y, const cmr_u64 z) {
    return (x & y) ^ ((~x) & z);
}

static inline cmr_u64 recovery_sha512_maj(const cmr_u64 x, const cmr_u64 y, const cmr_u64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline cmr_u64 recovery_sha512_big_sigma0(const cmr_u64 x) {
    return recovery_rotr64(x, 28u) ^ recovery_rotr64(x, 34u) ^ recovery_rotr64(x, 39u);
}

static inline cmr_u64 recovery_sha512_big_sigma1(const cmr_u64 x) {
    return recovery_rotr64(x, 14u) ^ recovery_rotr64(x, 18u) ^ recovery_rotr64(x, 41u);
}

static inline cmr_u64 recovery_sha512_small_sigma0(const cmr_u64 x) {
    return recovery_rotr64(x, 1u) ^ recovery_rotr64(x, 8u) ^ (x >> 7u);
}

static inline cmr_u64 recovery_sha512_small_sigma1(const cmr_u64 x) {
    return recovery_rotr64(x, 19u) ^ recovery_rotr64(x, 61u) ^ (x >> 6u);
}

static constant cmr_u64 kRecoverySha512Constants[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
    0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull,
    0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
    0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
    0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
    0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffCull, 0x2e1b21385c26c926ull,
    0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
    0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull,
    0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
    0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
    0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
    0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
    0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull,
    0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

struct RecoverySha512Context {
    cmr_u64 state[8];
    cmr_u64 total_len;
    cmr_u8 buffer[128];
    cmr_u32 buffer_len;
};

static inline cmr_u64 recovery_sha512_load_be64(const thread cmr_u8* data, const cmr_u32 offset) {
    return (cmr_u64(data[offset + 0u]) << 56u) |
           (cmr_u64(data[offset + 1u]) << 48u) |
           (cmr_u64(data[offset + 2u]) << 40u) |
           (cmr_u64(data[offset + 3u]) << 32u) |
           (cmr_u64(data[offset + 4u]) << 24u) |
           (cmr_u64(data[offset + 5u]) << 16u) |
           (cmr_u64(data[offset + 6u]) << 8u) |
            cmr_u64(data[offset + 7u]);
}

static inline cmr_u64 recovery_sha512_load_be64(const thread cmr_u8* data) {
    return recovery_sha512_load_be64(data, 0u);
}

static inline void recovery_sha512_store_be64(const cmr_u64 value, thread cmr_u8* out) {
    out[0] = cmr_u8((value >> 56u) & 0xFFu);
    out[1] = cmr_u8((value >> 48u) & 0xFFu);
    out[2] = cmr_u8((value >> 40u) & 0xFFu);
    out[3] = cmr_u8((value >> 32u) & 0xFFu);
    out[4] = cmr_u8((value >> 24u) & 0xFFu);
    out[5] = cmr_u8((value >> 16u) & 0xFFu);
    out[6] = cmr_u8((value >> 8u) & 0xFFu);
    out[7] = cmr_u8(value & 0xFFu);
}

static inline void recovery_sha512_compress_words(thread cmr_u64 state[8], const cmr_u64 first_words[16]) {
    cmr_u64 w[80];
    for (cmr_u32 i = 0u; i < 16u; ++i) {
        w[i] = first_words[i];
    }
    for (cmr_u32 i = 16u; i < 80u; ++i) {
        w[i] = recovery_sha512_small_sigma1(w[i - 2u]) + w[i - 7u] + recovery_sha512_small_sigma0(w[i - 15u]) + w[i - 16u];
    }

    cmr_u64 a = state[0];
    cmr_u64 b = state[1];
    cmr_u64 c = state[2];
    cmr_u64 d = state[3];
    cmr_u64 e = state[4];
    cmr_u64 f = state[5];
    cmr_u64 g = state[6];
    cmr_u64 h = state[7];

    for (cmr_u32 i = 0u; i < 80u; ++i) {
        const cmr_u64 t1 = h + recovery_sha512_big_sigma1(e) + recovery_sha512_ch(e, f, g) + kRecoverySha512Constants[i] + w[i];
        const cmr_u64 t2 = recovery_sha512_big_sigma0(a) + recovery_sha512_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static inline void recovery_sha512_compress(thread cmr_u64 state[8], const thread cmr_u8* block) {
    cmr_u64 w[16];
    for (cmr_u32 i = 0u; i < 16u; ++i) {
        w[i] = recovery_sha512_load_be64(block + (i * 8u));
    }
    recovery_sha512_compress_words(state, w);
}

static inline void recovery_sha512_init(thread RecoverySha512Context* ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ull;
    ctx->state[1] = 0xbb67ae8584caa73bull;
    ctx->state[2] = 0x3c6ef372fe94f82bull;
    ctx->state[3] = 0xa54ff53a5f1d36f1ull;
    ctx->state[4] = 0x510e527fade682d1ull;
    ctx->state[5] = 0x9b05688c2b3e6c1full;
    ctx->state[6] = 0x1f83d9abfb41bd6bull;
    ctx->state[7] = 0x5be0cd19137e2179ull;
    ctx->total_len = 0u;
    ctx->buffer_len = 0u;
    recovery_zero_thread_bytes(ctx->buffer, 128u);
}

static inline void recovery_sha512_update(thread RecoverySha512Context* ctx, const thread cmr_u8* data, const cmr_u32 len) {
    if (data == nullptr || len == 0u) {
        return;
    }

    ctx->total_len += cmr_u64(len);
    cmr_u32 offset = 0u;

    if (ctx->buffer_len > 0u) {
        const cmr_u32 space = 128u - ctx->buffer_len;
        const cmr_u32 take = len < space ? len : space;
        recovery_copy_thread_bytes(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        offset += take;
        if (ctx->buffer_len == 128u) {
            recovery_sha512_compress(ctx->state, ctx->buffer);
            ctx->buffer_len = 0u;
        }
    }

    while ((offset + 128u) <= len) {
        recovery_sha512_compress(ctx->state, data + offset);
        offset += 128u;
    }

    if (offset < len) {
        const cmr_u32 remaining = len - offset;
        recovery_copy_thread_bytes(ctx->buffer, data + offset, remaining);
        ctx->buffer_len = remaining;
    }
}

static inline void recovery_sha512_final(thread RecoverySha512Context* ctx, thread cmr_u8 out[64]) {
    thread cmr_u8 block[128];
    recovery_zero_thread_bytes(block, 128u);
    recovery_copy_thread_bytes(block, ctx->buffer, ctx->buffer_len);
    block[ctx->buffer_len] = 0x80u;

    if (ctx->buffer_len >= 112u) {
        recovery_sha512_compress(ctx->state, block);
        recovery_zero_thread_bytes(block, 128u);
    }

    const cmr_u64 bit_len = ctx->total_len * 8u;
    recovery_sha512_store_be64(0u, block + 112u);
    recovery_sha512_store_be64(bit_len, block + 120u);
    recovery_sha512_compress(ctx->state, block);

    for (cmr_u32 i = 0u; i < 8u; ++i) {
        recovery_sha512_store_be64(ctx->state[i], out + (i * 8u));
    }
}

static inline void recovery_sha512_digest(const thread cmr_u8* data, const cmr_u32 len, thread cmr_u8 out[64]) {
    RecoverySha512Context ctx;
    recovery_sha512_init(&ctx);
    recovery_sha512_update(&ctx, data, len);
    recovery_sha512_final(&ctx, out);
}

struct RecoveryHmacSha512Precomp {
    cmr_u64 inner_H[8];
    cmr_u64 outer_H[8];
};

static inline cmr_u64 recovery_hmac_sha512_load_key_word_be(const thread cmr_u8* key,
                                                            const cmr_u32 key_len,
                                                            const cmr_u32 word_idx) {
    const cmr_u32 offset = word_idx * 8u;
    if (offset >= key_len) {
        return 0u;
    }
    if ((offset + 8u) <= key_len) {
        return recovery_sha512_load_be64(key, offset);
    }

    cmr_u64 word = 0u;
    const cmr_u32 tail = key_len - offset;
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        word <<= 8u;
        if (i < tail) {
            word |= cmr_u64(key[offset + i]);
        }
    }
    return word;
}

static inline void recovery_sha512_transform_words(const cmr_u64 state_in[8],
                                                   cmr_u64 state_out[8],
                                                   const cmr_u64 block_words[16]) {
    recovery_copy_thread_bytes(reinterpret_cast<thread cmr_u8*>(state_out),
                               reinterpret_cast<const thread cmr_u8*>(state_in),
                               64u);
    recovery_sha512_compress_words(state_out, block_words);
}

static inline void recovery_hmac_sha512_precompute(const thread cmr_u8* key,
                                                   const cmr_u32 key_len,
                                                   thread RecoveryHmacSha512Precomp* out_ctx) {
    thread cmr_u8 hashed_key[64];
    const thread cmr_u8* effective_key = key;
    cmr_u32 effective_len = key_len;
    if (effective_len > 128u) {
        recovery_sha512_digest(key, effective_len, hashed_key);
        effective_key = hashed_key;
        effective_len = 64u;
    }

    cmr_u64 block_words[16];
    for (cmr_u32 i = 0u; i < 16u; ++i) {
        block_words[i] = recovery_hmac_sha512_load_key_word_be(effective_key, effective_len, i) ^ 0x3636363636363636ull;
    }
    const cmr_u64 iv[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
    };
    recovery_sha512_transform_words(iv, out_ctx->inner_H, block_words);

    for (cmr_u32 i = 0u; i < 16u; ++i) {
        block_words[i] ^= 0x6a6a6a6a6a6a6a6aull;
    }
    recovery_sha512_transform_words(iv, out_ctx->outer_H, block_words);
}

static inline void recovery_hmac_sha512_precompute_32(const thread cmr_u8 key[32],
                                                      thread RecoveryHmacSha512Precomp* out_ctx) {
    cmr_u64 block_words[16];
    for (cmr_u32 i = 0u; i < 4u; ++i) {
        block_words[i] = recovery_sha512_load_be64(key, i * 8u) ^ 0x3636363636363636ull;
    }
    for (cmr_u32 i = 4u; i < 16u; ++i) {
        block_words[i] = 0x3636363636363636ull;
    }
    const cmr_u64 iv[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
    };
    recovery_sha512_transform_words(iv, out_ctx->inner_H, block_words);

    for (cmr_u32 i = 0u; i < 4u; ++i) {
        block_words[i] ^= 0x6a6a6a6a6a6a6a6aull;
    }
    for (cmr_u32 i = 4u; i < 16u; ++i) {
        block_words[i] = 0x5c5c5c5c5c5c5c5cull;
    }
    recovery_sha512_transform_words(iv, out_ctx->outer_H, block_words);
}

static inline void recovery_hmac_sha512(const thread cmr_u8* key,
                                        const cmr_u32 key_len,
                                        const thread cmr_u8* data,
                                        const cmr_u32 data_len,
                                        thread cmr_u8 out[64]) {
    thread RecoveryHmacSha512Precomp ctx;
    recovery_hmac_sha512_precompute(key, key_len, &ctx);

    thread cmr_u8 inner_block[128];
    recovery_zero_thread_bytes(inner_block, 128u);
    recovery_copy_thread_bytes(inner_block, data, data_len);
    inner_block[data_len] = 0x80u;
    recovery_sha512_store_be64(0u, inner_block + 112u);
    recovery_sha512_store_be64(cmr_u64(128u + data_len) * 8u, inner_block + 120u);

    thread cmr_u64 inner_state[8];
    recovery_copy_thread_bytes(reinterpret_cast<thread cmr_u8*>(inner_state),
                               reinterpret_cast<const thread cmr_u8*>(ctx.inner_H),
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
                               reinterpret_cast<const thread cmr_u8*>(ctx.outer_H),
                               64u);
    recovery_sha512_compress(outer_state, outer_block);
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        recovery_sha512_store_be64(outer_state[i], out + (i * 8u));
    }
}

static inline void recovery_hmac_sha512_from_precomp(const thread RecoveryHmacSha512Precomp* ctx,
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

static inline void recovery_hmac_sha512_from_precomp_64_words(
    const thread RecoveryHmacSha512Precomp* ctx,
    const thread cmr_u64 data_words[8],
    thread cmr_u64 out_words[8]) {
    thread cmr_u64 inner_block[16] = { 0ull };
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        inner_block[i] = data_words[i];
    }
    inner_block[8] = 0x8000000000000000ull;
    inner_block[15] = 0x0000000000000600ull;

    thread cmr_u64 inner_state[8];
    recovery_sha512_transform_words(ctx->inner_H, inner_state, inner_block);

    thread cmr_u64 outer_block[16] = { 0ull };
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        outer_block[i] = inner_state[i];
    }
    outer_block[8] = 0x8000000000000000ull;
    outer_block[15] = 0x0000000000000600ull;
    recovery_sha512_transform_words(ctx->outer_H, out_words, outer_block);
}

static inline void recovery_hmac_sha512_from_precomp_37(
    const thread cmr_u64 inner_H[8],
    const thread cmr_u64 outer_H[8],
    const thread cmr_u8* data,
    thread cmr_u8 out[64]) {
    thread cmr_u64 inner_block[16] = { 0ull };
    for (cmr_u32 i = 0u; i < 4u; ++i) {
        inner_block[i] = recovery_sha512_load_be64(data, i * 8u);
    }
    inner_block[4] =
        (cmr_u64(data[32]) << 56u) |
        (cmr_u64(data[33]) << 48u) |
        (cmr_u64(data[34]) << 40u) |
        (cmr_u64(data[35]) << 32u) |
        (cmr_u64(data[36]) << 24u) |
        (0x80ull << 16u);
    inner_block[15] = 0x0000000000000528ull;

    thread cmr_u64 inner_state[8];
    recovery_sha512_transform_words(inner_H, inner_state, inner_block);

    thread cmr_u64 outer_block[16] = { 0ull };
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        outer_block[i] = inner_state[i];
    }
    outer_block[8] = 0x8000000000000000ull;
    outer_block[15] = 0x0000000000000600ull;

    thread cmr_u64 outer_state[8];
    recovery_sha512_transform_words(outer_H, outer_state, outer_block);
    for (cmr_u32 i = 0u; i < 8u; ++i) {
        recovery_sha512_store_be64(outer_state[i], out + (i * 8u));
    }
}

static inline void recovery_hmac_sha512_from_precomp_37(
    const thread RecoveryHmacSha512Precomp* ctx,
    const thread cmr_u8* data,
    thread cmr_u8 out[64]) {
    recovery_hmac_sha512_from_precomp_37(ctx->inner_H, ctx->outer_H, data, out);
}

static inline void recovery_hmac_sha512_32_37(const thread cmr_u8 key[32],
                                              const thread cmr_u8* data,
                                              thread cmr_u8 out[64]) {
    thread RecoveryHmacSha512Precomp ctx;
    recovery_hmac_sha512_precompute_32(key, &ctx);
    recovery_hmac_sha512_from_precomp_37(&ctx, data, out);
}

static inline uint recovery_rotl32(const uint x, const uint n) {
    return (x << n) | (x >> (32u - n));
}

static inline cmr_u64 recovery_rotl64(const cmr_u64 x, const cmr_u32 n) {
    return (x << n) | (x >> (64u - n));
}

static inline uint recovery_load_le32(const thread cmr_u8* data, const uint offset) {
    return uint(data[offset + 0u]) |
           (uint(data[offset + 1u]) << 8u) |
           (uint(data[offset + 2u]) << 16u) |
           (uint(data[offset + 3u]) << 24u);
}

static inline cmr_u64 recovery_load_le64(const thread cmr_u8* data, const cmr_u32 offset) {
    return cmr_u64(data[offset + 0u]) |
           (cmr_u64(data[offset + 1u]) << 8u) |
           (cmr_u64(data[offset + 2u]) << 16u) |
           (cmr_u64(data[offset + 3u]) << 24u) |
           (cmr_u64(data[offset + 4u]) << 32u) |
           (cmr_u64(data[offset + 5u]) << 40u) |
           (cmr_u64(data[offset + 6u]) << 48u) |
           (cmr_u64(data[offset + 7u]) << 56u);
}

static inline void recovery_store_le32(const uint value, thread cmr_u8* out) {
    out[0] = cmr_u8(value & 0xFFu);
    out[1] = cmr_u8((value >> 8u) & 0xFFu);
    out[2] = cmr_u8((value >> 16u) & 0xFFu);
    out[3] = cmr_u8((value >> 24u) & 0xFFu);
}

static inline void recovery_store_le64(const cmr_u64 value, thread cmr_u8* out) {
    out[0] = cmr_u8(value & 0xFFu);
    out[1] = cmr_u8((value >> 8u) & 0xFFu);
    out[2] = cmr_u8((value >> 16u) & 0xFFu);
    out[3] = cmr_u8((value >> 24u) & 0xFFu);
    out[4] = cmr_u8((value >> 32u) & 0xFFu);
    out[5] = cmr_u8((value >> 40u) & 0xFFu);
    out[6] = cmr_u8((value >> 48u) & 0xFFu);
    out[7] = cmr_u8((value >> 56u) & 0xFFu);
}

static inline void recovery_ripemd160_initialize(thread uint state[5]) {
    state[0] = 0x67452301u;
    state[1] = 0xEFCDAB89u;
    state[2] = 0x98BADCFEu;
    state[3] = 0x10325476u;
    state[4] = 0xC3D2E1F0u;
}

static inline void recovery_ripemd160_prepare_block32(thread uint words[16], const thread cmr_u8 input[32]) {
    for (uint i = 0u; i < 8u; ++i) {
        words[i] = recovery_load_le32(input, i * 4u);
    }
    words[8] = 0x00000080u;
    words[9] = 0u;
    words[10] = 0u;
    words[11] = 0u;
    words[12] = 0u;
    words[13] = 0u;
    words[14] = 32u * 8u;
    words[15] = 0u;
}

static inline uint recovery_ripemd160_f1(const uint x, const uint y, const uint z) { return x ^ y ^ z; }
static inline uint recovery_ripemd160_f2(const uint x, const uint y, const uint z) { return (x & y) | (~x & z); }
static inline uint recovery_ripemd160_f3(const uint x, const uint y, const uint z) { return (x | ~y) ^ z; }
static inline uint recovery_ripemd160_f4(const uint x, const uint y, const uint z) { return (x & z) | (~z & y); }
static inline uint recovery_ripemd160_f5(const uint x, const uint y, const uint z) { return x ^ (y | ~z); }

#define RECOVERY_RIPEMD_ROUND(a,b,c,d,e,f,x,k,r) do { \
    const uint u = (a) + (f) + (x) + (k); \
    (a) = recovery_rotl32(u, (r)) + (e); \
    (c) = recovery_rotl32((c), 10u); \
} while (0)
#define RECOVERY_R11(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f1((b),(c),(d)),x,0u,r)
#define RECOVERY_R21(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f2((b),(c),(d)),x,0x5A827999u,r)
#define RECOVERY_R31(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f3((b),(c),(d)),x,0x6ED9EBA1u,r)
#define RECOVERY_R41(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f4((b),(c),(d)),x,0x8F1BBCDCu,r)
#define RECOVERY_R51(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f5((b),(c),(d)),x,0xA953FD4Eu,r)
#define RECOVERY_R12(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f5((b),(c),(d)),x,0x50A28BE6u,r)
#define RECOVERY_R22(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f4((b),(c),(d)),x,0x5C4DD124u,r)
#define RECOVERY_R32(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f3((b),(c),(d)),x,0x6D703EF3u,r)
#define RECOVERY_R42(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f2((b),(c),(d)),x,0x7A6D76E9u,r)
#define RECOVERY_R52(a,b,c,d,e,x,r) RECOVERY_RIPEMD_ROUND(a,b,c,d,e,recovery_ripemd160_f1((b),(c),(d)),x,0u,r)

static inline void recovery_ripemd160_transform(thread uint state[5], const thread uint* w) {
    uint a1 = state[0], b1 = state[1], c1 = state[2], d1 = state[3], e1 = state[4];
    uint a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;

    RECOVERY_R11(a1, b1, c1, d1, e1, w[0], 11u); RECOVERY_R12(a2, b2, c2, d2, e2, w[5], 8u);
    RECOVERY_R11(e1, a1, b1, c1, d1, w[1], 14u); RECOVERY_R12(e2, a2, b2, c2, d2, w[14], 9u);
    RECOVERY_R11(d1, e1, a1, b1, c1, w[2], 15u); RECOVERY_R12(d2, e2, a2, b2, c2, w[7], 9u);
    RECOVERY_R11(c1, d1, e1, a1, b1, w[3], 12u); RECOVERY_R12(c2, d2, e2, a2, b2, w[0], 11u);
    RECOVERY_R11(b1, c1, d1, e1, a1, w[4], 5u);  RECOVERY_R12(b2, c2, d2, e2, a2, w[9], 13u);
    RECOVERY_R11(a1, b1, c1, d1, e1, w[5], 8u);  RECOVERY_R12(a2, b2, c2, d2, e2, w[2], 15u);
    RECOVERY_R11(e1, a1, b1, c1, d1, w[6], 7u);  RECOVERY_R12(e2, a2, b2, c2, d2, w[11], 15u);
    RECOVERY_R11(d1, e1, a1, b1, c1, w[7], 9u);  RECOVERY_R12(d2, e2, a2, b2, c2, w[4], 5u);
    RECOVERY_R11(c1, d1, e1, a1, b1, w[8], 11u); RECOVERY_R12(c2, d2, e2, a2, b2, w[13], 7u);
    RECOVERY_R11(b1, c1, d1, e1, a1, w[9], 13u); RECOVERY_R12(b2, c2, d2, e2, a2, w[6], 7u);
    RECOVERY_R11(a1, b1, c1, d1, e1, w[10], 14u); RECOVERY_R12(a2, b2, c2, d2, e2, w[15], 8u);
    RECOVERY_R11(e1, a1, b1, c1, d1, w[11], 15u); RECOVERY_R12(e2, a2, b2, c2, d2, w[8], 11u);
    RECOVERY_R11(d1, e1, a1, b1, c1, w[12], 6u);  RECOVERY_R12(d2, e2, a2, b2, c2, w[1], 14u);
    RECOVERY_R11(c1, d1, e1, a1, b1, w[13], 7u);  RECOVERY_R12(c2, d2, e2, a2, b2, w[10], 14u);
    RECOVERY_R11(b1, c1, d1, e1, a1, w[14], 9u);  RECOVERY_R12(b2, c2, d2, e2, a2, w[3], 12u);
    RECOVERY_R11(a1, b1, c1, d1, e1, w[15], 8u);  RECOVERY_R12(a2, b2, c2, d2, e2, w[12], 6u);

    RECOVERY_R21(e1, a1, b1, c1, d1, w[7], 7u);   RECOVERY_R22(e2, a2, b2, c2, d2, w[6], 9u);
    RECOVERY_R21(d1, e1, a1, b1, c1, w[4], 6u);   RECOVERY_R22(d2, e2, a2, b2, c2, w[11], 13u);
    RECOVERY_R21(c1, d1, e1, a1, b1, w[13], 8u);  RECOVERY_R22(c2, d2, e2, a2, b2, w[3], 15u);
    RECOVERY_R21(b1, c1, d1, e1, a1, w[1], 13u);  RECOVERY_R22(b2, c2, d2, e2, a2, w[7], 7u);
    RECOVERY_R21(a1, b1, c1, d1, e1, w[10], 11u); RECOVERY_R22(a2, b2, c2, d2, e2, w[0], 12u);
    RECOVERY_R21(e1, a1, b1, c1, d1, w[6], 9u);   RECOVERY_R22(e2, a2, b2, c2, d2, w[13], 8u);
    RECOVERY_R21(d1, e1, a1, b1, c1, w[15], 7u);  RECOVERY_R22(d2, e2, a2, b2, c2, w[5], 9u);
    RECOVERY_R21(c1, d1, e1, a1, b1, w[3], 15u);  RECOVERY_R22(c2, d2, e2, a2, b2, w[10], 11u);
    RECOVERY_R21(b1, c1, d1, e1, a1, w[12], 7u);  RECOVERY_R22(b2, c2, d2, e2, a2, w[14], 7u);
    RECOVERY_R21(a1, b1, c1, d1, e1, w[0], 12u);  RECOVERY_R22(a2, b2, c2, d2, e2, w[15], 7u);
    RECOVERY_R21(e1, a1, b1, c1, d1, w[9], 15u);  RECOVERY_R22(e2, a2, b2, c2, d2, w[8], 12u);
    RECOVERY_R21(d1, e1, a1, b1, c1, w[5], 9u);   RECOVERY_R22(d2, e2, a2, b2, c2, w[12], 7u);
    RECOVERY_R21(c1, d1, e1, a1, b1, w[2], 11u);  RECOVERY_R22(c2, d2, e2, a2, b2, w[4], 6u);
    RECOVERY_R21(b1, c1, d1, e1, a1, w[14], 7u);  RECOVERY_R22(b2, c2, d2, e2, a2, w[9], 15u);
    RECOVERY_R21(a1, b1, c1, d1, e1, w[11], 13u); RECOVERY_R22(a2, b2, c2, d2, e2, w[1], 13u);
    RECOVERY_R21(e1, a1, b1, c1, d1, w[8], 12u);  RECOVERY_R22(e2, a2, b2, c2, d2, w[2], 11u);

    RECOVERY_R31(d1, e1, a1, b1, c1, w[3], 11u);  RECOVERY_R32(d2, e2, a2, b2, c2, w[15], 9u);
    RECOVERY_R31(c1, d1, e1, a1, b1, w[10], 13u); RECOVERY_R32(c2, d2, e2, a2, b2, w[5], 7u);
    RECOVERY_R31(b1, c1, d1, e1, a1, w[14], 6u);  RECOVERY_R32(b2, c2, d2, e2, a2, w[1], 15u);
    RECOVERY_R31(a1, b1, c1, d1, e1, w[4], 7u);   RECOVERY_R32(a2, b2, c2, d2, e2, w[3], 11u);
    RECOVERY_R31(e1, a1, b1, c1, d1, w[9], 14u);  RECOVERY_R32(e2, a2, b2, c2, d2, w[7], 8u);
    RECOVERY_R31(d1, e1, a1, b1, c1, w[15], 9u);  RECOVERY_R32(d2, e2, a2, b2, c2, w[14], 6u);
    RECOVERY_R31(c1, d1, e1, a1, b1, w[8], 13u);  RECOVERY_R32(c2, d2, e2, a2, b2, w[6], 6u);
    RECOVERY_R31(b1, c1, d1, e1, a1, w[1], 15u);  RECOVERY_R32(b2, c2, d2, e2, a2, w[9], 14u);
    RECOVERY_R31(a1, b1, c1, d1, e1, w[2], 14u);  RECOVERY_R32(a2, b2, c2, d2, e2, w[11], 12u);
    RECOVERY_R31(e1, a1, b1, c1, d1, w[7], 8u);   RECOVERY_R32(e2, a2, b2, c2, d2, w[8], 13u);
    RECOVERY_R31(d1, e1, a1, b1, c1, w[0], 13u);  RECOVERY_R32(d2, e2, a2, b2, c2, w[12], 5u);
    RECOVERY_R31(c1, d1, e1, a1, b1, w[6], 6u);   RECOVERY_R32(c2, d2, e2, a2, b2, w[2], 14u);
    RECOVERY_R31(b1, c1, d1, e1, a1, w[13], 5u);  RECOVERY_R32(b2, c2, d2, e2, a2, w[10], 13u);
    RECOVERY_R31(a1, b1, c1, d1, e1, w[11], 12u); RECOVERY_R32(a2, b2, c2, d2, e2, w[0], 13u);
    RECOVERY_R31(e1, a1, b1, c1, d1, w[5], 7u);   RECOVERY_R32(e2, a2, b2, c2, d2, w[4], 7u);
    RECOVERY_R31(d1, e1, a1, b1, c1, w[12], 5u);  RECOVERY_R32(d2, e2, a2, b2, c2, w[13], 5u);

    RECOVERY_R41(c1, d1, e1, a1, b1, w[1], 11u);  RECOVERY_R42(c2, d2, e2, a2, b2, w[8], 15u);
    RECOVERY_R41(b1, c1, d1, e1, a1, w[9], 12u);  RECOVERY_R42(b2, c2, d2, e2, a2, w[6], 5u);
    RECOVERY_R41(a1, b1, c1, d1, e1, w[11], 14u); RECOVERY_R42(a2, b2, c2, d2, e2, w[4], 8u);
    RECOVERY_R41(e1, a1, b1, c1, d1, w[10], 15u); RECOVERY_R42(e2, a2, b2, c2, d2, w[1], 11u);
    RECOVERY_R41(d1, e1, a1, b1, c1, w[0], 14u);  RECOVERY_R42(d2, e2, a2, b2, c2, w[3], 14u);
    RECOVERY_R41(c1, d1, e1, a1, b1, w[8], 15u);  RECOVERY_R42(c2, d2, e2, a2, b2, w[11], 14u);
    RECOVERY_R41(b1, c1, d1, e1, a1, w[12], 9u);  RECOVERY_R42(b2, c2, d2, e2, a2, w[15], 6u);
    RECOVERY_R41(a1, b1, c1, d1, e1, w[4], 8u);   RECOVERY_R42(a2, b2, c2, d2, e2, w[0], 14u);
    RECOVERY_R41(e1, a1, b1, c1, d1, w[13], 9u);  RECOVERY_R42(e2, a2, b2, c2, d2, w[5], 6u);
    RECOVERY_R41(d1, e1, a1, b1, c1, w[3], 14u);  RECOVERY_R42(d2, e2, a2, b2, c2, w[12], 9u);
    RECOVERY_R41(c1, d1, e1, a1, b1, w[7], 5u);   RECOVERY_R42(c2, d2, e2, a2, b2, w[2], 12u);
    RECOVERY_R41(b1, c1, d1, e1, a1, w[15], 6u);  RECOVERY_R42(b2, c2, d2, e2, a2, w[13], 9u);
    RECOVERY_R41(a1, b1, c1, d1, e1, w[14], 8u);  RECOVERY_R42(a2, b2, c2, d2, e2, w[9], 12u);
    RECOVERY_R41(e1, a1, b1, c1, d1, w[5], 6u);   RECOVERY_R42(e2, a2, b2, c2, d2, w[7], 5u);
    RECOVERY_R41(d1, e1, a1, b1, c1, w[6], 5u);   RECOVERY_R42(d2, e2, a2, b2, c2, w[10], 15u);
    RECOVERY_R41(c1, d1, e1, a1, b1, w[2], 12u);  RECOVERY_R42(c2, d2, e2, a2, b2, w[14], 8u);

    RECOVERY_R51(b1, c1, d1, e1, a1, w[4], 9u);   RECOVERY_R52(b2, c2, d2, e2, a2, w[12], 8u);
    RECOVERY_R51(a1, b1, c1, d1, e1, w[0], 15u);  RECOVERY_R52(a2, b2, c2, d2, e2, w[15], 5u);
    RECOVERY_R51(e1, a1, b1, c1, d1, w[5], 5u);   RECOVERY_R52(e2, a2, b2, c2, d2, w[10], 12u);
    RECOVERY_R51(d1, e1, a1, b1, c1, w[9], 11u);  RECOVERY_R52(d2, e2, a2, b2, c2, w[4], 9u);
    RECOVERY_R51(c1, d1, e1, a1, b1, w[7], 6u);   RECOVERY_R52(c2, d2, e2, a2, b2, w[1], 12u);
    RECOVERY_R51(b1, c1, d1, e1, a1, w[12], 8u);  RECOVERY_R52(b2, c2, d2, e2, a2, w[5], 5u);
    RECOVERY_R51(a1, b1, c1, d1, e1, w[2], 13u);  RECOVERY_R52(a2, b2, c2, d2, e2, w[8], 14u);
    RECOVERY_R51(e1, a1, b1, c1, d1, w[10], 12u); RECOVERY_R52(e2, a2, b2, c2, d2, w[7], 6u);
    RECOVERY_R51(d1, e1, a1, b1, c1, w[14], 5u);  RECOVERY_R52(d2, e2, a2, b2, c2, w[6], 8u);
    RECOVERY_R51(c1, d1, e1, a1, b1, w[1], 12u);  RECOVERY_R52(c2, d2, e2, a2, b2, w[2], 13u);
    RECOVERY_R51(b1, c1, d1, e1, a1, w[3], 13u);  RECOVERY_R52(b2, c2, d2, e2, a2, w[13], 6u);
    RECOVERY_R51(a1, b1, c1, d1, e1, w[8], 14u);  RECOVERY_R52(a2, b2, c2, d2, e2, w[14], 5u);
    RECOVERY_R51(e1, a1, b1, c1, d1, w[11], 11u); RECOVERY_R52(e2, a2, b2, c2, d2, w[0], 15u);
    RECOVERY_R51(d1, e1, a1, b1, c1, w[6], 8u);   RECOVERY_R52(d2, e2, a2, b2, c2, w[3], 13u);
    RECOVERY_R51(c1, d1, e1, a1, b1, w[15], 5u);  RECOVERY_R52(c2, d2, e2, a2, b2, w[9], 11u);
    RECOVERY_R51(b1, c1, d1, e1, a1, w[13], 6u);  RECOVERY_R52(b2, c2, d2, e2, a2, w[11], 11u);

    const uint t = state[0];
    state[0] = state[1] + c1 + d2;
    state[1] = state[2] + d1 + e2;
    state[2] = state[3] + e1 + a2;
    state[3] = state[4] + a1 + b2;
    state[4] = t + b1 + c2;
}

#undef RECOVERY_R11
#undef RECOVERY_R21
#undef RECOVERY_R31
#undef RECOVERY_R41
#undef RECOVERY_R51
#undef RECOVERY_R12
#undef RECOVERY_R22
#undef RECOVERY_R32
#undef RECOVERY_R42
#undef RECOVERY_R52
#undef RECOVERY_RIPEMD_ROUND

static inline void recovery_ripemd160_digest_32(const thread cmr_u8 input[32], thread cmr_u8 out[20]) {
    uint state[5];
    uint words[16];
    recovery_ripemd160_initialize(state);
    recovery_ripemd160_prepare_block32(words, input);
    recovery_ripemd160_transform(state, words);
    for (uint i = 0u; i < 5u; ++i) {
        recovery_store_le32(state[i], out + (i * 4u));
    }
}

static inline void recovery_hash160_digest(const thread cmr_u8* data, const cmr_u32 len, thread cmr_u8 out[20]) {
    thread cmr_u8 sha[32];
    recovery_sha256_digest(data, len, sha);
    recovery_ripemd160_digest_32(sha, out);
}

static constant cmr_u64 kRecoveryKeccakRoundConstants[24] = {
    0x0000000000000001ull, 0x0000000000008082ull,
    0x800000000000808aull, 0x8000000080008000ull,
    0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008aull, 0x0000000000000088ull,
    0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull,
    0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull,
    0x8000000080008081ull, 0x8000000000008080ull,
    0x0000000080000001ull, 0x8000000080008008ull
};

static constant int kRecoveryKeccakRotationConstants[5][5] = {
    {  0, 36,  3, 41, 18},
    {  1, 44, 10, 45,  2},
    { 62,  6, 43, 15, 61},
    { 28, 55, 25, 21, 56},
    { 27, 20, 39,  8, 14}
};

static inline void recovery_keccak_f1600(thread cmr_u64 state[25]) {
    for (int round = 0; round < 24; ++round) {
        cmr_u64 c[5];
        for (int x = 0; x < 5; ++x) {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            const cmr_u64 d = c[(x + 4) % 5] ^ recovery_rotl64(c[(x + 1) % 5], 1u);
            for (int y = 0; y < 25; y += 5) {
                state[y + x] ^= d;
            }
        }

        cmr_u64 b[25];
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                const int idx = y * 5 + x;
                const int r = kRecoveryKeccakRotationConstants[x][y];
                const int new_x = y;
                const int new_y = (2 * x + 3 * y) % 5;
                b[new_y * 5 + new_x] = recovery_rotl64(state[idx], cmr_u32(r));
            }
        }

        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                state[y * 5 + x] = b[y * 5 + x] ^
                    ((~b[y * 5 + ((x + 1) % 5)]) & b[y * 5 + ((x + 2) % 5)]);
            }
        }

        state[0] ^= kRecoveryKeccakRoundConstants[round];
    }
}

static inline void recovery_keccak256_digest(const thread cmr_u8* data, const cmr_u32 len, thread cmr_u8 out[32]) {
    thread cmr_u64 state[25];
    for (cmr_u32 i = 0u; i < 25u; ++i) {
        state[i] = 0ull;
    }

    // Current secp/ETH path only needs a single absorb block.
    thread cmr_u8 block[136];
    recovery_zero_thread_bytes(block, 136u);
    recovery_copy_thread_bytes(block, data, len);
    block[len] = 0x01u;
    block[135] |= 0x80u;

    for (cmr_u32 i = 0u; i < 17u; ++i) {
        state[i] ^= recovery_load_le64(block, i * 8u);
    }

    recovery_keccak_f1600(state);
    for (cmr_u32 i = 0u; i < 4u; ++i) {
        recovery_store_le64(state[i], out + (i * 8u));
    }
}
