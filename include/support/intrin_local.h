#pragma once

#include <stdint.h>
#include <stdlib.h>


#ifdef _MSC_VER
#include <intrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#else

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif
//------------------------------------------------------------

static inline unsigned char _addcarry_u64(unsigned char c, uint64_t a, uint64_t b, uint64_t* sum) {
    uint64_t temp = a + b;
    unsigned char carry1 = (temp < a) ? 1 : 0;
    uint64_t result = temp + c;
    unsigned char carry2 = (result < temp) ? 1 : 0;
    *sum = result;
    return (carry1 || carry2) ? 1 : 0;
}

// _subborrow_u64: performs subborrow u64.
static inline unsigned char _subborrow_u64(unsigned char borrow, uint64_t a, uint64_t b, uint64_t* diff) {
    uint64_t temp = a - b;
    unsigned char borrow1 = (a < b) ? 1 : 0;
    uint64_t result = temp - borrow;
    unsigned char borrow2 = (temp < borrow) ? 1 : 0;
    *diff = result;
    return (borrow1 || borrow2) ? 1 : 0;
}


// _umul128: performs umul 128.
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* high) {
#ifdef __SIZEOF_INT128__
    unsigned __int128 r = (unsigned __int128)a * b;
    *high = (uint64_t)(r >> 64);
    return (uint64_t)r;
#else
    const uint64_t a_lo = a & 0xFFFFFFFFULL;
    const uint64_t a_hi = a >> 32;
    const uint64_t b_lo = b & 0xFFFFFFFFULL;
    const uint64_t b_hi = b >> 32;

    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;

    uint64_t middle = p1 + p2;
    uint64_t carry = (middle < p1) ? (1ULL << 32) : 0ULL;
    uint64_t middle_low = middle << 32;
    uint64_t low = p0 + middle_low;
    uint64_t carry2 = (low < p0) ? 1ULL : 0ULL;
    *high = p3 + (middle >> 32) + carry + carry2;
    return low;
#endif
}

// __shiftright128: performs shiftright 128.
static inline uint64_t __shiftright128(uint64_t low, uint64_t high, uint8_t shift) {
    if (shift == 0)
        return low;
    else if (shift < 64)
        return (low >> shift) | (high << (64 - shift));
    else if (shift < 128)
        return high >> (shift - 64);
    else
        return 0;
}

// __shiftleft128: performs shiftleft 128.
static inline uint64_t __shiftleft128(uint64_t low, uint64_t high, uint8_t shift) {
    if (shift == 0)
        return high;
    else if (shift < 64)
        return (high << shift) | (low >> (64 - shift));
    else if (shift < 128)
        return low << (shift - 64);
    else
        return 0;
}

// _tzcnt_u64: performs tzcnt u64.
static inline uint64_t _tzcnt_u64(uint64_t x) {
    return x ? __builtin_ctzll(x) : 64;
}

// _lzcnt_u64: performs lzcnt u64.
static inline uint64_t _lzcnt_u64(uint64_t x) {
    return x ? __builtin_clzll(x) : 64;
}

// _bzhi_u64: performs bzhi u64.
static inline uint64_t _bzhi_u64(uint64_t x, uint32_t n) {
    if (n >= 64)
        return x;
    return x & ((1ULL << n) - 1);
}

// _udiv64: performs udiv 64.
static inline uint32_t _udiv64(uint64_t a, uint32_t b, uint32_t* remainder) {
    *remainder = (uint32_t)(a % b);
    return (uint32_t)(a / b);
}

// _udiv128: performs udiv 128.
static inline uint64_t _udiv128(uint64_t nHi, uint64_t nLo, uint64_t d, uint64_t* rem) {
    uint64_t quotient = 0;
    uint64_t r = nHi;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((nLo >> i) & 1ULL);
        if (r >= d) {
            r -= d;
            quotient |= (1ULL << i);
        }
    }
    *rem = r;
    return quotient;
}


typedef union {
    float f[4];
} __m128;

typedef union {
    int i[4];
    int32_t i32[4];
    int64_t ll[2];
    uint32_t u32[4];
    uint64_t ull[2];
} __m128i;

typedef union {
    double d[2];
    int64_t ll[2];
} __m128d;

// _mm_set_ss: sets ss for mm.
static inline __m128 _mm_set_ss(float x) {
    __m128 r;
    r.f[0] = x;
    r.f[1] = 0.0f;
    r.f[2] = 0.0f;
    r.f[3] = 0.0f;
    return r;
}

// _mm_castps_si128: performs mm castps si 128.
static inline __m128i _mm_castps_si128(__m128 a) {
    __m128i r;
    r.i[0] = *(int*)&a.f[0];
    r.i[1] = *(int*)&a.f[1];
    r.i[2] = *(int*)&a.f[2];
    r.i[3] = *(int*)&a.f[3];
    return r;
}

// _mm_cvtsi64_si128: performs mm cvtsi 64 si 128.
static inline __m128i _mm_cvtsi64_si128(int64_t a) {
    __m128i r;
    r.ll[0] = a;
    r.ll[1] = 0;
    return r;
}

// _mm_cvtsi128_si32: performs mm cvtsi 128 si 32.
static inline int _mm_cvtsi128_si32(__m128i a) {
    return a.i[0];
}

// _mm_set_sd: sets sd for mm.
static inline __m128d _mm_set_sd(double a) {
    __m128d r;
    r.d[0] = a;
    r.d[1] = 0.0;
    return r;
}

// _mm_castpd_si128: performs mm castpd si 128.
static inline __m128i _mm_castpd_si128(__m128d a) {
    __m128i r;
    r.ll[0] = *((const int64_t*)&a.d[0]);
    r.ll[1] = *((const int64_t*)&a.d[1]);
    return r;
}

// _mm_cvtsi128_si64: performs mm cvtsi 128 si 64.
static inline int64_t _mm_cvtsi128_si64(__m128i a) {
    return a.ll[0];
}

// _mm_cvtsi32_si128: performs mm cvtsi 32 si 128.
static inline __m128i _mm_cvtsi32_si128(int a) {
    __m128i r;
    r.i[0] = a;
    r.i[1] = 0;
    r.i[2] = 0;
    r.i[3] = 0;
    return r;
}

// _mm_castsi128_ps: performs mm castsi 128 ps.
static inline __m128 _mm_castsi128_ps(__m128i a) {
    __m128 r;
    r.f[0] = *(float*)&a.i[0];
    r.f[1] = *(float*)&a.i[1];
    r.f[2] = *(float*)&a.i[2];
    r.f[3] = *(float*)&a.i[3];
    return r;
}

// _mm_cvtss_f32: performs mm cvtss f 32.
static inline float _mm_cvtss_f32(__m128 a) {
    return a.f[0];
}

// _mm_castsi128_pd: performs mm castsi 128 pd.
static inline __m128d _mm_castsi128_pd(__m128i a) {
    __m128d r;
    r.ll[0] = a.ll[0];
    r.ll[1] = a.ll[1];
    return r;
}


// _mm_cvtsd_f64: performs mm cvtsd f 64.
static inline double _mm_cvtsd_f64(__m128d a) {
    return a.d[0];
}

#endif  // _MSC_VER
