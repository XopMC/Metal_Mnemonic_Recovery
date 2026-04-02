#pragma once

#include "metal/RecoveryMetalTypes.h"

#if !defined(__METAL_VERSION__)
#include <chrono>
#include <cstddef>
#include <cstdint>
#endif

#define REC_HOST
#define REC_DEVICE

#if defined(__METAL_VERSION__)
#define REC_KERNEL kernel
#define REC_CONSTANT constant
#define REC_SHARED threadgroup
#else
#define REC_KERNEL
#define REC_CONSTANT const
#define REC_SHARED
#endif

#define REC_FORCEINLINE inline
#define REC_NOINLINE
#define REC_ALIGN(N) __attribute__((aligned(N)))

#ifndef NULL
#define NULL nullptr
#endif

#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffu
#endif

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

struct dim3 {
    unsigned int x;
    unsigned int y;
    unsigned int z;
    constexpr dim3(unsigned int vx = 1u, unsigned int vy = 1u, unsigned int vz = 1u)
        : x(vx), y(vy), z(vz) {}
};

#if defined(__METAL_VERSION__)
#define threadIdx dim3()
#define blockIdx dim3()
#define blockDim dim3()
#define gridDim dim3()

template <typename T>
inline T __ldg(const device T* ptr) {
    return *ptr;
}

template <typename T>
inline T __ldg(const constant T* ptr) {
    return *ptr;
}

template <typename T>
inline T __ldg(const thread T* ptr) {
    return *ptr;
}

inline cmr_u64 __umul64hi(const cmr_u64 a, const cmr_u64 b) {
    return static_cast<cmr_u64>((static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b)) >> 64);
}

inline int __ffsll(const long value) {
    if (value == 0l) {
        return 0;
    }
    return __builtin_ctzl(static_cast<ulong>(value)) + 1;
}

inline cmr_u32 __brev(const cmr_u32 value) {
    cmr_u32 v = value;
    v = ((v & 0x55555555u) << 1) | ((v >> 1) & 0x55555555u);
    v = ((v & 0x33333333u) << 2) | ((v >> 2) & 0x33333333u);
    v = ((v & 0x0f0f0f0fu) << 4) | ((v >> 4) & 0x0f0f0f0fu);
    v = (v << 24) | ((v & 0x0000ff00u) << 8) | ((v >> 8) & 0x0000ff00u) | (v >> 24);
    return v;
}

inline int __clz(const cmr_u32 value) {
    return value == 0u ? 32 : __builtin_clz(value);
}

inline int __clzll(const cmr_u64 value) {
    return value == 0ull ? 64 : __builtin_clzll(value);
}

inline cmr_u32 __byte_perm(const cmr_u32 x, const cmr_u32 y, const cmr_u32 s) {
    const cmr_u8 bytes[8] = {
        static_cast<cmr_u8>(x & 0xffu),
        static_cast<cmr_u8>((x >> 8) & 0xffu),
        static_cast<cmr_u8>((x >> 16) & 0xffu),
        static_cast<cmr_u8>((x >> 24) & 0xffu),
        static_cast<cmr_u8>(y & 0xffu),
        static_cast<cmr_u8>((y >> 8) & 0xffu),
        static_cast<cmr_u8>((y >> 16) & 0xffu),
        static_cast<cmr_u8>((y >> 24) & 0xffu),
    };

    cmr_u32 out = 0u;
    for (int i = 0; i < 4; ++i) {
        const cmr_u32 sel = (s >> (i * 4)) & 0x0fu;
        const cmr_u8 value = sel < 8u ? bytes[sel] : 0u;
        out |= static_cast<cmr_u32>(value) << (i * 8);
    }
    return out;
}

inline cmr_u64 clock64() {
    return 0ull;
}
#else
static constexpr dim3 threadIdx{};
static constexpr dim3 blockIdx{};
static constexpr dim3 blockDim{};
static constexpr dim3 gridDim{};

template <typename T>
inline T __ldg(const T* ptr) {
    return *ptr;
}

inline cmr_u64 __umul64hi(const cmr_u64 a, const cmr_u64 b) {
    return static_cast<cmr_u64>((static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b)) >> 64);
}

inline int __ffsll(const long long value) {
    if (value == 0ll) {
        return 0;
    }
    return __builtin_ctzll(static_cast<unsigned long long>(value)) + 1;
}

inline cmr_u32 __brev(const cmr_u32 value) {
    cmr_u32 v = value;
    v = ((v & 0x55555555u) << 1) | ((v >> 1) & 0x55555555u);
    v = ((v & 0x33333333u) << 2) | ((v >> 2) & 0x33333333u);
    v = ((v & 0x0f0f0f0fu) << 4) | ((v >> 4) & 0x0f0f0f0fu);
    v = (v << 24) | ((v & 0x0000ff00u) << 8) | ((v >> 8) & 0x0000ff00u) | (v >> 24);
    return v;
}

inline int __clz(const cmr_u32 value) {
    return value == 0u ? 32 : __builtin_clz(value);
}

inline int __clzll(const cmr_u64 value) {
    return value == 0ull ? 64 : __builtin_clzll(value);
}

inline cmr_u32 __byte_perm(const cmr_u32 x, const cmr_u32 y, const cmr_u32 s) {
    const cmr_u8 bytes[8] = {
        static_cast<cmr_u8>(x & 0xffu),
        static_cast<cmr_u8>((x >> 8) & 0xffu),
        static_cast<cmr_u8>((x >> 16) & 0xffu),
        static_cast<cmr_u8>((x >> 24) & 0xffu),
        static_cast<cmr_u8>(y & 0xffu),
        static_cast<cmr_u8>((y >> 8) & 0xffu),
        static_cast<cmr_u8>((y >> 16) & 0xffu),
        static_cast<cmr_u8>((y >> 24) & 0xffu),
    };

    cmr_u32 out = 0u;
    for (int i = 0; i < 4; ++i) {
        const cmr_u32 sel = (s >> (i * 4)) & 0x0fu;
        const cmr_u8 value = sel < 8u ? bytes[sel] : 0u;
        out |= static_cast<cmr_u32>(value) << (i * 8);
    }
    return out;
}

inline cmr_u64 clock64() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<cmr_u64>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}
#endif
