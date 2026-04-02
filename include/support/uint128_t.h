

#pragma once

#ifndef UINT128_T_H
#define UINT128_T_H

#include <cstdint>
#include "support/intrin_local.h"
#include "metal/RecoveryDeviceSupport.h"
#include <iosfwd>
#include <iostream>


#define MAKE_BINARY_OP_HELPERS(op) \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, uint8_t   y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, uint16_t  y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, uint32_t  y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, uint64_t  y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, int8_t   y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, int16_t  y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, int32_t  y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, int64_t  y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, char y) { return operator op(x, (uint128_t)y); }  \
friend REC_DEVICE REC_HOST auto operator op(uint8_t   x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(uint16_t  x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(uint32_t  x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(uint64_t  x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(int8_t   x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(int16_t  x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(int32_t  x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(int64_t  x, const uint128_t& y) { return operator op((uint128_t)x, y); }  \
friend REC_DEVICE REC_HOST auto operator op(char x, const uint128_t& y) { return operator op((uint128_t)x, y); }

#define MAKE_BINARY_OP_HELPERS_FLOAT(op) \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, float  y) { return (float)x op y; }   \
friend REC_DEVICE REC_HOST auto operator op(const uint128_t& x, double y) { return (double)x op y; }  \
friend REC_DEVICE REC_HOST auto operator op(float  x, const uint128_t& y) { return x op (float)y; }    \
friend REC_DEVICE REC_HOST auto operator op(double x, const uint128_t& y) { return x op (double)y; }

#define MAKE_BINARY_OP_HELPERS_uint64_t(op) \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, uint8_t  n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, uint16_t n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, uint32_t n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, int8_t  n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, int16_t n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, int32_t n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, int64_t n) { return operator op(x, (uint64_t)n); }    \
friend REC_DEVICE REC_HOST uint128_t operator op(const uint128_t& x, const uint128_t& n) { return operator op(x, (uint64_t)n); }

class uint128_t
{
public:

    uint64_t m_lo;
    uint64_t m_hi;
    friend REC_HOST uint128_t DivMod(uint128_t n, uint128_t d, uint128_t& rem);

    REC_DEVICE REC_HOST uint128_t() = default;
// Device helper: m_hi.
    REC_DEVICE REC_HOST uint128_t(uint8_t    x) : m_lo(x), m_hi(0) {}
// Device helper: m_hi.
    REC_DEVICE REC_HOST uint128_t(uint16_t   x) : m_lo(x), m_hi(0) {}
// Device helper: m_hi.
    REC_DEVICE REC_HOST uint128_t(uint32_t   x) : m_lo(x), m_hi(0) {}
// Device helper: m_hi.
    REC_DEVICE REC_HOST uint128_t(uint64_t   x) : m_lo(x), m_hi(0) {}
// Device helper: int64_t.
    REC_DEVICE REC_HOST uint128_t(int8_t    x) : m_lo(int64_t(x)), m_hi(int64_t(x) >> 63) {}
// Device helper: int64_t.
    REC_DEVICE REC_HOST uint128_t(int16_t   x) : m_lo(int64_t(x)), m_hi(int64_t(x) >> 63) {}
// Device helper: int64_t.
    REC_DEVICE REC_HOST uint128_t(int32_t   x) : m_lo(int64_t(x)), m_hi(int64_t(x) >> 63) {}
// Device helper: int64_t.
    REC_DEVICE REC_HOST uint128_t(int64_t   x) : m_lo(int64_t(x)), m_hi(int64_t(x) >> 63) {}
// Device helper: m_hi.
    REC_DEVICE REC_HOST uint128_t(uint64_t hi, uint64_t lo) : m_lo(lo), m_hi(hi) {}
// Device helper: __shiftleft128.
    REC_DEVICE REC_HOST static uint64_t __shiftleft128(uint64_t lo, uint64_t hi, uint8_t n) {
        if (n >= 64) {
            return hi << (n - 64);
        }
        else {
            return (hi << n) | (lo >> (64 - n));
        }
    }

// Device helper: __shiftright128.
    REC_DEVICE REC_HOST static uint64_t __shiftright128(uint64_t lo, uint64_t hi, uint8_t n) {
        if (n >= 64) {
            return lo >> (n - 64);
        }
        else {
            return (hi << (64 - n)) | (lo >> n);
        }
    }

// Device helper: _subborrow_u64.
    REC_DEVICE REC_HOST static unsigned char _subborrow_u64(unsigned char c, uint64_t a, uint64_t b, uint64_t* res) {
        uint64_t sub = a - b - c;
        *res = sub;
        return (sub > a) ? 1 : 0; // �������� �� �������
    }

// Device helper: _udiv64.
    REC_DEVICE REC_HOST static uint64_t _udiv64(uint64_t n, uint64_t d) {
        return n / d; // ���������� ���������� �������
    }

// Device helper: _udiv128.
    REC_DEVICE REC_HOST static uint64_t _udiv128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t* rem) {
        uint128_t num = { hi, lo };
        uint128_t den = { 0, d };
        uint128_t quotient = num / den;
        *rem = num % den;
        return quotient.m_lo; // ������������, ��� ��������� � ��� ������� 64 ����
    }


    // inexact values truncate, as per the Standard [conv.fpint]
    // passing values unrepresentable in the destination format is undefined behavior,
    // as per the Standard, but this implementation saturates
     REC_HOST uint128_t(float x);

    // inexact values truncate, as per the Standard [conv.fpint]
    // passing values unrepresentable in the destination format is undefined behavior,
    // as per the Standard, but this implementation saturates
    REC_HOST uint128_t(double x);

    REC_DEVICE REC_HOST static __inline__ unsigned char addcarry_u64(
        unsigned char Carry,
        uint64_t Source1,
        uint64_t Source2,
        uint64_t* Destination)
    {
        uint64_t Sum = (Carry != 0) + Source1 + Source2;
        uint64_t CarryVector = (Source1 & Source2) ^ ((Source1 ^ Source2) & ~Sum);
        *Destination = Sum;
        return (unsigned char)(CarryVector >> 63);
    }

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator+=(const uint128_t& x)
    {
        static_cast<void>(addcarry_u64(addcarry_u64(0, m_lo, x.m_lo, &m_lo), m_hi, x.m_hi, &m_hi));
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator+(const uint128_t& x, const uint128_t& y)
    {
        uint128_t ret;
        static_cast<void>(addcarry_u64(addcarry_u64(0, x.m_lo, y.m_lo, &ret.m_lo), x.m_hi, y.m_hi, &ret.m_hi));
        return ret;
    }

    MAKE_BINARY_OP_HELPERS(+);
    MAKE_BINARY_OP_HELPERS_FLOAT(+);

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator-=(const uint128_t& x)
    {
        static_cast<void>(_subborrow_u64(_subborrow_u64(0, m_lo, x.m_lo, &m_lo), m_hi, x.m_hi, &m_hi));
        return *this;
    }

// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator-(const uint128_t& x, const uint128_t& y)
    {
        uint128_t ret;
        static_cast<void>(_subborrow_u64(_subborrow_u64(0, x.m_lo, y.m_lo, &ret.m_lo), x.m_hi, y.m_hi, &ret.m_hi));
        return ret;
    }

    MAKE_BINARY_OP_HELPERS(-);
    MAKE_BINARY_OP_HELPERS_FLOAT(-);
// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator*=(const uint128_t& x)
    {
        // ab * cd
        // ==
        // (2^64*a + b) * (2^64*c + d)
        // if a*c == e, a*d == f, b*c == g, b*d == h
        // |ee|ee|  |  |
        // |  |fg|fg|  |
        // |  |  |hh|hh|
        uint64_t hHi;
        const uint64_t hLo = _umul128(m_lo, x.m_lo, &hHi);
        m_hi = hHi + m_hi * x.m_lo + m_lo * x.m_hi;
        m_lo = hLo;
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator*(const uint128_t& x, const uint128_t& y)
    {
        uint128_t ret;
        uint64_t hHi;
        ret.m_lo = _umul128(x.m_lo, y.m_lo, &hHi);
        ret.m_hi = hHi + y.m_hi * x.m_lo + y.m_lo * x.m_hi;
        return ret;
    }

    MAKE_BINARY_OP_HELPERS(*);
    MAKE_BINARY_OP_HELPERS_FLOAT(*);

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator/=(const uint128_t& x)
    {
        uint128_t rem;
        *this = DivMod(*this, x, rem);
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator/(const uint128_t& x, const uint128_t& y)
    {
        uint128_t rem;
        return DivMod(x, y, rem);
    }

    MAKE_BINARY_OP_HELPERS(/ );
    MAKE_BINARY_OP_HELPERS_FLOAT(/ );

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator%=(const uint128_t& x)
    {
        static_cast<void>(DivMod(*this, x, *this));
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator%(const uint128_t& x, const uint128_t& y)
    {
        uint128_t ret;
        static_cast<void>(DivMod(x, y, ret));
        return ret;
    }

    MAKE_BINARY_OP_HELPERS(%);

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator&=(const uint128_t& x)
    {
        m_hi &= x.m_hi;
        m_lo &= x.m_lo;
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator&(const uint128_t& x, const uint128_t& y)
    {
        return uint128_t(x.m_hi & y.m_hi, x.m_lo & y.m_lo);
    }

    MAKE_BINARY_OP_HELPERS(&);

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator|=(const uint128_t& x)
    {
        m_hi |= x.m_hi;
        m_lo |= x.m_lo;
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator|(const uint128_t& x, const uint128_t& y)
    {
        return uint128_t(x.m_hi | y.m_hi, x.m_lo | y.m_lo);
    }

    MAKE_BINARY_OP_HELPERS(| );

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator^=(const uint128_t& x)
    {
        m_hi ^= x.m_hi;
        m_lo ^= x.m_lo;
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator^(const uint128_t& x, const uint128_t& y)
    {
        return uint128_t(x.m_hi ^ y.m_hi, x.m_lo ^ y.m_lo);
    }

    MAKE_BINARY_OP_HELPERS(^);

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator>>=(uint64_t n)
    {
        const uint64_t lo = __shiftright128(m_lo, m_hi, (uint8_t)n);
        const uint64_t hi = m_hi >> (n & 63ULL);

        m_lo = n & 64 ? hi : lo;
        m_hi = n & 64 ? 0 : hi;

        return *this;
    }

// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator>>(const uint128_t& x, uint64_t n)
    {
        uint128_t ret;

        const uint64_t lo = __shiftright128(x.m_lo, x.m_hi, (uint8_t)n);
        const uint64_t hi = x.m_hi >> (n & 63ULL);

        ret.m_lo = n & 64 ? hi : lo;
        ret.m_hi = n & 64 ? 0 : hi;

        return ret;
    }

    MAKE_BINARY_OP_HELPERS_uint64_t(>> );

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator<<=(uint64_t n)
    {
        const uint64_t hi = __shiftleft128(m_lo, m_hi, (uint8_t)n);
        const uint64_t lo = m_lo << (n & 63ULL);

        m_hi = n & 64 ? lo : hi;
        m_lo = n & 64 ? 0 : lo;

        return *this;
    }

// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator<<(const uint128_t& x, uint64_t n)
    {
        uint128_t ret;

        const uint64_t hi = __shiftleft128(x.m_lo, x.m_hi, (uint8_t)n);
        const uint64_t lo = x.m_lo << (n & 63ULL);

        ret.m_hi = n & 64 ? lo : hi;
        ret.m_lo = n & 64 ? 0 : lo;

        return ret;
    }

    MAKE_BINARY_OP_HELPERS_uint64_t(<< );

// Device helper: operator~.
    friend REC_DEVICE REC_HOST uint128_t operator~(const uint128_t& x)
    {
        return uint128_t(~x.m_hi, ~x.m_lo);
    }
// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator+(const uint128_t& x)
    {
        return x;
    }

// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST uint128_t operator-(const uint128_t& x)
    {
        uint128_t ret;
        static_cast<void>(_subborrow_u64(_subborrow_u64(0, 0, x.m_lo, &ret.m_lo), 0, x.m_hi, &ret.m_hi));
        return ret;
    }
// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator++()
    {
        operator+=(1);
        return *this;
    }
// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t operator++(int)
    {
        const uint128_t x = *this;
        operator++();
        return x;
    }

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t& operator--()
    {
        operator-=(1);
        return *this;
    }

// Device helper for internal arithmetic or hashing operations.
    REC_DEVICE REC_HOST uint128_t operator--(int)
    {
        const uint128_t x = *this;
        operator--();
        return x;
    }

// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST bool operator<(const uint128_t& x, const uint128_t& y)
    {
        uint64_t unusedLo, unusedHi;
        return _subborrow_u64(_subborrow_u64(0, x.m_lo, y.m_lo, &unusedLo), x.m_hi, y.m_hi, &unusedHi);
    }
    MAKE_BINARY_OP_HELPERS(< );
    MAKE_BINARY_OP_HELPERS_FLOAT(< );

    friend REC_DEVICE REC_HOST bool operator>(const uint128_t& x, const uint128_t& y) { return y < x; }
    MAKE_BINARY_OP_HELPERS(> );
    MAKE_BINARY_OP_HELPERS_FLOAT(> );

    friend REC_DEVICE REC_HOST bool operator<=(const uint128_t& x, const uint128_t& y) { return !(x > y); }
    MAKE_BINARY_OP_HELPERS(<= );
    MAKE_BINARY_OP_HELPERS_FLOAT(<= );

    friend REC_DEVICE REC_HOST bool operator>=(const uint128_t& x, const uint128_t& y) { return !(x < y); }
    MAKE_BINARY_OP_HELPERS(>= );
    MAKE_BINARY_OP_HELPERS_FLOAT(>= );

// Device helper for internal arithmetic or hashing operations.
    friend REC_DEVICE REC_HOST bool operator==(const uint128_t& x, const uint128_t& y)
    {
        return !((x.m_hi ^ y.m_hi) | (x.m_lo ^ y.m_lo));
    }
    MAKE_BINARY_OP_HELPERS(== );
    MAKE_BINARY_OP_HELPERS_FLOAT(== );

    friend REC_DEVICE REC_HOST bool operator!=(const uint128_t& x, const uint128_t& y) { return !(x == y); }
    MAKE_BINARY_OP_HELPERS(!= );
    MAKE_BINARY_OP_HELPERS_FLOAT(!= );

    REC_DEVICE REC_HOST explicit operator bool() const { return m_hi | m_lo; }

    REC_DEVICE REC_HOST operator uint8_t () const { return (uint8_t)m_lo; }
    REC_DEVICE REC_HOST operator uint16_t() const { return (uint16_t)m_lo; }
    REC_DEVICE REC_HOST operator uint32_t() const { return (uint32_t)m_lo; }
    REC_DEVICE REC_HOST operator uint64_t() const { return (uint64_t)m_lo; }

    REC_DEVICE REC_HOST operator int8_t () const { return (int8_t)m_lo; }
    REC_DEVICE REC_HOST operator int16_t() const { return (int16_t)m_lo; }
    REC_DEVICE REC_HOST operator int32_t() const { return (int32_t)m_lo; }
    REC_DEVICE REC_HOST operator int64_t() const { return (int64_t)m_lo; }

    REC_DEVICE REC_HOST operator char() const { return (char)m_lo; }

    // rounding method is implementation-defined as per the Standard [conv.fpint]
    // this implementation performs IEEE 754-compliant "round half to even" rounding to nearest,
    // regardless of the current FPU rounding mode, which matches the behavior of clang and GCC
    REC_DEVICE REC_HOST operator float() const;

    // rounding method is implementation-defined as per the Standard [conv.fpint]
    // this implementation performs IEEE 754-compliant "round half to even" rounding to nearest,
    // regardless of the current FPU rounding mode, which matches the behavior of clang and GCC
    REC_DEVICE REC_HOST operator double() const;

    // caller is responsible for ensuring that buf has space for the uint128_t AND the null terminator
    // that follows, in the given output base.
    // Common bases and worst-case size requirements:
    // Base  2: 129 bytes (128 + null terminator)
    // Base  8:  44 bytes ( 43 + null terminator)
    // Base 10:  40 bytes ( 39 + null terminator)
    // Base 16:  33 bytes ( 32 + null terminator)
    REC_DEVICE REC_HOST void ToString(char* buf, uint64_t base = 10) const;

};

#undef MAKE_BINARY_OP_HELPERS
#undef MAKE_BINARY_OP_HELPERS_FLOAT
#undef MAKE_BINARY_OP_HELPERS_uint64_t

REC_HOST std::ostream& operator<<(std::ostream& os, const uint128_t& x);


// Device helper: FitsHardwareDivL.
REC_DEVICE REC_HOST static __inline__ bool FitsHardwareDivL(uint64_t nHi, uint64_t nLo, uint64_t d)
{
    return !(nHi | (d >> 32)) && nLo < (d << 32);
}


// Device helper: IsPow2.
REC_DEVICE REC_HOST static __inline__ bool IsPow2(uint64_t hi, uint64_t lo)
{
    const uint64_t T = hi | lo;
    return !((hi & lo) | (T & (T - 1)));
}
// Host helper: HardwareDivL.
REC_HOST static __inline__ uint64_t HardwareDivL(uint64_t n, uint64_t d, uint64_t& rem)
{
    uint32_t rLo;
    const uint32_t qLo = _udiv64(n, uint32_t(d), &rLo);
    rem = rLo;
    return qLo;
}

// Host helper: HardwareDivQ.
REC_HOST static __inline__ uint64_t HardwareDivQ(uint64_t nHi, uint64_t nLo, uint64_t d, uint64_t& rem)
{
    nLo = _udiv128(nHi, nLo, d, &nHi);
    rem = nHi;
    return nLo;
}

// Host helper: CountTrailingZeros.
REC_HOST static __inline__ uint64_t CountTrailingZeros(uint64_t hi, uint64_t lo)
{
    const uint64_t nLo = _tzcnt_u64(lo);
    const uint64_t nHi = 64ULL + _tzcnt_u64(hi);
    return lo ? nLo : nHi;
}

// Host helper: CountLeadingZeros.
REC_HOST static __inline__ uint64_t CountLeadingZeros(uint64_t hi, uint64_t lo)
{
    const uint64_t nLo = 64ULL + _lzcnt_u64(lo);
    const uint64_t nHi = _lzcnt_u64(hi);
    return hi ? nHi : nLo;
}

// Host helper: MaskBitsBelow.
REC_HOST static __inline__ uint128_t MaskBitsBelow(uint64_t hi, uint64_t lo, uint64_t n)
{
    return uint128_t(_bzhi_u64(hi, uint32_t(n < 64 ? 0 : n - 64)), _bzhi_u64(lo, uint32_t(n)));
}


// Device helper: DivMod.
REC_DEVICE REC_HOST __inline__ uint128_t DivMod(uint128_t N, uint128_t D, uint128_t& rem)
{
    if (D > N)
    {
        rem = N;
        return 0;
    }

    uint64_t nHi = N.m_hi;
    uint64_t nLo = N.m_lo;
    uint64_t dHi = D.m_hi;
    uint64_t dLo = D.m_lo;
    if (IsPow2(dHi, dLo))
    {
        const uint64_t n = CountTrailingZeros(dHi, dLo);
        rem = MaskBitsBelow(nHi, nLo, n);
        return N >> n;
    }

    if (!dHi)
    {
        if (nHi < dLo)
        {
            uint64_t remLo;
            uint64_t Q;
            if (FitsHardwareDivL(nHi, nLo, dLo))
                Q = HardwareDivL(nLo, dLo, remLo);
            else
                Q = HardwareDivQ(nHi, nLo, dLo, remLo);
            rem = remLo;
            return Q;
        }

        uint64_t remLo;
        const uint64_t qHi = HardwareDivQ(0, nHi, dLo, remLo);
        const uint64_t qLo = HardwareDivQ(remLo, nLo, dLo, remLo);
        rem = remLo;
        return uint128_t(qHi, qLo);
    }

    uint64_t n = _lzcnt_u64(dHi) - _lzcnt_u64(nHi);

    dHi = __shiftleft128(dLo, dHi, uint8_t(n));
    dLo <<= n;

    uint64_t Q = 0;
    ++n;

    do
    {
        uint64_t tLo, tHi;
        unsigned char carry = _subborrow_u64(_subborrow_u64(0, nLo, dLo, &tLo), nHi, dHi, &tHi);
        nLo = !carry ? tLo : nLo;
        nHi = !carry ? tHi : nHi;
        Q = (Q << 1) + !carry;
        dLo = __shiftright128(dLo, dHi, 1);
        dHi >>= 1;
    } while (--n);

    rem = uint128_t(nHi, nLo);
    return Q;
}









//REC_HOST void uint128_t::ToString(char* buf, uint64_t base/* = 10*/) const
//{
//    uint64_t i = 0;
//    if (base >= 2 && base <= 36)
//    {
//        uint128_t n = *this;
//        uint128_t r, b = base;
//        do
//        {
//            n = DivMod(n, b, r);
//            const char c(r);
//            buf[i++] = c + (c >= 10 ? '7' : '0');
//        } while (n);
//
//        for (uint64_t j = 0; j < (i >> 1); ++j)
//        {
//            const char t = buf[j];
//            buf[j] = buf[i - j - 1];
//            buf[i - j - 1] = t;
//        }
//    }
//    buf[i] = '\0';
//}
//
// REC_HOST std::ostream& operator<<(std::ostream& os, const uint128_t& x)
//{
//    char buf[40];
//    x.ToString(buf);
//    os << buf;
//    return os;
//}
//
//
//REC_DEVICE REC_HOST const char* NatVisStr_DebugOnly(const uint128_t& x)
//{
//    static char buf[40];
//    x.ToString(buf);
//    return buf;
//}

#endif // UINT128_T_H
