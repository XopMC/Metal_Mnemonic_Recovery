// Author: Mikhail Khoroshavin aka "XopMC"
//
// Host-side SHA-256 helpers for the macOS Metal release path.
// This translation unit intentionally uses CommonCrypto so the public
// repository does not ship GPL-derived host hashing code.

#ifndef SHA256_H
#define SHA256_H

#include <cstddef>
#include <cstdint>
#include <string>

void sha256(std::uint8_t* input, std::size_t length, std::uint8_t* digest);
void sha256_33(std::uint8_t* input, std::uint8_t* digest);
void sha256_65(std::uint8_t* input, std::uint8_t* digest);
void sha256_checksum(std::uint8_t* input, int length, std::uint8_t* checksum);
void sha256sse_1B(std::uint32_t* i0, std::uint32_t* i1, std::uint32_t* i2, std::uint32_t* i3,
    std::uint8_t* d0, std::uint8_t* d1, std::uint8_t* d2, std::uint8_t* d3);
void sha256sse_2B(std::uint32_t* i0, std::uint32_t* i1, std::uint32_t* i2, std::uint32_t* i3,
    std::uint8_t* d0, std::uint8_t* d1, std::uint8_t* d2, std::uint8_t* d3);
void sha256sse_checksum(std::uint32_t* i0, std::uint32_t* i1, std::uint32_t* i2, std::uint32_t* i3,
    std::uint8_t* d0, std::uint8_t* d1, std::uint8_t* d2, std::uint8_t* d3);
std::string sha256_hex(unsigned char* digest);
void sha256sse_test();

#endif
