// Author: Mikhail Khoroshavin aka "XopMC"
//
// Host-side SHA-256 helpers for the macOS Metal release path.
// This translation unit intentionally uses CommonCrypto so the public
// repository does not ship GPL-derived host hashing code.

#include "sha256.h"

#include <CommonCrypto/CommonDigest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace {

void sha256_const(const std::uint8_t* input, const std::size_t length, std::uint8_t* digest) {
    CC_SHA256(input, static_cast<CC_LONG>(length), digest);
}

void sha256_words(std::uint32_t* input, const std::size_t byte_length, std::uint8_t* digest) {
    sha256(reinterpret_cast<std::uint8_t*>(input), byte_length, digest);
}

}  // namespace

void sha256(std::uint8_t* input, const std::size_t length, std::uint8_t* digest) {
    sha256_const(input, length, digest);
}

void sha256_33(std::uint8_t* input, std::uint8_t* digest) {
    sha256_const(input, 33u, digest);
}

void sha256_65(std::uint8_t* input, std::uint8_t* digest) {
    sha256_const(input, 65u, digest);
}

void sha256_checksum(std::uint8_t* input, const int length, std::uint8_t* checksum) {
    std::array<std::uint8_t, CC_SHA256_DIGEST_LENGTH> digest{};
    sha256_const(input, static_cast<std::size_t>(length), digest.data());
    sha256_const(digest.data(), digest.size(), digest.data());
    std::memcpy(checksum, digest.data(), 4u);
}

void sha256sse_1B(std::uint32_t* i0, std::uint32_t* i1, std::uint32_t* i2, std::uint32_t* i3,
    std::uint8_t* d0, std::uint8_t* d1, std::uint8_t* d2, std::uint8_t* d3) {
    if (i0 != nullptr && d0 != nullptr) sha256_words(i0, 64u, d0);
    if (i1 != nullptr && d1 != nullptr) sha256_words(i1, 64u, d1);
    if (i2 != nullptr && d2 != nullptr) sha256_words(i2, 64u, d2);
    if (i3 != nullptr && d3 != nullptr) sha256_words(i3, 64u, d3);
}

void sha256sse_2B(std::uint32_t* i0, std::uint32_t* i1, std::uint32_t* i2, std::uint32_t* i3,
    std::uint8_t* d0, std::uint8_t* d1, std::uint8_t* d2, std::uint8_t* d3) {
    if (i0 != nullptr && d0 != nullptr) sha256_words(i0, 128u, d0);
    if (i1 != nullptr && d1 != nullptr) sha256_words(i1, 128u, d1);
    if (i2 != nullptr && d2 != nullptr) sha256_words(i2, 128u, d2);
    if (i3 != nullptr && d3 != nullptr) sha256_words(i3, 128u, d3);
}

void sha256sse_checksum(std::uint32_t* i0, std::uint32_t* i1, std::uint32_t* i2, std::uint32_t* i3,
    std::uint8_t* d0, std::uint8_t* d1, std::uint8_t* d2, std::uint8_t* d3) {
    if (i0 != nullptr && d0 != nullptr) sha256_checksum(reinterpret_cast<std::uint8_t*>(i0), 64, d0);
    if (i1 != nullptr && d1 != nullptr) sha256_checksum(reinterpret_cast<std::uint8_t*>(i1), 64, d1);
    if (i2 != nullptr && d2 != nullptr) sha256_checksum(reinterpret_cast<std::uint8_t*>(i2), 64, d2);
    if (i3 != nullptr && d3 != nullptr) sha256_checksum(reinterpret_cast<std::uint8_t*>(i3), 64, d3);
}

std::string sha256_hex(unsigned char* digest) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        out << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    return out.str();
}

void sha256sse_test() {
}
