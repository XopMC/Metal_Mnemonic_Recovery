#include "recovery/found_record_formatter.h"

#include "third_party/hash/sha256.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string_view>
#include <vector>

namespace recovery_format {
namespace {

constexpr char kBase58Alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr char kBech32Alphabet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::uint16_t kCrc16Poly = 0x1021u;
constexpr std::uint16_t kCrcInit = 0x0000u;
constexpr std::uint8_t kNonBounceableTag = 0x51u;

std::string hex_encode(const std::uint8_t* data, const std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(size * 2u);
    for (std::size_t i = 0; i < size; ++i) {
        const std::uint8_t value = data[i];
        out[(i * 2u) + 0u] = kHex[value >> 4u];
        out[(i * 2u) + 1u] = kHex[value & 0x0Fu];
    }
    return out;
}

std::string encode_base58(const std::uint8_t* bytes, const std::size_t length) {
    if (bytes == nullptr || length == 0u) {
        return {};
    }

    std::size_t zeros = 0u;
    while (zeros < length && bytes[zeros] == 0u) {
        ++zeros;
    }

    std::vector<std::uint8_t> b58;
    b58.reserve((length - zeros) * 138u / 100u + 1u);
    for (std::size_t i = zeros; i < length; ++i) {
        std::uint32_t carry = bytes[i];
        for (std::size_t j = 0; j < b58.size(); ++j) {
            const std::uint32_t x = static_cast<std::uint32_t>(b58[j]) * 256u + carry;
            b58[j] = static_cast<std::uint8_t>(x % 58u);
            carry = x / 58u;
        }
        while (carry > 0u) {
            b58.push_back(static_cast<std::uint8_t>(carry % 58u));
            carry /= 58u;
        }
    }

    std::string out;
    out.reserve(zeros + b58.size());
    out.append(zeros, '1');
    for (std::size_t i = 0; i < b58.size(); ++i) {
        out.push_back(kBase58Alphabet[b58[b58.size() - 1u - i]]);
    }
    return out;
}

std::string hash160_to_base58(const std::uint8_t hash160[20], const std::uint8_t prefix) {
    std::uint8_t extended[25] = {0};
    extended[0] = prefix;
    std::memcpy(&extended[1], hash160, 20u);
    std::uint8_t digest[32] = {0};
    sha256(extended, 21u, digest);
    sha256(digest, 32u, digest);
    std::memcpy(&extended[21], digest, 4u);
    return encode_base58(extended, 25u);
}

std::uint32_t bech32_polymod_step(const std::uint32_t pre) {
    const std::uint8_t b = static_cast<std::uint8_t>(pre >> 25u);
    return ((pre & 0x1ffffffu) << 5u) ^
        (((b >> 0u) & 1u) != 0u ? 0x3b6a57b2u : 0u) ^
        (((b >> 1u) & 1u) != 0u ? 0x26508e6du : 0u) ^
        (((b >> 2u) & 1u) != 0u ? 0x1ea119fau : 0u) ^
        (((b >> 3u) & 1u) != 0u ? 0x3d4233ddu : 0u) ^
        (((b >> 4u) & 1u) != 0u ? 0x2a1462b3u : 0u);
}

int convert_bits(std::uint8_t* out, std::size_t* outlen, const int outbits, const std::uint8_t* in, std::size_t inlen, const int inbits, const int pad) {
    std::uint32_t val = 0u;
    int bits = 0;
    const std::uint32_t maxv = (1u << outbits) - 1u;
    while (inlen-- > 0u) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = static_cast<std::uint8_t>((val >> bits) & maxv);
        }
    }
    if (pad != 0) {
        if (bits != 0) {
            out[(*outlen)++] = static_cast<std::uint8_t>((val << (outbits - bits)) & maxv);
        }
    } else if (((val << (outbits - bits)) & maxv) != 0u || bits >= inbits) {
        return 0;
    }
    return 1;
}

int bech32_encode(char* output, const char* hrp, const std::uint8_t* data, const std::size_t data_len, const bool bech32m) {
    std::uint32_t chk = 1u;
    std::size_t i = 0u;
    while (hrp[i] != 0) {
        const int ch = hrp[i];
        if (ch < 33 || ch > 126 || (ch >= 'A' && ch <= 'Z')) {
            return 0;
        }
        chk = bech32_polymod_step(chk) ^ static_cast<std::uint32_t>(ch >> 5);
        ++i;
    }
    chk = bech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = bech32_polymod_step(chk) ^ static_cast<std::uint32_t>(*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0u; i < data_len; ++i) {
        if ((data[i] >> 5u) != 0u) {
            return 0;
        }
        chk = bech32_polymod_step(chk) ^ data[i];
        *(output++) = kBech32Alphabet[data[i]];
    }
    for (i = 0u; i < 6u; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= (bech32m ? 0x2bc830a3u : 1u);
    for (i = 0u; i < 6u; ++i) {
        *(output++) = kBech32Alphabet[(chk >> ((5u - i) * 5u)) & 0x1fu];
    }
    *output = 0;
    return 1;
}

std::string taproot_address(const std::uint8_t xonly[32]) {
    std::uint8_t data[65] = {0};
    std::size_t data_len = 0u;
    data[0] = 1u;
    convert_bits(data + 1u, &data_len, 5, xonly, 32u, 8, 1);
    ++data_len;
    char output[86] = {0};
    return bech32_encode(output, "bc", data, data_len, true) != 0 ? std::string(output) : hex_encode(xonly, 32u);
}

std::uint16_t crc16(const std::vector<std::uint8_t>& data) {
    std::uint16_t crc = kCrcInit;
    for (const std::uint8_t byte : data) {
        crc ^= static_cast<std::uint16_t>(byte) << 8u;
        for (int i = 0; i < 8; ++i) {
            crc = static_cast<std::uint16_t>(((crc & 0x8000u) != 0u) ? ((crc << 1u) ^ kCrc16Poly) : (crc << 1u));
        }
    }
    return static_cast<std::uint16_t>(crc & 0xffffu);
}

std::string base64_urlsafe_encode(const std::vector<std::uint8_t>& input) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string encoded;
    encoded.reserve(((input.size() + 2u) / 3u) * 4u);

    int i = 0;
    int j = 0;
    std::uint8_t buf3[3] = {0};
    std::uint8_t buf4[4] = {0};
    for (const std::uint8_t byte : input) {
        buf3[i++] = byte;
        if (i == 3) {
            buf4[0] = (buf3[0] & 0xfcu) >> 2u;
            buf4[1] = static_cast<std::uint8_t>(((buf3[0] & 0x03u) << 4u) + ((buf3[1] & 0xf0u) >> 4u));
            buf4[2] = static_cast<std::uint8_t>(((buf3[1] & 0x0fu) << 2u) + ((buf3[2] & 0xc0u) >> 6u));
            buf4[3] = static_cast<std::uint8_t>(buf3[2] & 0x3fu);
            for (i = 0; i < 4; ++i) {
                encoded.push_back(alphabet[buf4[i]]);
            }
            i = 0;
        }
    }
    if (i != 0) {
        for (j = i; j < 3; ++j) {
            buf3[j] = 0;
        }
        buf4[0] = (buf3[0] & 0xfcu) >> 2u;
        buf4[1] = static_cast<std::uint8_t>(((buf3[0] & 0x03u) << 4u) + ((buf3[1] & 0xf0u) >> 4u));
        buf4[2] = static_cast<std::uint8_t>(((buf3[1] & 0x0fu) << 2u) + ((buf3[2] & 0xc0u) >> 6u));
        for (j = 0; j < i + 1; ++j) {
            encoded.push_back(alphabet[buf4[j]]);
        }
        while (i++ < 3) {
            encoded.push_back('=');
        }
    }
    while (!encoded.empty() && encoded.back() == '=') {
        encoded.pop_back();
    }
    return encoded;
}

std::string ton_address_from_hash(const std::uint8_t hash[32]) {
    std::vector<std::uint8_t> address_data;
    address_data.reserve(36u);
    address_data.push_back(kNonBounceableTag);
    address_data.push_back(0u);
    address_data.insert(address_data.end(), hash, hash + 32u);
    const std::uint16_t checksum = crc16(address_data);
    address_data.push_back(static_cast<std::uint8_t>(checksum >> 8u));
    address_data.push_back(static_cast<std::uint8_t>(checksum & 0xffu));
    return base64_urlsafe_encode(address_data);
}

std::size_t effective_match_len(const FoundRecord& record) {
    const std::size_t fallback = static_cast<std::size_t>(recovery_match_size_for_type(record.coin_type));
    const std::size_t record_len = record.match_len != 0u ? static_cast<std::size_t>(record.match_len) : fallback;
    return std::min<std::size_t>(record_len, 32u);
}

const char* ton_label_from_type(const cmr_u32 type) {
    switch (type) {
    case 0x80u: return "TON(v1r1)";
    case 0x81u: return "TON(v1r2)";
    case 0x82u: return "TON(v1r3)";
    case 0x83u: return "TON(v2r1)";
    case 0x84u: return "TON(v2r2)";
    case 0x85u: return "TON(v3r1)";
    case 0x86u: return "TON(v3r2)";
    case 0x87u: return "TON(v4r1)";
    case 0x88u: return "TON(v4r2)";
    case 0x89u: return "TON(v5r1)";
    default:    return "TON";
    }
}

}  // namespace

const char* derivation_tag_from_type(const cmr_u32 derivation_type) {
    switch (derivation_type) {
    case RESULT_DERIVATION_BIP32_SECP256K1:
        return "bip32-secp256k1";
    case RESULT_DERIVATION_SLIP0010_ED25519:
        return "slip0010-ed25519";
    case RESULT_DERIVATION_ED25519_BIP32_TEST:
        return "ed25519-bip32-test";
    default:
        return "bip32-secp256k1";
    }
}

const char* coin_label_from_type(const cmr_u32 coin_type) {
    switch (recovery_decode_base_type(coin_type)) {
    case 0x01u: return "UNCOMPRESSED";
    case 0x02u: return "COMPRESSED";
    case 0x03u: return "SEGWIT";
    case 0x04u: return "TAPROOT";
    case 0x05u: return "XPOINT";
    case 0x06u: return "ETH";
    case 0x60u: return "SOLANA";
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
        return ton_label_from_type(recovery_decode_base_type(coin_type));
    default:
        return "unknown";
    }
}

bool rebuild_phrase_from_found_record(const FoundRecord& record,
                                      const std::vector<std::string_view>& words,
                                      std::string& out_phrase,
                                      std::string& err) {
    out_phrase.clear();
    err.clear();
    if (record.word_count == 0u || record.word_count > RECOVERY_MAX_WORDS) {
        err = "invalid FoundRecord word_count";
        return false;
    }
    std::ostringstream oss;
    for (cmr_u32 word_index = 0u; word_index < record.word_count; ++word_index) {
        const cmr_u32 id = record.word_ids[word_index];
        if (id >= words.size()) {
            err = "FoundRecord word id is out of range";
            return false;
        }
        if (word_index != 0u) {
            oss << ' ';
        }
        oss << words[id];
    }
    out_phrase = oss.str();
    return true;
}

std::string format_match_hex(const FoundRecord& record) {
    return hex_encode(record.match_bytes, effective_match_len(record));
}

bool format_save_value(const FoundRecord& record,
                       std::string& out_value,
                       std::string& err) {
    out_value.clear();
    err.clear();

    switch (recovery_decode_base_type(record.coin_type)) {
    case 0x01u:
    case 0x02u:
        out_value = hash160_to_base58(record.match_bytes, 0x00u);
        return true;
    case 0x03u:
        out_value = hash160_to_base58(record.match_bytes, 0x05u);
        return true;
    case 0x04u:
        out_value = taproot_address(record.match_bytes);
        return true;
    case 0x05u:
        out_value = hex_encode(record.match_bytes, 32u);
        return true;
    case 0x06u:
        out_value = "0x" + hex_encode(record.match_bytes, 20u);
        return true;
    case 0x60u:
        out_value = encode_base58(record.match_bytes, 32u);
        return true;
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
        out_value = ton_address_from_hash(record.match_bytes);
        return true;
    default:
        err = "unsupported FoundRecord coin_type";
        return false;
    }
}

bool format_found_line(const FoundRecord& record,
                       const std::vector<std::string_view>& words,
                       const std::vector<std::string>& derivations,
                       const std::vector<std::string>& passphrases,
                       const bool save_output,
                       std::string& out_line,
                       std::string& err) {
    out_line.clear();
    err.clear();

    std::string phrase;
    if (!rebuild_phrase_from_found_record(record, words, phrase, err)) {
        return false;
    }
    if (record.derivation_index >= derivations.size()) {
        err = "FoundRecord derivation_index is out of range";
        return false;
    }
    std::string passphrase;
    if (!passphrases.empty()) {
        if (record.passphrase_index >= passphrases.size()) {
            err = "FoundRecord passphrase_index is out of range";
            return false;
        }
        passphrase = passphrases[record.passphrase_index];
    }

    const char* derivation_tag = derivation_tag_from_type(record.derivation_type);
    const bool show_marker = record.derivation_type != recovery_default_derivation_type_for_type(record.coin_type);
    const std::string derivation_display = show_marker
        ? ("(" + std::string(derivation_tag) + ") " + derivations[record.derivation_index])
        : derivations[record.derivation_index];

    std::string final_value;
    if (save_output) {
        if (!format_save_value(record, final_value, err)) {
            return false;
        }
    } else {
        final_value = format_match_hex(record);
    }

    std::ostringstream oss;
    oss << "[!] Found: "
        << phrase << ':'
        << derivation_display << ':'
        << hex_encode(record.private_key, 32u) << ':'
        << coin_label_from_type(record.coin_type) << ':'
        << final_value;
    if (!passphrase.empty()) {
        oss << ":passphrase=\"" << passphrase << "\"";
    }
    out_line = oss.str();
    return true;
}

}  // namespace recovery_format
