#include "recovery/found_record_formatter.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

void require(const bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "[found-record-formatter] " << message << '\n';
        std::exit(1);
    }
}

std::vector<std::uint8_t> hex_to_bytes(const char* hex) {
    std::vector<std::uint8_t> out;
    const std::string input(hex == nullptr ? "" : hex);
    require((input.size() % 2u) == 0u, "hex fixture has odd length");
    out.reserve(input.size() / 2u);
    for (std::size_t i = 0; i < input.size(); i += 2u) {
        const std::string chunk = input.substr(i, 2u);
        out.push_back(static_cast<std::uint8_t>(std::strtoul(chunk.c_str(), nullptr, 16)));
    }
    return out;
}

FoundRecord make_record(const std::uint32_t derivation_type,
                        const std::uint32_t coin_type,
                        const char* private_key_hex,
                        const char* match_hex,
                        const std::uint32_t passphrase_index = 0u) {
    FoundRecord record{};
    record.word_count = 12u;
    for (std::uint32_t i = 0u; i < record.word_count; ++i) {
        record.word_ids[i] = i;
    }
    record.derivation_index = 0u;
    record.derivation_type = derivation_type;
    record.coin_type = coin_type;
    record.round_delta = 0;
    record.passphrase_index = passphrase_index;

    const std::vector<std::uint8_t> private_key = hex_to_bytes(private_key_hex);
    const std::vector<std::uint8_t> match = hex_to_bytes(match_hex);
    require(private_key.size() == 32u, "private key fixture must be 32 bytes");
    require(match.size() <= 32u, "match fixture exceeds 32 bytes");

    std::memcpy(record.private_key, private_key.data(), private_key.size());
    std::memcpy(record.match_bytes, match.data(), match.size());
    record.match_len = static_cast<std::uint32_t>(match.size());
    return record;
}

std::vector<std::string_view> base_words() {
    return {
        "adapt", "access", "alert", "human", "kiwi", "rough",
        "pottery", "level", "soon", "funny", "burst", "divorce"
    };
}

void expect_line(const FoundRecord& record,
                 const std::vector<std::string>& derivations,
                 const std::vector<std::string>& passphrases,
                 const bool save_output,
                 const char* expected_line,
                 const char* case_name) {
    std::string line;
    std::string err;
    require(
        recovery_format::format_found_line(record, base_words(), derivations, passphrases, save_output, line, err),
        std::string(case_name) + ": formatter error: " + err);
    require(line == expected_line, std::string(case_name) + ": line mismatch");
}

}  // namespace

int main() {
    expect_line(
        make_record(
            RESULT_DERIVATION_BIP32_SECP256K1,
            0x02u,
            "1e1985ee8e215c7250016c04c410a48299710cccf95fed7a749177c436f25df9",
            "1a4603d1ff9121515d02a6fee37c20829ca522b0"),
        {"m/44'/0'/0'/0/0"},
        {},
        true,
        "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:m/44'/0'/0'/0/0:1e1985ee8e215c7250016c04c410a48299710cccf95fed7a749177c436f25df9:COMPRESSED:13PvSiAXs13bFByyw6v8vENDyeqXCGMamM",
        "secp compressed save");

    expect_line(
        make_record(
            RESULT_DERIVATION_BIP32_SECP256K1,
            0x02u,
            "1e1985ee8e215c7250016c04c410a48299710cccf95fed7a749177c436f25df9",
            "1a4603d1ff9121515d02a6fee37c20829ca522b0"),
        {"m/44'/0'/0'/0/0"},
        {},
        false,
        "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:m/44'/0'/0'/0/0:1e1985ee8e215c7250016c04c410a48299710cccf95fed7a749177c436f25df9:COMPRESSED:1a4603d1ff9121515d02a6fee37c20829ca522b0",
        "secp compressed raw");

    expect_line(
        make_record(
            RESULT_DERIVATION_BIP32_SECP256K1,
            0x02u,
            "269ed59b6bdedd90ec58c42a3840f39a702fa3d47c487183d25d3dd64a1ce53b",
            "1e398598f50849236bc8a077b184fbce0aa74f4e",
            0u),
        {"m/44'/0'/0'/0/0"},
        {"TREZOR"},
        true,
        "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:m/44'/0'/0'/0/0:269ed59b6bdedd90ec58c42a3840f39a702fa3d47c487183d25d3dd64a1ce53b:COMPRESSED:13kpBSmCRv8vDTpKPkt6uMsz6TahMJhpNT:passphrase=\"TREZOR\"",
        "secp passphrase");

    expect_line(
        make_record(
            RESULT_DERIVATION_SLIP0010_ED25519,
            0x60u,
            "2af60a958e4a68310136587f469b488e720574c50cd1eeac4e9723ca23380bce",
            "89dfcdfe8986448bf0ca1f5bc1720de5ad66104c672238ff3b8064c4c6659f63"),
        {"m/44'/501'/0'/0'"},
        {},
        true,
        "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:m/44'/501'/0'/0':2af60a958e4a68310136587f469b488e720574c50cd1eeac4e9723ca23380bce:SOLANA:AHCnjmCRYnAEson16A7zX4HyFdWcwKJpzn8oq3UAmXLE",
        "solana save");

    expect_line(
        make_record(
            RESULT_DERIVATION_ED25519_BIP32_TEST,
            0x02u,
            "b70a276d18761a97a4282dd5cd719ad9b0121109a479c77bab7f70a2a5ad88f4",
            "4fd01a8da7097495668c9ee9499084bc5680199a"),
        {"m/44'/0'/0'/0/0"},
        {},
        true,
        "[!] Found: adapt access alert human kiwi rough pottery level soon funny burst divorce:(ed25519-bip32-test) m/44'/0'/0'/0/0:b70a276d18761a97a4282dd5cd719ad9b0121109a479c77bab7f70a2a5ad88f4:COMPRESSED:18H1gTP45BW2HP3NHq24z5vpNUcf2cJeYR",
        "ed25519-bip32 save");

    std::cout << "found record formatter: ok\n";
    return 0;
}
