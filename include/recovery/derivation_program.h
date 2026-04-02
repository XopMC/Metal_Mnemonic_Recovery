#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace recovery_derivation {

enum class Policy : std::uint8_t {
    Auto = 0,
    ForceBip32Secp256k1 = 1,
    ForceSlip0010Ed25519 = 2,
    Mixed = 3,
    ForceEd25519Bip32Test = 4
};

constexpr std::size_t kMaxDerivationPathSegments = 64u;

bool parse_path(const std::string& path, std::vector<std::uint32_t>& out, std::string& err);
bool parse_policy_argument(const char* value, Policy& out_policy);
std::string policy_cli_value(Policy policy);
bool has_any_coin(const std::string& coin_types, const char* candidates);
std::vector<std::string> engines_for_policy(Policy policy, const std::string& coin_types);
const char* default_engine_for_coin(char coin);

}  // namespace recovery_derivation
