#include "recovery/derivation_program.h"

#include <cstdlib>

namespace recovery_derivation {

bool parse_path(const std::string& path, std::vector<std::uint32_t>& out, std::string& err) {
    out.clear();
    if (path.empty() || path[0] != 'm') {
        err = "unsupported derivation path: " + path;
        return false;
    }
    if (path == "m") {
        return true;
    }

    std::size_t begin = 2u;
    while (begin <= path.size()) {
        const std::size_t slash = path.find('/', begin);
        std::string segment = (slash == std::string::npos) ? path.substr(begin) : path.substr(begin, slash - begin);
        if (segment.empty()) {
            err = "invalid derivation segment in path: " + path;
            out.clear();
            return false;
        }

        bool hardened = false;
        if (segment.back() == '\'') {
            hardened = true;
            segment.pop_back();
        }

        char* end_ptr = nullptr;
        const unsigned long value = std::strtoul(segment.c_str(), &end_ptr, 10);
        if (end_ptr == nullptr || *end_ptr != '\0' || value > 0x7fffffffu) {
            err = "invalid derivation segment in path: " + path;
            out.clear();
            return false;
        }

        std::uint32_t parsed = static_cast<std::uint32_t>(value);
        if (hardened) {
            parsed |= 0x80000000u;
        }
        out.emplace_back(parsed);
        if (out.size() > kMaxDerivationPathSegments) {
            err = "derivation path has too many segments (max " +
                  std::to_string(kMaxDerivationPathSegments) + "): " + path;
            out.clear();
            return false;
        }

        if (slash == std::string::npos) {
            break;
        }
        begin = slash + 1u;
    }
    return true;
}

bool parse_policy_argument(const char* value, Policy& out_policy) {
    if (value == nullptr || *value == '\0' || value[1] != '\0') {
        return false;
    }
    switch (value[0]) {
        case '1': out_policy = Policy::ForceBip32Secp256k1; return true;
        case '2': out_policy = Policy::ForceSlip0010Ed25519; return true;
        case '3': out_policy = Policy::Mixed; return true;
        case '4': out_policy = Policy::ForceEd25519Bip32Test; return true;
        default: return false;
    }
}

std::string policy_cli_value(const Policy policy) {
    switch (policy) {
        case Policy::ForceBip32Secp256k1: return "1";
        case Policy::ForceSlip0010Ed25519: return "2";
        case Policy::Mixed: return "3";
        case Policy::ForceEd25519Bip32Test: return "4";
        case Policy::Auto:
        default:
            return "auto";
    }
}

bool has_any_coin(const std::string& coin_types, const char* candidates) {
    for (const char* it = candidates; *it != '\0'; ++it) {
        if (coin_types.find(*it) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> engines_for_policy(const Policy policy, const std::string& coin_types) {
    switch (policy) {
        case Policy::ForceBip32Secp256k1: return {"bip32-secp256k1"};
        case Policy::ForceSlip0010Ed25519: return {"slip0010-ed25519"};
        case Policy::Mixed: return {"bip32-secp256k1", "slip0010-ed25519"};
        case Policy::ForceEd25519Bip32Test: return {"ed25519-bip32-test"};
        case Policy::Auto:
        default: {
            std::vector<std::string> engines;
            if (has_any_coin(coin_types, "cusrxe")) {
                engines.emplace_back("bip32-secp256k1");
            }
            if (has_any_coin(coin_types, "StT")) {
                engines.emplace_back("slip0010-ed25519");
            }
            return engines;
        }
    }
}

const char* default_engine_for_coin(const char coin) {
    switch (coin) {
        case 'S':
        case 't':
        case 'T':
            return "slip0010-ed25519";
        default:
            return "bip32-secp256k1";
    }
}

}  // namespace recovery_derivation
