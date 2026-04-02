#include "recovery/derivation_program.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << message << '\n';
        return false;
    }
    return true;
}

bool require_equal(const std::vector<std::uint32_t>& lhs,
                   const std::vector<std::uint32_t>& rhs,
                   const std::string& label) {
    if (lhs == rhs) {
        return true;
    }
    std::cerr << label << " mismatch\n";
    return false;
}

bool require_equal(const std::vector<std::string>& lhs,
                   const std::vector<std::string>& rhs,
                   const std::string& label) {
    if (lhs == rhs) {
        return true;
    }
    std::cerr << label << " mismatch\n";
    return false;
}

}  // namespace

int main() {
    bool ok = true;
    const auto build_path = [](const std::size_t segment_count) {
        std::string out = "m";
        for (std::size_t i = 0u; i < segment_count; ++i) {
            out += "/";
            out += std::to_string(i & 0x7fffffffu);
        }
        return out;
    };

    {
        std::vector<std::uint32_t> path;
        std::string err;
        ok &= require(recovery_derivation::parse_path("m/44'/501'/0'/0'", path, err), "parse_path should accept hardened path");
        ok &= require_equal(path,
                            {0x8000002cu, 0x800001f5u, 0x80000000u, 0x80000000u},
                            "parse_path(hardened)");
    }

    {
        std::vector<std::uint32_t> path;
        std::string err;
        ok &= require(recovery_derivation::parse_path("m/84'/0'/0'/0/7", path, err), "parse_path should accept mixed hardened path");
        ok &= require_equal(path,
                            {0x80000054u, 0x80000000u, 0x80000000u, 0x00000000u, 0x00000007u},
                            "parse_path(mixed)");
    }

    {
        std::vector<std::uint32_t> path;
        std::string err;
        ok &= require(!recovery_derivation::parse_path("x/44'/0'/0'", path, err), "parse_path should reject non-m root");
        ok &= require(!err.empty(), "parse_path should return error text");
    }

    {
        std::vector<std::uint32_t> path;
        std::string err;
        ok &= require(recovery_derivation::parse_path(build_path(recovery_derivation::kMaxDerivationPathSegments), path, err),
                      "parse_path should accept max segment count");
        ok &= require(path.size() == recovery_derivation::kMaxDerivationPathSegments,
                      "parse_path max segment count mismatch");
    }

    {
        std::vector<std::uint32_t> path;
        std::string err;
        ok &= require(!recovery_derivation::parse_path(build_path(recovery_derivation::kMaxDerivationPathSegments + 1u), path, err),
                      "parse_path should reject overlong path");
        ok &= require(path.empty(), "parse_path should clear output on overlong path");
        ok &= require(err.find("max") != std::string::npos, "parse_path overlong error should mention max");
    }

    {
        std::vector<std::uint32_t> path;
        std::string err;
        ok &= require(!recovery_derivation::parse_path("m/0/1/x", path, err),
                      "parse_path should reject malformed segment");
        ok &= require(path.empty(), "parse_path should clear output on malformed segment");
    }

    {
        recovery_derivation::Policy policy = recovery_derivation::Policy::Auto;
        ok &= require(recovery_derivation::parse_policy_argument("1", policy), "parse_policy_argument(1)");
        ok &= require(policy == recovery_derivation::Policy::ForceBip32Secp256k1, "policy 1 mismatch");
        ok &= require(recovery_derivation::parse_policy_argument("4", policy), "parse_policy_argument(4)");
        ok &= require(policy == recovery_derivation::Policy::ForceEd25519Bip32Test, "policy 4 mismatch");
        ok &= require(!recovery_derivation::parse_policy_argument("0", policy), "parse_policy_argument should reject 0");
        ok &= require(!recovery_derivation::parse_policy_argument("12", policy), "parse_policy_argument should reject multi-char");
    }

    {
        ok &= require_equal(
            recovery_derivation::engines_for_policy(recovery_derivation::Policy::Auto, "ce"),
            {"bip32-secp256k1"},
            "engines_for_policy(auto,secp)");
        ok &= require_equal(
            recovery_derivation::engines_for_policy(recovery_derivation::Policy::Auto, "St"),
            {"slip0010-ed25519"},
            "engines_for_policy(auto,ed)");
        ok &= require_equal(
            recovery_derivation::engines_for_policy(recovery_derivation::Policy::Mixed, "cSt"),
            {"bip32-secp256k1", "slip0010-ed25519"},
            "engines_for_policy(mixed)");
        ok &= require_equal(
            recovery_derivation::engines_for_policy(recovery_derivation::Policy::ForceEd25519Bip32Test, "S"),
            {"ed25519-bip32-test"},
            "engines_for_policy(d_type4)");
    }

    {
        ok &= require(std::string(recovery_derivation::default_engine_for_coin('c')) == "bip32-secp256k1",
                      "default_engine_for_coin(c)");
        ok &= require(std::string(recovery_derivation::default_engine_for_coin('S')) == "slip0010-ed25519",
                      "default_engine_for_coin(S)");
        ok &= require(recovery_derivation::policy_cli_value(recovery_derivation::Policy::Mixed) == "3",
                      "policy_cli_value(mixed)");
        ok &= require(recovery_derivation::policy_cli_value(recovery_derivation::Policy::Auto) == "auto",
                      "policy_cli_value(auto)");
    }

    return ok ? 0 : 1;
}
