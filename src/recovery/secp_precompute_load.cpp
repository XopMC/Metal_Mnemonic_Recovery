#include "recovery/secp_precompute_load.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>

namespace recovery_secp_precompute {
namespace {

namespace fs = std::filesystem;

struct CacheHeader {
    std::uint32_t magic = 0u;
    std::uint32_t version = 0u;
    std::uint32_t entry_size = 0u;
    std::uint32_t window_bits = 0u;
    std::uint32_t window_count = 0u;
    std::uint64_t row_pitch = 0u;
    std::uint64_t entry_count = 0u;
};

constexpr std::uint32_t kCacheMagic = 0x434d5253u;  // "CMRS"
constexpr std::uint32_t kCacheVersion = 1u;

}  // namespace

bool load_blob(Table& out, const std::string& path, std::string& err) {
    out = Table{};
    err.clear();

    std::ifstream in(fs::path(path), std::ios::binary);
    if (!in) {
        err = "failed to open secp precompute blob";
        return false;
    }

    CacheHeader header{};
    in.read(reinterpret_cast<char*>(&header), sizeof(header));
    if (!in) {
        err = "failed to read secp precompute blob header";
        return false;
    }
    if (header.magic != kCacheMagic ||
        header.version != kCacheVersion ||
        header.entry_size != sizeof(secp256k1_ge_storage) ||
        header.entry_count == 0u ||
        header.row_pitch == 0u) {
        err = "invalid secp precompute blob header";
        return false;
    }
    if (header.entry_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        err = "secp precompute blob entry count exceeds host limits";
        return false;
    }
    if (header.row_pitch > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        err = "secp precompute blob row pitch exceeds host limits";
        return false;
    }

    out.window_bits = header.window_bits;
    out.window_count = header.window_count;
    out.row_pitch = static_cast<std::size_t>(header.row_pitch);
    out.entries.resize(static_cast<std::size_t>(header.entry_count));

    in.read(reinterpret_cast<char*>(out.entries.data()),
            static_cast<std::streamsize>(out.entries.size() * sizeof(secp256k1_ge_storage)));
    if (!in) {
        out = Table{};
        err = "failed to read secp precompute blob contents";
        return false;
    }
    return true;
}

}  // namespace recovery_secp_precompute
