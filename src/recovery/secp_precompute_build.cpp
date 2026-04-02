#include "recovery/secp_precompute_build.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <system_error>
#include <vector>

#include "third_party/secp256k1/secp256k1.inc"

namespace recovery_secp_precompute {
namespace {

namespace fs = std::filesystem;

using SampleKey = std::array<unsigned char, 32>;

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

constexpr std::array<SampleKey, 4> kVerifyKeys = {{
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01},
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
     0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x01, 0x13, 0x25, 0x37, 0x49, 0x5b, 0x6d, 0x7f,
     0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7},
    {0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
     0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0x11, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
     0x80, 0x7f, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0x19},
}};

int build_manual_pubkey(secp256k1_pubkey& out, const unsigned char* seckey) {
    secp256k1_scalar sec{};
    int ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    secp256k1_scalar scalar_one = SCALAR_ONE;
    secp256k1_scalar_cmov(&sec, &scalar_one, !ret);

    secp256k1_gej accum{};
    secp256k1_gej_set_infinity(&accum);
    secp256k1_ge generator = secp256k1_ge_const_g;
    for (int bit = 255; bit >= 0; --bit) {
        secp256k1_gej_double_var(&accum, &accum, nullptr);
        if (secp256k1_scalar_get_bits(&sec, static_cast<unsigned int>(bit), 1u) != 0u) {
            secp256k1_gej_add_ge_var(&accum, &accum, &generator, nullptr);
        }
    }

    secp256k1_ge affine{};
    secp256k1_ge_set_gej(&affine, &accum);
    secp256k1_pubkey_save(&out, &affine);
    return ret;
}

bool verify_table_contents(const Table& table, std::string& err) {
    if (table.entries.empty()) {
        err = "secp precompute table is empty";
        return false;
    }
    if (table.row_pitch == 0u) {
        err = "secp precompute table has zero row pitch";
        return false;
    }

    secp256k1_ge_storage expected_g{};
    secp256k1_ge generator = secp256k1_ge_const_g;
    secp256k1_ge_to_storage(&expected_g, &generator);
    if (std::memcmp(&table.entries.front(), &expected_g, sizeof(expected_g)) != 0) {
        err = "secp precompute table first entry does not match generator";
        return false;
    }

    for (const SampleKey& key : kVerifyKeys) {
        secp256k1_pubkey manual_pubkey{};
        secp256k1_pubkey fast_pubkey{};
        const int manual_ok = build_manual_pubkey(manual_pubkey, key.data());
        const int fast_ok = secp256k1_ec_pubkey_create(&fast_pubkey, key.data(), table.entries.data(), table.row_pitch);
        if (manual_ok != fast_ok) {
            err = "secp precompute verification diverged on pubkey validity";
            return false;
        }
        if (manual_ok == 0) {
            continue;
        }
        if (std::memcmp(manual_pubkey.data, fast_pubkey.data, sizeof(manual_pubkey.data)) != 0) {
            err = "secp precompute verification diverged on pubkey bytes";
            return false;
        }
    }

    return true;
}

bool persist_table_to_path(const Table& table, const fs::path& path, std::string* err) {
    if (table.entries.empty() || table.row_pitch == 0u) {
        if (err != nullptr) {
            *err = "secp precompute table is empty";
        }
        return false;
    }

    const fs::path tmp_path = path.string() + ".tmp";
    std::error_code ec;
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path(), ec);
        if (ec) {
            if (err != nullptr) {
                *err = "failed to create secp precompute blob directory";
            }
            return false;
        }
    }

    std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        if (err != nullptr) {
            *err = "failed to open secp precompute blob for writing";
        }
        return false;
    }

    CacheHeader header{};
    header.magic = kCacheMagic;
    header.version = kCacheVersion;
    header.entry_size = sizeof(secp256k1_ge_storage);
    header.window_bits = table.window_bits;
    header.window_count = table.window_count;
    header.row_pitch = static_cast<std::uint64_t>(table.row_pitch);
    header.entry_count = static_cast<std::uint64_t>(table.entries.size());

    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    out.write(reinterpret_cast<const char*>(table.entries.data()),
              static_cast<std::streamsize>(table.entries.size() * sizeof(secp256k1_ge_storage)));
    out.close();
    if (!out) {
        fs::remove(tmp_path, ec);
        if (err != nullptr) {
            *err = "failed to write secp precompute blob";
        }
        return false;
    }

    fs::rename(tmp_path, path, ec);
    if (ec) {
        fs::remove(path, ec);
        ec.clear();
        fs::rename(tmp_path, path, ec);
        if (ec) {
            fs::remove(tmp_path, ec);
            if (err != nullptr) {
                *err = "failed to publish secp precompute blob";
            }
            return false;
        }
    }
    return true;
}

}  // namespace

bool build_table(Table& out, std::string& err) {
    out = Table{};
    err.clear();

    const unsigned int window_bits = ECMULT_WINDOW_SIZE_CONST[0];
    const unsigned int window_count = WINDOWS_SIZE_CONST[0];
    if (window_bits == 0u || window_bits >= 31u) {
        err = "invalid secp precompute window width";
        return false;
    }
    if (window_count == 0u) {
        err = "invalid secp precompute window count";
        return false;
    }

    const std::size_t row_size = std::size_t{1} << (window_bits - 1u);
    const std::size_t total_entries = row_size * static_cast<std::size_t>(window_count);
    const std::size_t row_pitch = row_size * sizeof(secp256k1_ge_storage);
    if (row_size == 0u || total_entries == 0u || row_pitch == 0u) {
        err = "secp precompute sizing overflow";
        return false;
    }
    if (row_pitch > static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
        err = "secp precompute row pitch exceeds kernel ABI";
        return false;
    }

    out.entries.resize(total_entries);
    out.row_pitch = row_pitch;
    out.window_bits = window_bits;
    out.window_count = window_count;

    std::vector<secp256k1_gej> window_points(row_size);
    std::vector<secp256k1_ge> affine_points(row_size);

    secp256k1_gej base_j{};
    secp256k1_gej_set_ge(&base_j, &secp256k1_ge_const_g);

    for (unsigned int window = 0u; window < window_count; ++window) {
        secp256k1_gej base_copy = base_j;
        secp256k1_ge base_ge{};
        secp256k1_ge_set_gej(&base_ge, &base_copy);

        secp256k1_gej accum{};
        secp256k1_gej_set_infinity(&accum);
        for (std::size_t entry = 0u; entry < row_size; ++entry) {
            secp256k1_gej_add_ge_var(&accum, &accum, &base_ge, nullptr);
            window_points[entry] = accum;
        }

        secp256k1_ge_set_all_gej_var(affine_points.data(), window_points.data(), row_size);
        const std::size_t row_offset = static_cast<std::size_t>(window) * row_size;
        for (std::size_t entry = 0u; entry < row_size; ++entry) {
            secp256k1_ge_to_storage(&out.entries[row_offset + entry], &affine_points[entry]);
        }

        for (unsigned int bit = 0u; bit < window_bits; ++bit) {
            secp256k1_gej_double_var(&base_j, &base_j, nullptr);
        }
    }

    return verify_table_contents(out, err);
}

bool write_blob(const std::string& path, std::string& err) {
    Table table;
    if (!build_table(table, err)) {
        return false;
    }
    return persist_table_to_path(table, fs::path(path), &err);
}

}  // namespace recovery_secp_precompute
