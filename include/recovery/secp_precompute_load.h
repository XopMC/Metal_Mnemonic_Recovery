#pragma once

#include "third_party/secp256k1/secp256k1_common.h"

#include <cstddef>
#include <string>
#include <vector>

namespace recovery_secp_precompute {

struct Table {
    std::vector<secp256k1_ge_storage> entries;
    std::size_t row_pitch = 0u;
    unsigned int window_bits = 0u;
    unsigned int window_count = 0u;
};

bool load_blob(Table& out, const std::string& path, std::string& err);

}  // namespace recovery_secp_precompute
