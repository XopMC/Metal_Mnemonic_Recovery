#include "recovery/secp_precompute_build.h"

#include <cstddef>
#include <iostream>
#include <string>

int main() {
    recovery_secp_precompute::Table table;
    std::string err;
    if (!recovery_secp_precompute::build_table(table, err)) {
        std::cerr << "secp precompute build failed: " << err << "\n";
        return 1;
    }

    if (table.window_bits != 16u) {
        std::cerr << "unexpected secp window bits: " << table.window_bits << "\n";
        return 1;
    }
    if (table.window_count != 17u) {
        std::cerr << "unexpected secp window count: " << table.window_count << "\n";
        return 1;
    }

    const std::size_t expected_row_entries = std::size_t{1} << (table.window_bits - 1u);
    const std::size_t expected_pitch = expected_row_entries * sizeof(secp256k1_ge_storage);
    const std::size_t expected_entries = expected_row_entries * table.window_count;

    if (table.row_pitch != expected_pitch) {
        std::cerr << "unexpected secp row pitch: " << table.row_pitch << "\n";
        return 1;
    }
    if (table.entries.size() != expected_entries) {
        std::cerr << "unexpected secp entry count: " << table.entries.size() << "\n";
        return 1;
    }

    return 0;
}
