#include "recovery/secp_precompute_build.h"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: generate_secp_precompute_blob <output-path>\n";
        return 1;
    }

    std::string err;
    if (!recovery_secp_precompute::write_blob(argv[1], err)) {
        std::cerr << "failed to generate secp precompute blob: " << err << '\n';
        return 1;
    }
    return 0;
}
