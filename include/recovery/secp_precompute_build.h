#pragma once

#include "recovery/secp_precompute_load.h"

namespace recovery_secp_precompute {

bool build_table(Table& out, std::string& err);
bool write_blob(const std::string& path, std::string& err);

}  // namespace recovery_secp_precompute
