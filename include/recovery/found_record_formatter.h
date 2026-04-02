#pragma once

#include "metal/RecoveryMetalTypes.h"

#include <string>
#include <string_view>
#include <vector>

namespace recovery_format {

const char* derivation_tag_from_type(cmr_u32 derivation_type);
const char* coin_label_from_type(cmr_u32 coin_type);

bool rebuild_phrase_from_found_record(const FoundRecord& record,
                                      const std::vector<std::string_view>& words,
                                      std::string& out_phrase,
                                      std::string& err);

std::string format_match_hex(const FoundRecord& record);

bool format_save_value(const FoundRecord& record,
                       std::string& out_value,
                       std::string& err);

bool format_found_line(const FoundRecord& record,
                       const std::vector<std::string_view>& words,
                       const std::vector<std::string>& derivations,
                       const std::vector<std::string>& passphrases,
                       bool save_output,
                       std::string& out_line,
                       std::string& err);

}  // namespace recovery_format
