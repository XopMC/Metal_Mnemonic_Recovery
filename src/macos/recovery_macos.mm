// Author: Mikhail Khoroshavin aka "XopMC"

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dispatch/dispatch.h>

#include "app/recovery_app.h"
#include "app/recovery_cli.h"
#include "metal/RecoveryEvalEd25519.h"
#include "metal/RecoveryEvalSecp.h"
#include "metal/RecoveryMetalTypes.h"
#include "recovery/RecoveryWordlistsEmbedded.h"
#include "recovery/derivation_program.h"
#include "recovery/filter.h"
#include "recovery/found_record_formatter.h"
#include "recovery/secp_precompute_load.h"
#include "third_party/hash/sha256.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <clocale>
#include <cmath>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern bool g_public_help_requested;
bool is_public_recovery_flag(const char* arg);
bool is_supported_public_target_family(char value);
void printHelp();

namespace fs = std::filesystem;

namespace {

static constexpr uint32_t kRecoveryMinStageCapacity = 32768u;
static constexpr uint32_t kRecoveryDefaultStageCapacity = 262144u;
static constexpr uint32_t kRecoveryMaxStageCapacity = 262144u;
static constexpr uint32_t kRecoveryMaxPairCapacity = 524288u;
static constexpr uint32_t kRecoveryMaxChecksumBatchCandidates = 16777216u;
static constexpr uint32_t kRecoveryDefaultDispatchThreads = 256u;
static constexpr uint32_t kRecoveryDefaultStageSizingThreads = 256u;
static constexpr uint32_t kRecoveryDefaultChecksumCandidateMultiplier = 8u;
enum class RecoveryQueueEntryType {
    Phrase,
    File
};

using DerivationPolicy = recovery_derivation::Policy;

struct RecoveryQueueEntry {
    RecoveryQueueEntryType type = RecoveryQueueEntryType::Phrase;
    std::string value;
};

struct RecoveryWordlist {
    std::string id;
    std::string file_name;
    std::string path;
    std::string name;
    std::vector<std::string_view> words;
    std::vector<std::string> owned_words;
    std::vector<std::string> words_norm;
    std::unordered_map<std::string, int> id_by_norm;
    bool external = false;
};

struct RecoveryTemplateInput {
    std::string source;
    size_t line_no = 0;
    std::string phrase;
};

struct RecoveryPreparedTask {
    std::string source;
    size_t line_no = 0;
    const RecoveryWordlist* wordlist = nullptr;
    std::vector<int> ids;
    std::vector<int> missing_positions;
    std::string normalized_phrase;
    size_t added_stars = 0;
    std::vector<std::pair<std::string, std::string>> replacements;
};

struct RecoveryPreparedDerivation {
    std::string text;
    std::vector<cmr_u32> path;
};

enum class RecoveryEngineKind : uint8_t {
    Secp,
    Slip0010Ed25519,
    Ed25519Bip32Test,
};

enum class RecoveryFilterKernelMode : uint8_t {
    None,
    BloomOnly,
    XorSingle,
    Full,
};

struct RecoveryEngineDispatch {
    RecoveryEngineKind kind = RecoveryEngineKind::Secp;
    cmr_u32 derivation_type = RESULT_DERIVATION_BIP32_SECP256K1;
};

struct RecoveryExecutionPlan {
    std::vector<RecoveryEngineDispatch> engines;
    std::string secp_coin_types;
    std::string ed_coin_types;
    bool need_secp_targets = false;
    bool need_ed_targets = false;
    bool need_secp_derive = false;
    bool need_ed_derive = false;
    cmr_u32 secp_outputs_per_candidate = 1u;
    cmr_u32 ed_outputs_per_candidate = 1u;
};

struct AppConfig {
    bool recovery_mode = false;
    bool save_output = false;
    bool silent = false;
    bool full = false;
    uint64_t pbkdf_iterations = 2048;
    uint32_t found_limit = 150000;
    unsigned int block_threads = kRecoveryDefaultDispatchThreads;
    unsigned int block_count = 0;
    bool custom_threads = false;
    bool custom_blocks = false;
    std::vector<int> device_list = {0};
    std::vector<RecoveryQueueEntry> recovery_queue;
    std::vector<std::string> derivation_files;
    std::vector<std::string> passphrases;
    std::string passphrases_file;
    std::string forced_wordlist;
    std::string output_file = "result.txt";
    std::string coin_types = "cus";
    DerivationPolicy derivation_policy = DerivationPolicy::Auto;
    bool use_hash_target = false;
    std::vector<uint8_t> hash_target;
    std::string hash_target_hex;
    std::vector<std::string> bloom_files;
    std::vector<std::string> xor_filter_files;
};

static uint32_t recovery_effective_found_limit(const AppConfig& config) {
    return config.found_limit;
}

struct PipelineBuildRequest {
    const char* function_name = nullptr;
    const char* label = nullptr;
    bool required = true;
    id<MTLComputePipelineState> pipeline = nil;
    std::string error;
};

struct PipelineArchiveContext {
    id<MTLBinaryArchive> archive = nil;
    NSURL* url = nil;
};

struct RecoveryStats {
    uint64_t tested_total = 0;
    uint32_t found_total = 0;
};

struct RecoveryLiveStatusState {
    std::atomic_uint64_t tested_total{0ull};
    std::atomic_uint64_t checksum_valid_total{0ull};
    std::atomic_uint found_total{0u};
    std::atomic_bool stop{false};
    uint64_t hash_checks_per_candidate = 0ull;
};

static std::mutex g_console_status_mutex;
static bool g_console_status_active = false;
static size_t g_console_status_width = 0u;

static void recovery_console_clear_status_line_locked() {
    if (!g_console_status_active) {
        return;
    }
    std::string output;
    output.reserve(g_console_status_width + 3u);
    output.push_back('\r');
    output.append(g_console_status_width, ' ');
    output.push_back('\r');
    std::fputs(output.c_str(), stdout);
    std::fflush(stdout);
    g_console_status_active = false;
    g_console_status_width = 0u;
}

static void recovery_console_write_status_line(const std::string& line) {
    std::string normalized = line;
    while (!normalized.empty() && (normalized.back() == '\r' || normalized.back() == '\n')) {
        normalized.pop_back();
    }
    if (normalized.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_console_status_mutex);
    std::string output;
    output.reserve(normalized.size() + 3u +
                   (g_console_status_active && g_console_status_width > normalized.size()
                        ? (g_console_status_width - normalized.size())
                        : 0u));
    output.push_back('\r');
    output += normalized;
    if (g_console_status_active && g_console_status_width > normalized.size()) {
        output.append(g_console_status_width - normalized.size(), ' ');
    }
    output.push_back('\r');
    std::fputs(output.c_str(), stdout);
    std::fflush(stdout);
    g_console_status_active = true;
    g_console_status_width = normalized.size();
}

static void recovery_console_clear_status_line() {
    std::lock_guard<std::mutex> lock(g_console_status_mutex);
    recovery_console_clear_status_line_locked();
}

static void recovery_console_write_stdout_line(const std::string& line) {
    if (line.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_console_status_mutex);
    recovery_console_clear_status_line_locked();
    std::fputs(line.c_str(), stdout);
    std::fflush(stdout);
}

static std::string recovery_trim_spaces_copy(const std::string& in) {
    size_t b = 0;
    size_t e = in.size();
    while (b < e && std::isspace(static_cast<unsigned char>(in[b])) != 0) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1])) != 0) --e;
    return in.substr(b, e - b);
}

static bool recovery_is_ascii(const std::string& s) {
    for (const unsigned char c : s) {
        if (c >= 128u) return false;
    }
    return true;
}

static std::string recovery_norm_token(const std::string& in) {
    if (!recovery_is_ascii(in)) {
        return in;
    }
    std::string out = in;
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

static std::vector<std::string> recovery_split_tokens(const std::string& phrase) {
    std::vector<std::string> out;
    std::istringstream iss(phrase);
    std::string token;
    while (iss >> token) {
        out.emplace_back(std::move(token));
    }
    return out;
}

static size_t recovery_levenshtein(const std::string& a, const std::string& b) {
    const size_t n = a.size();
    const size_t m = b.size();
    if (n == 0) return m;
    if (m == 0) return n;

    std::vector<size_t> prev(m + 1);
    std::vector<size_t> curr(m + 1);
    for (size_t j = 0; j <= m; ++j) prev[j] = j;
    for (size_t i = 1; i <= n; ++i) {
        curr[0] = i;
        for (size_t j = 1; j <= m; ++j) {
            const size_t cost = (a[i - 1] == b[j - 1]) ? 0u : 1u;
            curr[j] = std::min({prev[j] + 1u, curr[j - 1] + 1u, prev[j - 1] + cost});
        }
        prev.swap(curr);
    }
    return prev[m];
}

static std::string recovery_path_filename(const std::string& path) {
    return fs::path(path).filename().string();
}

static std::string recovery_norm_file_id(const std::string& raw) {
    std::string name = recovery_norm_token(recovery_path_filename(raw));
    const size_t dot = name.find_last_of('.');
    if (dot != std::string::npos) {
        name = name.substr(0, dot);
    }
    return name;
}

static bool recovery_add_embedded_wordlist(const RecoveryEmbeddedWordlistView& view, RecoveryWordlist& out, std::string& err) {
    out = RecoveryWordlist{};
    out.id = view.id;
    out.file_name = view.file_name;
    out.path = view.file_name;
    out.name = view.file_name;
    out.external = false;
    out.words.reserve(view.count);
    out.words_norm.reserve(view.count);
    out.id_by_norm.reserve(view.count * 2u);

    for (std::size_t i = 0; i < view.count; ++i) {
        const char* word = view.words[i];
        if (word == nullptr || *word == '\0') continue;
        const int idx = static_cast<int>(out.words.size());
        const std::string_view word_view(word);
        out.words.emplace_back(word_view);
        const std::string norm = recovery_norm_token(std::string(word_view));
        out.words_norm.emplace_back(norm);
        if (out.id_by_norm.find(norm) == out.id_by_norm.end()) {
            out.id_by_norm.emplace(norm, idx);
        }
    }

    if (out.words.empty()) {
        err = "embedded wordlist is empty: " + out.file_name;
        return false;
    }
    return true;
}

static bool recovery_add_file_wordlist(const std::string& path, RecoveryWordlist& out, std::string& err) {
    std::ifstream fin(path.c_str(), std::ios::binary);
    if (!fin) {
        err = "failed to open external wordlist: " + path;
        return false;
    }

    out = RecoveryWordlist{};
    out.path = path;
    out.file_name = recovery_path_filename(path);
    out.id = recovery_norm_file_id(path);
    out.name = out.file_name;
    out.external = true;
    out.words.reserve(2048u);
    out.owned_words.reserve(2048u);
    out.words_norm.reserve(2048u);
    out.id_by_norm.reserve(4096u);

    std::string line;
    size_t line_no = 0;
    while (std::getline(fin, line)) {
        ++line_no;
        line = recovery_trim_spaces_copy(line);
        if (line.empty()) continue;
        if (line_no == 1 && line.size() >= 3u &&
            static_cast<unsigned char>(line[0]) == 0xEFu &&
            static_cast<unsigned char>(line[1]) == 0xBBu &&
            static_cast<unsigned char>(line[2]) == 0xBFu) {
            line.erase(0u, 3u);
            line = recovery_trim_spaces_copy(line);
            if (line.empty()) continue;
        }
        if (!line.empty() && line[0] == '#') continue;
        for (const unsigned char c : line) {
            if (std::isspace(c) != 0) {
                err = "invalid external wordlist line (contains spaces) at line " + std::to_string(line_no);
                return false;
            }
        }
        const int idx = static_cast<int>(out.words.size());
        out.owned_words.emplace_back(line);
        out.words.emplace_back(out.owned_words.back());
        const std::string norm = recovery_norm_token(out.owned_words.back());
        if (out.id_by_norm.find(norm) != out.id_by_norm.end()) {
            err = "duplicate word in external wordlist at line " + std::to_string(line_no);
            return false;
        }
        out.words_norm.emplace_back(norm);
        out.id_by_norm.emplace(norm, idx);
    }

    if (out.words.size() != 2048u) {
        err = "external wordlist must contain exactly 2048 words for BIP39 checksum mode";
        return false;
    }
    return true;
}

static int recovery_find_best_word_id(const RecoveryWordlist& wl, const std::string& token_norm, size_t* out_dist) {
    auto it = wl.id_by_norm.find(token_norm);
    if (it != wl.id_by_norm.end()) {
        if (out_dist) *out_dist = 0;
        return it->second;
    }

    size_t best_dist = std::numeric_limits<size_t>::max();
    int best_id = -1;
    for (size_t i = 0; i < wl.words_norm.size(); ++i) {
        const size_t dist = recovery_levenshtein(token_norm, wl.words_norm[i]);
        if (dist < best_dist) {
            best_dist = dist;
            best_id = static_cast<int>(i);
            if (best_dist == 1u) break;
        }
    }
    if (out_dist) *out_dist = best_dist;
    return best_id;
}

static const RecoveryWordlist* recovery_pick_wordlist(const std::vector<RecoveryWordlist>& lists, const std::vector<std::string>& tokens) {
    if (lists.empty()) return nullptr;
    if (lists.size() == 1u) return &lists[0];

    int best_exact = -1;
    size_t best_penalty = std::numeric_limits<size_t>::max();
    const RecoveryWordlist* best = &lists.front();

    for (const RecoveryWordlist& wl : lists) {
        int exact = 0;
        size_t penalty = 0;
        for (const std::string& token : tokens) {
            if (token == "*") continue;
            const std::string norm = recovery_norm_token(token);
            auto it = wl.id_by_norm.find(norm);
            if (it != wl.id_by_norm.end()) {
                ++exact;
                continue;
            }
            size_t dist = 0;
            (void)recovery_find_best_word_id(wl, norm, &dist);
            penalty += dist;
        }
        if (exact > best_exact || (exact == best_exact && penalty < best_penalty)) {
            best_exact = exact;
            best_penalty = penalty;
            best = &wl;
        }
    }
    return best;
}

struct RecoveryWordlistScore {
    int exact = 0;
    size_t penalty = 0u;
};

static int recovery_find_best_embedded_word_id(const RecoveryEmbeddedWordlistView& view,
                                               const std::string& token_norm,
                                               size_t* out_dist) {
    size_t best_dist = std::numeric_limits<size_t>::max();
    int best_id = -1;
    for (size_t i = 0; i < view.count; ++i) {
        const char* word = view.words[i];
        if (word == nullptr || *word == '\0') {
            continue;
        }
        const std::string norm = recovery_norm_token(std::string(word));
        if (norm == token_norm) {
            if (out_dist) *out_dist = 0u;
            return static_cast<int>(i);
        }
        const size_t dist = recovery_levenshtein(token_norm, norm);
        if (dist < best_dist) {
            best_dist = dist;
            best_id = static_cast<int>(i);
            if (best_dist == 1u) {
                break;
            }
        }
    }
    if (out_dist) *out_dist = best_dist;
    return best_id;
}

static RecoveryWordlistScore recovery_score_embedded_wordlist(const RecoveryEmbeddedWordlistView& view,
                                                              const std::vector<std::string>& tokens) {
    RecoveryWordlistScore score{};
    for (const std::string& token : tokens) {
        if (token == "*") {
            continue;
        }
        const std::string norm = recovery_norm_token(token);
        size_t dist = 0u;
        (void)recovery_find_best_embedded_word_id(view, norm, &dist);
        if (dist == 0u) {
            ++score.exact;
        } else {
            score.penalty += dist;
        }
    }
    return score;
}

static bool recovery_select_embedded_wordlist_indices(const std::vector<RecoveryTemplateInput>& templates,
                                                      std::vector<size_t>& out_indices) {
    out_indices.clear();
    std::unordered_set<size_t> unique_indices;

    for (const RecoveryTemplateInput& tmpl : templates) {
        const std::vector<std::string> tokens = recovery_split_tokens(tmpl.phrase);
        if (tokens.empty()) {
            continue;
        }

        const size_t non_star_tokens = std::count_if(tokens.begin(), tokens.end(), [](const std::string& token) {
            return token != "*";
        });
        int best_exact = -1;
        size_t best_penalty = std::numeric_limits<size_t>::max();
        std::vector<size_t> best_matches;

        for (size_t index = 0; index < kRecoveryEmbeddedWordlistsCount; ++index) {
            const RecoveryWordlistScore score = recovery_score_embedded_wordlist(kRecoveryEmbeddedWordlists[index], tokens);
            if (score.exact > best_exact || (score.exact == best_exact && score.penalty < best_penalty)) {
                best_exact = score.exact;
                best_penalty = score.penalty;
                best_matches.assign(1u, index);
            } else if (score.exact == best_exact && score.penalty == best_penalty) {
                best_matches.emplace_back(index);
            }
        }

        if (best_matches.empty()) {
            return false;
        }
        if (best_matches.size() > 2u) {
            return false;
        }
        if (non_star_tokens > 0u) {
            if (best_exact <= 0) {
                return false;
            }
            if ((static_cast<size_t>(best_exact) + 2u) < non_star_tokens) {
                return false;
            }
        }

        for (const size_t index : best_matches) {
            if (unique_indices.insert(index).second) {
                out_indices.emplace_back(index);
            }
        }
    }

    return !out_indices.empty();
}

static std::string recovery_join_tokens(const std::vector<std::string>& tokens) {
    std::ostringstream oss;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i) oss << ' ';
        oss << tokens[i];
    }
    return oss.str();
}

static bool recovery_prepare_task(const RecoveryTemplateInput& in, const std::vector<RecoveryWordlist>& lists, RecoveryPreparedTask& out, std::string& err) {
    std::vector<std::string> tokens = recovery_split_tokens(in.phrase);
    if (tokens.empty()) {
        err = "empty phrase";
        return false;
    }

    size_t added_stars = 0;
    while (tokens.size() < 3u || (tokens.size() % 3u) != 0u) {
        tokens.emplace_back("*");
        ++added_stars;
    }
    if (tokens.size() > 48u) {
        err = "word count is greater than 48 after normalization";
        return false;
    }

    const RecoveryWordlist* wl = recovery_pick_wordlist(lists, tokens);
    if (wl == nullptr) {
        err = "no wordlists available";
        return false;
    }

    out = RecoveryPreparedTask{};
    out.source = in.source;
    out.line_no = in.line_no;
    out.wordlist = wl;
    out.added_stars = added_stars;
    out.ids.assign(tokens.size(), -1);

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i] == "*") {
            out.missing_positions.emplace_back(static_cast<int>(i));
            continue;
        }
        const std::string norm = recovery_norm_token(tokens[i]);
        size_t dist = 0;
        const int best_id = recovery_find_best_word_id(*wl, norm, &dist);
        if (best_id < 0 || static_cast<size_t>(best_id) >= wl->words.size()) {
            err = "failed to find replacement for token: " + tokens[i];
            return false;
        }
        out.ids[i] = best_id;
        if (dist != 0 || wl->words_norm[best_id] != norm) {
            out.replacements.emplace_back(tokens[i], wl->words[best_id]);
            tokens[i] = wl->words[best_id];
        }
    }

    out.normalized_phrase = recovery_join_tokens(tokens);
    return true;
}

static bool bip39_checksum_valid(const std::vector<int>& ids) {
    const int n = static_cast<int>(ids.size());
    if (n <= 0 || (n % 3) != 0) return false;
    const int total_bits = n * 11;
    const int ent_bits = (total_bits * 32) / 33;
    const int cs_bits = total_bits - ent_bits;
    const int bits_bytes = (total_bits + 7) >> 3;
    const int ent_bytes = (ent_bits + 7) >> 3;

    std::vector<uint8_t> bits(static_cast<size_t>(bits_bytes), 0u);
    std::vector<uint8_t> entropy(static_cast<size_t>(ent_bytes), 0u);
    uint8_t digest[32] = {0};

    int bitpos = 0;
    for (int value : ids) {
        for (int bit = 10; bit >= 0; --bit) {
            const int current = (value >> bit) & 1;
            bits[static_cast<size_t>(bitpos >> 3)] |= static_cast<uint8_t>(current << (7 - (bitpos & 7)));
            ++bitpos;
        }
    }

    for (int i = 0; i < ent_bytes; ++i) {
        entropy[static_cast<size_t>(i)] = bits[static_cast<size_t>(i)];
    }
    if ((ent_bits & 7) != 0 && !entropy.empty()) {
        entropy.back() &= static_cast<uint8_t>(0xFFu << (8 - (ent_bits & 7)));
    }
    sha256(entropy.data(), entropy.size(), digest);

    for (int i = 0; i < cs_bits; ++i) {
        const int phrase_bit_pos = ent_bits + i;
        const uint8_t phrase_bit = (bits[static_cast<size_t>(phrase_bit_pos >> 3)] >> (7 - (phrase_bit_pos & 7))) & 1u;
        const uint8_t digest_bit = (digest[static_cast<size_t>(i >> 3)] >> (7 - (i & 7))) & 1u;
        if (phrase_bit != digest_bit) return false;
    }
    return true;
}

static bool parse_hash_target_argument(const char* arg, std::vector<uint8_t>& out_bytes, std::string& out_hex, std::string& err) {
    if (arg == nullptr) {
        err = "value is missing";
        return false;
    }
    std::string s(arg);
    if (s.size() >= 2u && s[0] == '0' && ((s[1] | 0x20) == 'x')) s.erase(0, 2);
    if (s.empty() || (s.size() & 1u) != 0u || s.size() < 8u || s.size() > 40u) {
        err = "expects 4..20 bytes (8..40 hex chars)";
        return false;
    }
    out_bytes.clear();
    out_bytes.reserve(s.size() / 2u);
    for (size_t i = 0; i < s.size(); i += 2u) {
        const std::string part = s.substr(i, 2u);
        char* end = nullptr;
        const long v = std::strtol(part.c_str(), &end, 16);
        if (end == part.c_str() || *end != '\0') {
            err = "contains non-hex characters";
            return false;
        }
        out_bytes.emplace_back(static_cast<uint8_t>(v));
    }
    out_hex = s;
    std::transform(out_hex.begin(), out_hex.end(), out_hex.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return true;
}

template <typename T>
static bool parse_list_or_ranges(const std::string& input, std::vector<T>& out, const bool clear_out = false) {
    if (clear_out) out.clear();
    size_t token_begin = 0;
    while (token_begin <= input.size()) {
        const size_t comma = input.find(',', token_begin);
        const size_t token_end = (comma == std::string::npos) ? input.size() : comma;
        if (token_end > token_begin) {
            const std::string token = input.substr(token_begin, token_end - token_begin);
            const size_t dash = token.find('-');
            if (dash != std::string::npos) {
                const int start = std::stoi(token.substr(0, dash));
                const int end = std::stoi(token.substr(dash + 1));
                for (int value = start; value <= end; ++value) out.emplace_back(static_cast<T>(value));
            } else {
                out.emplace_back(static_cast<T>(std::stoi(token)));
            }
        }
        if (comma == std::string::npos) break;
        token_begin = comma + 1;
    }
    return true;
}

static std::vector<char> pack_wordlist_words(const RecoveryWordlist& wordlist);
static bool pack_candidate_ids(const RecoveryPreparedTask& task, const std::vector<std::string>& candidates, std::vector<uint16_t>& out_ids, std::string& err);
static std::vector<fs::path> recovery_packaged_resource_locations(std::string_view file_name);

static inline void recovery_u64_add_saturating(uint64_t& acc, const uint64_t delta) {
    const uint64_t max_v = std::numeric_limits<uint64_t>::max();
    if (acc > (max_v - delta)) {
        acc = max_v;
        return;
    }
    acc += delta;
}

static uint64_t recovery_u64_mul_saturating(const uint64_t lhs, const uint64_t rhs) {
    if (lhs == 0u || rhs == 0u) {
        return 0u;
    }
    const uint64_t max_v = std::numeric_limits<uint64_t>::max();
    if (lhs > (max_v / rhs)) {
        return max_v;
    }
    return lhs * rhs;
}

static uint64_t recovery_benchmark_checksum_batch_cap() {
    static const uint64_t cap = []() -> uint64_t {
        const char* raw = std::getenv("CMR_BENCH_MAX_CHECKSUM_BATCHES");
        if (raw == nullptr || *raw == '\0') {
            return 0ull;
        }
        char* end = nullptr;
        errno = 0;
        const unsigned long long parsed = std::strtoull(raw, &end, 10);
        if (end == raw || *end != '\0' || errno == ERANGE || parsed == 0ull) {
            return 0ull;
        }
        return static_cast<uint64_t>(parsed);
    }();
    return cap;
}

static int64_t recovery_runtime_completion_timeout_ns() {
    static const int64_t timeout_ns = []() -> int64_t {
        const char* raw = std::getenv("CMR_RUNTIME_COMPLETION_TIMEOUT_MS");
        if (raw == nullptr || *raw == '\0') {
            return 60ll * 60ll * 1000ll * 1000ll * 1000ll;
        }
        char* end = nullptr;
        errno = 0;
        const unsigned long long parsed = std::strtoull(raw, &end, 10);
        if (end == raw || *end != '\0' || errno == ERANGE || parsed == 0ull) {
            return 60ll * 60ll * 1000ll * 1000ll * 1000ll;
        }
        if (parsed >= static_cast<unsigned long long>(std::numeric_limits<int64_t>::max() / 1000000ll)) {
            return std::numeric_limits<int64_t>::max();
        }
        return static_cast<int64_t>(parsed) * 1000000ll;
    }();
    return timeout_ns;
}

static NSUInteger recovery_runtime_worker_cap_override(const char* env_name, const NSUInteger fallback) {
    if (env_name == nullptr || *env_name == '\0') {
        return fallback;
    }

    const char* raw = std::getenv(env_name);
    if (raw == nullptr || *raw == '\0') {
        return fallback;
    }

    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(raw, &end, 10);
    if (end == raw || *end != '\0' || errno == ERANGE || parsed == 0ull) {
        return fallback;
    }

    const unsigned long long max_groups = static_cast<unsigned long long>(std::numeric_limits<NSUInteger>::max());
    return static_cast<NSUInteger>(std::min<unsigned long long>(parsed, max_groups));
}

static uint32_t recovery_runtime_capacity_cap_override(const char* env_name, const uint32_t fallback) {
    if (env_name == nullptr || *env_name == '\0') {
        return fallback;
    }

    const char* raw = std::getenv(env_name);
    if (raw == nullptr || *raw == '\0') {
        return fallback;
    }

    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(raw, &end, 10);
    if (end == raw || *end != '\0' || errno == ERANGE || parsed == 0ull) {
        return fallback;
    }

    const unsigned long long max_capacity = static_cast<unsigned long long>(std::numeric_limits<uint32_t>::max());
    return static_cast<uint32_t>(std::min<unsigned long long>(parsed, max_capacity));
}

static uint32_t recovery_runtime_checksum_candidate_multiplier() {
    static const uint32_t multiplier = []() -> uint32_t {
        const char* raw = std::getenv("CMR_RUNTIME_CHECKSUM_CANDIDATE_MULTIPLIER");
        if (raw == nullptr || *raw == '\0') {
            return kRecoveryDefaultChecksumCandidateMultiplier;
        }

        char* end = nullptr;
        errno = 0;
        const unsigned long long parsed = std::strtoull(raw, &end, 10);
        if (end == raw || *end != '\0' || errno == ERANGE || parsed == 0ull) {
            return kRecoveryDefaultChecksumCandidateMultiplier;
        }

        return static_cast<uint32_t>(std::clamp<unsigned long long>(parsed, 1ull, 64ull));
    }();
    return multiplier;
}

static bool recovery_experimental_persistent_runtime_enabled() {
    const char* raw = std::getenv("CMR_EXPERIMENTAL_PERSISTENT_RUNTIME");
    if (raw == nullptr || *raw == '\0') {
        return false;
    }
    return std::strcmp(raw, "1") == 0 ||
           std::strcmp(raw, "true") == 0 ||
           std::strcmp(raw, "TRUE") == 0 ||
           std::strcmp(raw, "yes") == 0 ||
           std::strcmp(raw, "YES") == 0;
}

static bool recovery_wait_for_command_buffer_terminal_status(id<MTLCommandBuffer> command_buffer,
                                                             const int64_t timeout_ns) {
    if (command_buffer == nil) {
        return false;
    }

    const auto timeout = std::chrono::nanoseconds(std::max<int64_t>(timeout_ns, 1ll));
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        switch (command_buffer.status) {
        case MTLCommandBufferStatusCompleted:
        case MTLCommandBufferStatusError:
            return true;
        default:
            break;
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static uint64_t recovery_checksum_total_candidates(const size_t missing_count) {
    if (missing_count == 0u) {
        return 1u;
    }

    uint64_t total_candidates = 1u;
    for (size_t index = 0u; index < missing_count; ++index) {
        total_candidates = recovery_u64_mul_saturating(total_candidates, 2048u);
        if (total_candidates == std::numeric_limits<uint64_t>::max()) {
            break;
        }
    }
    return total_candidates;
}

static bool recovery_checksum_cursor_drained(const ChecksumCursorState* state) {
    return state == nullptr || state->exhausted != 0u;
}

static uint32_t recovery_checksum_divisor_for_words_count(const size_t words_count) {
    switch (words_count) {
    case 12u: return 16u;
    case 15u: return 32u;
    case 18u: return 64u;
    case 21u: return 128u;
    case 24u: return 256u;
    default:  return 16u;
    }
}

static uint64_t recovery_checksum_tested_candidates(const size_t missing_count,
                                                    const uint64_t batch_candidate_capacity,
                                                    const uint64_t batch_limit) {
    const uint64_t total_candidates = recovery_checksum_total_candidates(missing_count);

    if (batch_limit == 0u) {
        return total_candidates;
    }

    const uint64_t sampled_candidates =
        recovery_u64_mul_saturating(std::max<uint64_t>(batch_candidate_capacity, 1u), batch_limit);
    return std::min(total_candidates, sampled_candidates);
}

static uint64_t recovery_checksum_total_batches(const size_t missing_count,
                                                const uint64_t batch_candidate_capacity,
                                                const uint64_t batch_limit) {
    const uint64_t candidate_capacity = std::max<uint64_t>(batch_candidate_capacity, 1u);
    const uint64_t tested_candidates =
        recovery_checksum_tested_candidates(missing_count, candidate_capacity, batch_limit);
    return (tested_candidates + candidate_capacity - 1ull) / candidate_capacity;
}

static bool recovery_checksum_cursor_advance_host(ChecksumCursorState& cursor, const uint64_t amount) {
    if (cursor.missing_count == 0u) {
        cursor.exhausted = 1u;
        return true;
    }

    uint64_t carry = amount;
    for (cmr_u32 index = 0u; index < cursor.missing_count && index < RECOVERY_MAX_WORDS; ++index) {
        const uint64_t digit_add = carry & 0x7FFull;
        carry >>= 11u;

        uint64_t value = static_cast<uint64_t>(cursor.digit_cursor[index] & 0x07FFu) + digit_add;
        if (value >= 2048ull) {
            value -= 2048ull;
            carry += 1ull;
        }
        cursor.digit_cursor[index] = static_cast<cmr_u16>(value);
        if (carry == 0ull) {
            return false;
        }
    }

    cursor.exhausted = carry != 0ull ? 1u : 0u;
    return cursor.exhausted != 0u;
}

static uint64_t recovery_checksum_cursor_prepare_next_batch_host(ChecksumCursorState& cursor,
                                                                 uint64_t& remaining_candidates) {
    if (cursor.exhausted != 0u || remaining_candidates == 0ull) {
        cursor.exhausted = 1u;
        return 0ull;
    }

    const uint64_t batch_candidate_capacity = std::max<uint64_t>(cursor.batch_candidate_capacity, 1ull);
    const uint64_t range_count = std::min<uint64_t>(batch_candidate_capacity, remaining_candidates);
    remaining_candidates -= range_count;
    (void)recovery_checksum_cursor_advance_host(cursor, range_count);
    if (remaining_candidates == 0ull) {
        cursor.exhausted = 1u;
    }
    return range_count;
}

static cmr_u32 recovery_ed25519_derivation_type_from_engine(const std::string& engine) {
    if (engine == "slip0010-ed25519") {
        return RESULT_DERIVATION_SLIP0010_ED25519;
    }
    if (engine == "ed25519-bip32-test") {
        return RESULT_DERIVATION_ED25519_BIP32_TEST;
    }
    return 0u;
}

static cmr_u32 recovery_primary_ed25519_coin_type(const std::string& coin_types) {
    for (const char coin : coin_types) {
        switch (coin) {
        case 'S': return 0x60u;
        case 't': return 0x85u;
        case 'T': return 0x80u;
        default: break;
        }
    }
    return 0x60u;
}

static cmr_u32 recovery_ed25519_target_flags_for_coin_types(const std::string& coin_types, const bool emit_all) {
    cmr_u32 flags = emit_all ? RECOVERY_ED25519_TARGET_FLAG_EMIT_ALL : 0u;
    if (coin_types.find('S') != std::string::npos) {
        flags |= RECOVERY_ED25519_TARGET_FLAG_SOLANA;
    }
    if (coin_types.find('T') != std::string::npos) {
        flags |= RECOVERY_ED25519_TARGET_FLAG_TON_ALL;
    } else if (coin_types.find('t') != std::string::npos) {
        flags |= RECOVERY_ED25519_TARGET_FLAG_TON_SHORT;
    }
    return flags;
}

static cmr_u32 recovery_ed25519_outputs_per_candidate(const std::string& coin_types) {
    cmr_u32 total = 0u;
    if (coin_types.find('S') != std::string::npos) {
        total += 1u;
    }
    if (coin_types.find('T') != std::string::npos) {
        total += 10u;
    } else if (coin_types.find('t') != std::string::npos) {
        total += 4u;
    }
    return total == 0u ? 1u : total;
}

static cmr_u32 recovery_secp_target_mask_for_coin_types(const std::string& coin_types) {
    cmr_u32 mask = 0u;
    if (coin_types.find('c') != std::string::npos) {
        mask |= RecoverySecpTargetBitCompressed;
    }
    if (coin_types.find('u') != std::string::npos) {
        mask |= RecoverySecpTargetBitUncompressed;
    }
    if (coin_types.find('s') != std::string::npos) {
        mask |= RecoverySecpTargetBitSegwit;
    }
    if (coin_types.find('r') != std::string::npos) {
        mask |= RecoverySecpTargetBitTaproot;
    }
    if (coin_types.find('x') != std::string::npos) {
        mask |= RecoverySecpTargetBitXPoint;
    }
    if (coin_types.find('e') != std::string::npos) {
        mask |= RecoverySecpTargetBitEth;
    }
    return mask;
}

static cmr_u32 recovery_secp_outputs_per_candidate(const std::string& coin_types) {
    cmr_u32 total = 0u;
    if (coin_types.find('c') != std::string::npos) ++total;
    if (coin_types.find('u') != std::string::npos) ++total;
    if (coin_types.find('s') != std::string::npos) ++total;
    if (coin_types.find('r') != std::string::npos) ++total;
    if (coin_types.find('x') != std::string::npos) ++total;
    if (coin_types.find('e') != std::string::npos) ++total;
    return total == 0u ? 1u : total;
}

static std::string recovery_filter_coin_types(const std::string& coin_types, const char* allowed) {
    std::string out;
    for (const char coin : coin_types) {
        if (std::strchr(allowed, coin) != nullptr) {
            out.push_back(coin);
        }
    }
    return out;
}

static bool recovery_prepare_execution_plan(const AppConfig& config,
                                            RecoveryExecutionPlan& out,
                                            std::string& err) {
    out = {};
    const std::vector<std::string> engines =
        recovery_derivation::engines_for_policy(config.derivation_policy, config.coin_types);
    if (engines.empty()) {
        err = "no derivation engines selected";
        return false;
    }

    out.secp_coin_types = recovery_filter_coin_types(config.coin_types, "cusrxe");
    out.ed_coin_types = recovery_filter_coin_types(config.coin_types, "StT");
    out.need_secp_targets = !out.secp_coin_types.empty();
    out.need_ed_targets = !out.ed_coin_types.empty();
    out.secp_outputs_per_candidate = recovery_secp_outputs_per_candidate(out.secp_coin_types);
    out.ed_outputs_per_candidate = recovery_ed25519_outputs_per_candidate(out.ed_coin_types);

    out.engines.reserve(engines.size());
    for (const std::string& engine : engines) {
        if (engine == "bip32-secp256k1") {
            out.engines.push_back({RecoveryEngineKind::Secp, RESULT_DERIVATION_BIP32_SECP256K1});
            out.need_secp_derive = true;
            continue;
        }
        if (engine == "slip0010-ed25519") {
            out.engines.push_back({RecoveryEngineKind::Slip0010Ed25519, RESULT_DERIVATION_SLIP0010_ED25519});
            out.need_ed_derive = true;
            continue;
        }
        if (engine == "ed25519-bip32-test") {
            out.engines.push_back({RecoveryEngineKind::Ed25519Bip32Test, RESULT_DERIVATION_ED25519_BIP32_TEST});
            out.need_ed_derive = true;
            continue;
        }
        err = "unsupported derivation engine: " + engine;
        return false;
    }

    return true;
}

static uint64_t recovery_hash_checks_per_candidate(const RecoveryExecutionPlan& plan,
                                                   const size_t derivation_count) {
    const uint64_t target_checks =
        static_cast<uint64_t>(plan.secp_outputs_per_candidate) +
        static_cast<uint64_t>(plan.ed_outputs_per_candidate);
    if (derivation_count == 0u || target_checks == 0ull) {
        return 0ull;
    }
    return static_cast<uint64_t>(derivation_count) * target_checks;
}

static void recovery_speed_thread_func(RecoveryLiveStatusState* state) {
    using clock_type = std::chrono::steady_clock;
    uint64_t last_seen = state->tested_total.load(std::memory_order_relaxed);
    auto last_tick = clock_type::now();

    while (!state->stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        if (state->stop.load(std::memory_order_relaxed)) {
            break;
        }

        const auto now = clock_type::now();
        const uint64_t current = state->tested_total.load(std::memory_order_relaxed);
        const uint64_t checksum_valid = state->checksum_valid_total.load(std::memory_order_relaxed);
        const uint32_t found = state->found_total.load(std::memory_order_relaxed);
        if (current == 0ull && last_seen == 0ull && checksum_valid == 0ull && found == 0u) {
            last_tick = now;
            continue;
        }
        const std::chrono::duration<double> dt = now - last_tick;
        const double elapsed = dt.count();
        if (elapsed <= 0.0) {
            continue;
        }

        const double speed = static_cast<double>(current - last_seen) / elapsed;
        std::ostringstream line;
        line << "[!] Recovery speed: " << std::fixed << std::setprecision(2)
             << (speed / 1000000.0) << " M candidates/s";
        if (state->hash_checks_per_candidate != 0ull) {
            const double hash_speed = speed * static_cast<double>(state->hash_checks_per_candidate);
            line << " | " << (hash_speed / 1000000.0) << " M hashes/s";
        }
        line << " | tested=" << current
             << " | checksum-valid=" << checksum_valid
             << " | found=" << found;
        recovery_console_write_status_line(line.str());

        last_seen = current;
        last_tick = now;
    }
}

static RecoveryFilterKernelMode recovery_select_filter_kernel_mode(const bool filters_requested) {
    if (!filters_requested) {
        return RecoveryFilterKernelMode::None;
    }
    const RecoveryFilterSet& filter_set = recovery_filter_set();
    const int active_bloom_count = std::max(filter_set.bloom_count, 0);
    const int active_xor_count = std::clamp(filter_set.xor_count, 0, static_cast<int>(RECOVERY_ED25519_MAX_XOR_FILTERS));
    if (active_bloom_count > 0 && active_xor_count == 0) {
        return RecoveryFilterKernelMode::BloomOnly;
    }
    if (active_bloom_count == 0 && active_xor_count == 1) {
        return RecoveryFilterKernelMode::XorSingle;
    }
    return RecoveryFilterKernelMode::Full;
}

static bool recovery_prepare_derivations(const std::vector<std::string>& inputs,
                                         std::vector<RecoveryPreparedDerivation>& out,
                                         std::string& err) {
    out.clear();
    err.clear();
    out.reserve(inputs.size());
    for (const std::string& input : inputs) {
        RecoveryPreparedDerivation prepared;
        prepared.text = input;
        if (!recovery_derivation::parse_path(input, prepared.path, err)) {
            return false;
        }
        out.emplace_back(std::move(prepared));
    }
    return true;
}

class MetalRecoveryBackend final {
public:
    MetalRecoveryBackend(id<MTLDevice> device,
                         id<MTLCommandQueue> command_queue,
                         id<MTLComputePipelineState> checksum_prepare_pipeline,
                         id<MTLComputePipelineState> checksum_hit_pipeline,
                         id<MTLComputePipelineState> checksum_hit_12_pipeline,
                         id<MTLComputePipelineState> checksum_hit_15_pipeline,
                         id<MTLComputePipelineState> checksum_hit_18_pipeline,
                         id<MTLComputePipelineState> checksum_hit_21_pipeline,
                         id<MTLComputePipelineState> checksum_hit_24_pipeline,
                         id<MTLComputePipelineState> master_seed_pipeline,
                         id<MTLComputePipelineState> secp_master_seed_pipeline,
                         id<MTLComputePipelineState> indirect_dispatch_prepare_pipeline,
                         id<MTLComputePipelineState> ed25519_derive_pipeline,
                         id<MTLComputePipelineState> secp_derive_pipeline,
                         id<MTLComputePipelineState> secp_to_ed25519_pipeline,
                         id<MTLComputePipelineState> ed25519_to_secp_pipeline,
                         id<MTLComputePipelineState> ed25519_eval_pipeline,
                         id<MTLComputePipelineState> secp_eval_pipeline,
                         id<MTLComputePipelineState> secp_eval_master_pipeline,
                         id<MTLComputePipelineState> secp_eval_master_compressed_pipeline,
                         id<MTLComputePipelineState> secp_eval_master_compressed_noreuse_pipeline,
                         id<MTLComputePipelineState> runtime_checksum_schedule_pipeline,
                         id<MTLComputePipelineState> runtime_checksum_consume_pipeline,
                         id<MTLComputePipelineState> runtime_seed_produce_pipeline,
                         id<MTLComputePipelineState> runtime_secp_consume_pipeline,
                         id<MTLComputePipelineState> runtime_ed_consume_pipeline,
                         id<MTLComputePipelineState> runtime_ed_promote_consume_pipeline,
                         id<MTLComputePipelineState> runtime_secp_promote_consume_pipeline,
                         RecoveryExecutionPlan execution_plan,
                         RecoveryFilterKernelMode filter_kernel_mode,
                         bool filters_requested,
                         unsigned int thread_count,
                         unsigned int block_count,
                         uint32_t stage_capacity)
        : device_(device),
          command_queue_(command_queue),
          checksum_prepare_pipeline_(checksum_prepare_pipeline),
          checksum_hit_pipeline_(checksum_hit_pipeline),
          checksum_hit_12_pipeline_(checksum_hit_12_pipeline),
          checksum_hit_15_pipeline_(checksum_hit_15_pipeline),
          checksum_hit_18_pipeline_(checksum_hit_18_pipeline),
          checksum_hit_21_pipeline_(checksum_hit_21_pipeline),
          checksum_hit_24_pipeline_(checksum_hit_24_pipeline),
          master_seed_pipeline_(master_seed_pipeline),
          secp_master_seed_pipeline_(secp_master_seed_pipeline),
          indirect_dispatch_prepare_pipeline_(indirect_dispatch_prepare_pipeline),
          ed25519_derive_pipeline_(ed25519_derive_pipeline),
          ed25519_eval_pipeline_(ed25519_eval_pipeline),
          secp_derive_pipeline_(secp_derive_pipeline),
          secp_to_ed25519_pipeline_(secp_to_ed25519_pipeline),
          ed25519_to_secp_pipeline_(ed25519_to_secp_pipeline),
          secp_eval_pipeline_(secp_eval_pipeline),
          secp_eval_master_pipeline_(secp_eval_master_pipeline),
          secp_eval_master_compressed_pipeline_(secp_eval_master_compressed_pipeline),
          secp_eval_master_compressed_noreuse_pipeline_(secp_eval_master_compressed_noreuse_pipeline),
          runtime_checksum_schedule_pipeline_(runtime_checksum_schedule_pipeline),
          runtime_checksum_consume_pipeline_(runtime_checksum_consume_pipeline),
          runtime_seed_produce_pipeline_(runtime_seed_produce_pipeline),
          runtime_secp_consume_pipeline_(runtime_secp_consume_pipeline),
          runtime_ed_consume_pipeline_(runtime_ed_consume_pipeline),
          runtime_ed_promote_consume_pipeline_(runtime_ed_promote_consume_pipeline),
          runtime_secp_promote_consume_pipeline_(runtime_secp_promote_consume_pipeline),
          execution_plan_(std::move(execution_plan)),
          filter_kernel_mode_(filter_kernel_mode),
          filters_requested_(filters_requested),
          thread_count_(normalize_requested_threads(thread_count ? thread_count : kRecoveryDefaultDispatchThreads)),
          block_count_(block_count),
          stage_capacity_(std::max<uint32_t>(stage_capacity, 4096u)) {
        runtime_checksum_schedule_queue_ = [device_ newCommandQueue];
        runtime_checksum_queue_ = [device_ newCommandQueue];
        runtime_seed_queue_ = [device_ newCommandQueue];
        runtime_secp_queue_ = [device_ newCommandQueue];
        runtime_ed_queue_ = [device_ newCommandQueue];
        runtime_ed_promote_queue_ = [device_ newCommandQueue];
        runtime_secp_promote_queue_ = [device_ newCommandQueue];
        if (runtime_checksum_schedule_queue_ == nil) runtime_checksum_schedule_queue_ = command_queue_;
        if (runtime_checksum_queue_ == nil) runtime_checksum_queue_ = command_queue_;
        if (runtime_seed_queue_ == nil) runtime_seed_queue_ = command_queue_;
        if (runtime_secp_queue_ == nil) runtime_secp_queue_ = command_queue_;
        if (runtime_ed_queue_ == nil) runtime_ed_queue_ = command_queue_;
        if (runtime_ed_promote_queue_ == nil) runtime_ed_promote_queue_ = command_queue_;
        if (runtime_secp_promote_queue_ == nil) runtime_secp_promote_queue_ = command_queue_;
    }

    std::string name() const { return "metal"; }

    void set_live_status(RecoveryLiveStatusState* live_status) {
        live_status_ = live_status;
    }

    bool process_task(const RecoveryPreparedTask& task,
                      const std::vector<RecoveryPreparedDerivation>& derivations,
                      const AppConfig& config,
                      const std::vector<std::string>& passphrases,
                      std::vector<std::vector<FoundRecord>>& out_by_passphrase,
                      uint64_t& tested,
                      std::string& err) {
        tested = 0;
        out_by_passphrase.assign(passphrases.size(), {});
        err.clear();

        const bool use_experimental_persistent_runtime = recovery_experimental_persistent_runtime_enabled();
        if (device_ == nil ||
            checksum_prepare_pipeline_ == nil ||
            checksum_hit_pipeline_ == nil ||
            master_seed_pipeline_ == nil) {
            err = "Metal bounded batch pipelines unavailable";
            return false;
        }
        if (use_experimental_persistent_runtime &&
            (runtime_checksum_schedule_pipeline_ == nil ||
             runtime_checksum_consume_pipeline_ == nil ||
             runtime_seed_produce_pipeline_ == nil)) {
            err = "Metal experimental persistent runtime pipelines unavailable";
            return false;
        }
        if (passphrases.empty()) {
            return true;
        }

        std::array<uint16_t, RECOVERY_MAX_WORDS> base_ids{};
        for (size_t i = 0; i < task.ids.size(); ++i) {
            const int id = task.ids[i];
            if (id >= 2048) {
                err = "invalid recovery base word id";
                return false;
            }
            base_ids[i] = static_cast<uint16_t>(id < 0 ? 0 : id);
        }

        const size_t derivation_count = std::max<size_t>(derivations.size(), 1u);
        const bool use_secp_fast_lane_for_capacity =
            !use_experimental_persistent_runtime && should_use_bounded_secp_fast_lane();
        const uint32_t computed_tile_seed_capacity = std::max<uint32_t>(
            1u,
            use_secp_fast_lane_for_capacity
                ? stage_capacity_
                : std::min<uint32_t>(stage_capacity_,
                                     static_cast<uint32_t>(std::max<size_t>(
                                         1u,
                                         kRecoveryMaxPairCapacity / derivation_count))));
        const uint32_t default_tile_seed_capacity =
            use_experimental_persistent_runtime ? 512u : computed_tile_seed_capacity;
        const uint32_t tile_seed_capacity = std::clamp<uint32_t>(
            std::min<uint32_t>(
                computed_tile_seed_capacity,
                recovery_runtime_capacity_cap_override("CMR_RUNTIME_TILE_SEED_CAP",
                                                       default_tile_seed_capacity)),
            1u,
            computed_tile_seed_capacity);
        const uint64_t checksum_density_cursor_capacity =
            recovery_u64_mul_saturating(tile_seed_capacity, recovery_checksum_divisor_for_words_count(task.ids.size()));
        const uint32_t computed_cursor_tile_capacity = static_cast<uint32_t>(std::max<uint64_t>(
            tile_seed_capacity,
            std::min<uint64_t>(checksum_density_cursor_capacity, kRecoveryMaxChecksumBatchCandidates)));
        const uint32_t default_cursor_tile_capacity =
            use_experimental_persistent_runtime ? 512u : computed_cursor_tile_capacity;
        const uint32_t cursor_override_request =
            recovery_runtime_capacity_cap_override("CMR_RUNTIME_CURSOR_TILE_CAP",
                                                   default_cursor_tile_capacity);
        const uint32_t cursor_override_cap =
            std::max<uint32_t>(tile_seed_capacity, cursor_override_request);
        const uint32_t cursor_tile_capacity = std::clamp<uint32_t>(
            std::min<uint32_t>(computed_cursor_tile_capacity, cursor_override_cap),
            tile_seed_capacity,
            computed_cursor_tile_capacity);
        const uint64_t benchmark_batch_cap = recovery_benchmark_checksum_batch_cap();
        const uint64_t tested_candidates =
            recovery_checksum_tested_candidates(task.missing_positions.size(), cursor_tile_capacity, benchmark_batch_cap);
        if (!ensure_dict_buffer(*task.wordlist, err)) {
            return false;
        }
        if ((execution_plan_.need_secp_derive || execution_plan_.need_secp_targets) && !ensure_secp_precompute_buffer(err)) {
            return false;
        }
        if (filter_kernel_mode_ == RecoveryFilterKernelMode::None) {
            RecoveryFilterParams params{};
            if (!ensure_shared_buffer(ed25519_filter_params_buffer_, sizeof(params), err)) {
                err = "failed to allocate Metal runtime filter params buffer";
                return false;
            }
            std::memcpy([ed25519_filter_params_buffer_ contents], &params, sizeof(params));
        } else if (!ensure_ed25519_filter_buffers(err)) {
            return false;
        }

        ChecksumTileBuffers checksum_tile_buffers;
        if (!prepare_checksum_tile_buffers(task,
                                           base_ids,
                                           task.missing_positions,
                                           tile_seed_capacity,
                                           checksum_tile_buffers,
                                           err)) {
            return false;
        }
        for (size_t passphrase_index = 0u; passphrase_index < passphrases.size(); ++passphrase_index) {
            const bool ok =
                use_experimental_persistent_runtime
                    ? run_unified_runtime_passphrase(task,
                                                     derivations,
                                                     config,
                                                     passphrases[passphrase_index],
                                                     static_cast<cmr_u32>(passphrase_index),
                                                     tile_seed_capacity,
                                                     cursor_tile_capacity,
                                                     benchmark_batch_cap,
                                                     checksum_tile_buffers,
                                                     out_by_passphrase[passphrase_index],
                                                     err)
                    : run_bounded_batch_passphrase(task,
                                                   derivations,
                                                   config,
                                                   passphrases[passphrase_index],
                                                   static_cast<cmr_u32>(passphrase_index),
                                                   tile_seed_capacity,
                                                   cursor_tile_capacity,
                                                   benchmark_batch_cap,
                                                   checksum_tile_buffers,
                                                   out_by_passphrase[passphrase_index],
                                                   err);
            if (!ok) {
                return false;
            }
        }

        if (use_experimental_persistent_runtime && live_status_ != nullptr) {
            live_status_->tested_total.fetch_add(tested_candidates, std::memory_order_relaxed);
        }
        tested = tested_candidates;
        return true;
    }

    enum class RecoveryRuntimeWorkerStage {
        ChecksumProduce,
        SeedProduce,
        SecpConsume,
        EdConsume,
        EdPromoteConsume,
        SecpPromoteConsume
    };

    struct ChecksumTileBuffers {
        id<MTLBuffer> base_ids_buffer = nil;
        id<MTLBuffer> missing_positions_buffer = nil;
        id<MTLBuffer> start_digits_buffer = nil;
        id<MTLBuffer> hits_buffer = nil;
        id<MTLBuffer> out_count_buffer = nil;
        id<MTLBuffer> params_buffer = nil;
    };

    struct SeedTileBuffers {
        id<MTLBuffer> master_seed_records_buffer = nil;
        id<MTLBuffer> seed_pass_buffer = nil;
        id<MTLBuffer> seed_params_buffer = nil;
    };

    struct SecpEngineTileBuffers {
        id<MTLBuffer> secp_programs_buffer = nil;
        id<MTLBuffer> secp_master_records_buffer = nil;
        id<MTLBuffer> secp_master_dispatch_buffer = nil;
        id<MTLBuffer> secp_stage_records_buffer = nil;
        id<MTLBuffer> secp_params_buffer = nil;
        id<MTLBuffer> secp_eval_dispatch_buffer = nil;
        id<MTLBuffer> ed25519_stage_records_buffer = nil;
        id<MTLBuffer> ed25519_stage_params_buffer = nil;
        id<MTLBuffer> ed25519_eval_params_buffer = nil;
    };

    struct EdEngineTileBuffers {
        id<MTLBuffer> ed25519_programs_buffer = nil;
        id<MTLBuffer> ed25519_stage_records_buffer = nil;
        id<MTLBuffer> ed25519_stage_params_buffer = nil;
        id<MTLBuffer> ed25519_eval_params_buffer = nil;
        id<MTLBuffer> secp_stage_records_buffer = nil;
        id<MTLBuffer> secp_params_buffer = nil;
    };

    bool prepare_checksum_tile_buffers(const RecoveryPreparedTask& task,
                                       const std::array<uint16_t, RECOVERY_MAX_WORDS>& base_ids,
                                       const std::vector<int>& missing_positions,
                                       const uint32_t out_capacity,
                                       ChecksumTileBuffers& tile_buffers,
                                       std::string& err) {
        ChecksumStageParams params{};
        params.words_count = static_cast<uint32_t>(task.ids.size());
        params.missing_count = static_cast<uint32_t>(missing_positions.size());
        params.range_start = 0ull;
        params.range_count = 0ull;
        params.out_capacity = out_capacity;
        params.flags = RECOVERY_RECORD_FLAG_CHECKSUM_VALID | RECOVERY_RECORD_FLAG_STAGE_READY;

        const size_t missing_positions_length = missing_positions.empty() ? sizeof(int32_t) : missing_positions.size() * sizeof(int32_t);
        const size_t records_length = static_cast<size_t>(out_capacity) * sizeof(ChecksumHitRecord);
        if (!ensure_shared_buffer(checksum_cursor_state_buffer_, sizeof(ChecksumCursorState), err) ||
            !ensure_shared_buffer(checksum_base_ids_buffer_, sizeof(base_ids), err) ||
            !ensure_shared_buffer(checksum_missing_positions_buffer_, missing_positions_length, err) ||
            !ensure_shared_buffer(checksum_start_digits_buffer_, sizeof(std::array<uint16_t, RECOVERY_MAX_WORDS>), err) ||
            !ensure_shared_buffer(checksum_hits_buffer_, records_length, err) ||
            !ensure_shared_buffer(checksum_out_count_buffer_, sizeof(uint32_t), err) ||
            !ensure_shared_buffer(checksum_params_buffer_, sizeof(params), err)) {
            err = "failed to allocate Metal checksum hit buffers";
            return false;
        }

        tile_buffers.base_ids_buffer = checksum_base_ids_buffer_;
        tile_buffers.missing_positions_buffer = checksum_missing_positions_buffer_;
        tile_buffers.start_digits_buffer = checksum_start_digits_buffer_;
        tile_buffers.hits_buffer = checksum_hits_buffer_;
        tile_buffers.out_count_buffer = checksum_out_count_buffer_;
        tile_buffers.params_buffer = checksum_params_buffer_;

        std::memcpy([tile_buffers.base_ids_buffer contents], base_ids.data(), sizeof(base_ids));
        if (missing_positions.empty()) {
            *reinterpret_cast<int32_t*>([tile_buffers.missing_positions_buffer contents]) = 0;
        } else {
            std::memcpy([tile_buffers.missing_positions_buffer contents], missing_positions.data(), missing_positions_length);
        }
        *reinterpret_cast<uint32_t*>([tile_buffers.out_count_buffer contents]) = 0u;
        std::memcpy([tile_buffers.params_buffer contents], &params, sizeof(params));
        return true;
    }

    bool prepare_seed_tile_buffers(const RecoveryPreparedTask& task,
                                   const std::string& passphrase,
                                   const uint64_t iterations,
                                   const uint32_t record_capacity,
                                   const SeedTileBuffers& seed_tile_buffers,
                                   std::string& err) {
        err.clear();
        if (record_capacity == 0u) {
            return true;
        }
        if (task.wordlist == nullptr || dict_buffer_ == nil) {
            err = "missing wordlist for Metal seed staging";
            return false;
        }
        if (seed_tile_buffers.master_seed_records_buffer == nil ||
            seed_tile_buffers.seed_pass_buffer == nil ||
            seed_tile_buffers.seed_params_buffer == nil) {
            err = "failed to allocate Metal seed staging buffers";
            return false;
        }

        const SeedBatchParams params{
            static_cast<uint32_t>(task.ids.size()),
            record_capacity,
            RECOVERY_DICT_WORD_STRIDE,
            static_cast<uint32_t>(passphrase.size()),
            record_capacity,
            0u,
            0u,
            iterations
        };

        auto* seed_pass_bytes = static_cast<char*>([seed_tile_buffers.seed_pass_buffer contents]);
        const size_t pass_length = passphrase.empty() ? 1u : passphrase.size();
        std::memset(seed_pass_bytes, 0, pass_length);
        if (!passphrase.empty()) {
            std::memcpy(seed_pass_bytes, passphrase.data(), passphrase.size());
        }
        std::memcpy([seed_tile_buffers.seed_params_buffer contents], &params, sizeof(params));
        return true;
    }

    bool prepare_secp_engine_tile_buffers(const std::vector<RecoveryPreparedDerivation>& derivations,
                                          const AppConfig& config,
                                          const cmr_u32 passphrase_index,
                                          const uint32_t seed_record_count,
                                          const SecpEngineTileBuffers& engine_tile_buffers,
                                          const std::string& secp_coin_types,
                                          const std::string& ed_coin_types,
                                          std::string& err) {
        err.clear();
        const bool want_secp_targets = !secp_coin_types.empty();
        const bool want_ed_targets = !ed_coin_types.empty();
        if ((!want_secp_targets && !want_ed_targets) || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil ||
            secp_derive_pipeline_ == nil ||
            (want_secp_targets && secp_eval_pipeline_ == nil) ||
            (want_ed_targets && (secp_to_ed25519_pipeline_ == nil || ed25519_eval_pipeline_ == nil))) {
            err = "Metal secp engine pipelines unavailable";
            return false;
        }

        const size_t pair_count = static_cast<size_t>(seed_record_count) * derivations.size();
        if (pair_count == 0u) {
            return true;
        }
        if (pair_count > static_cast<size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "Metal secp engine batch is too large";
            return false;
        }
        ensure_secp_program_templates(derivations, RESULT_DERIVATION_BIP32_SECP256K1, passphrase_index);

        const size_t programs_length = secp_program_templates_.size() * sizeof(RecoverySecpDerivationProgram);
        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        const uint32_t secp_out_capacity = want_secp_targets ? final_out_capacity : 0u;
        const uint32_t ed_out_capacity = want_ed_targets ? final_out_capacity : 0u;
        const bool run_secp_eval = want_secp_targets && secp_out_capacity != 0u;
        const bool run_ed_eval = want_ed_targets && ed_out_capacity != 0u;

        RecoveryEvalSecpKernelParams secp_params{};
        secp_params.record_count = static_cast<cmr_u32>(pair_count);
        secp_params.precompute_pitch = secp_precompute_pitch_;
        secp_params.target_mask = run_secp_eval ? recovery_secp_target_mask_for_coin_types(secp_coin_types) : 0u;
        secp_params.out_capacity = run_secp_eval ? secp_out_capacity : static_cast<cmr_u32>(pair_count);
        secp_params.passphrase_count = seed_record_count;
        secp_params.words_count = static_cast<cmr_u32>(derivations.size());
        if (run_secp_eval) {
            secp_params.derivation_type_mask = (1u << RESULT_DERIVATION_BIP32_SECP256K1);
            secp_params.flags = config.use_hash_target ? 0u : RECOVERY_SECP_FLAG_EMIT_ALL;
            secp_params.target_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            if (config.use_hash_target) {
                std::memcpy(secp_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(secp_params.target_bytes)));
            }
        }

        if (programs_length > 0u) {
            std::memcpy([engine_tile_buffers.secp_programs_buffer contents], secp_program_templates_.data(), programs_length);
        }
        std::memcpy([engine_tile_buffers.secp_params_buffer contents], &secp_params, sizeof(secp_params));

        if (run_ed_eval) {
            RecoveryEd25519StageKernelParams promote_params{};
            promote_params.record_count = static_cast<cmr_u32>(pair_count);
            promote_params.out_capacity = static_cast<cmr_u32>(pair_count);
            promote_params.seed_count = seed_record_count;
            promote_params.program_count = static_cast<cmr_u32>(derivations.size());

            RecoveryEd25519EvalParams ed_eval_params{};
            ed_eval_params.candidate_count = static_cast<cmr_u32>(pair_count);
            ed_eval_params.target_flags = recovery_ed25519_target_flags_for_coin_types(ed_coin_types, !config.use_hash_target);
            ed_eval_params.derivation_type = RESULT_DERIVATION_BIP32_SECP256K1;
            ed_eval_params.derivation_type_mask = RECOVERY_ED25519_DERIVATION_FLAG_SECP256K1;
            ed_eval_params.out_capacity = ed_out_capacity;
            ed_eval_params.match_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            ed_eval_params.passphrase_index = passphrase_index;
            if (config.use_hash_target) {
                std::memcpy(ed_eval_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(ed_eval_params.target_bytes)));
            }

            std::memcpy([engine_tile_buffers.ed25519_stage_params_buffer contents], &promote_params, sizeof(promote_params));
            std::memcpy([engine_tile_buffers.ed25519_eval_params_buffer contents], &ed_eval_params, sizeof(ed_eval_params));
        }

        return true;
    }

    bool update_secp_engine_tile_params(const std::vector<RecoveryPreparedDerivation>& derivations,
                                        const AppConfig& config,
                                        const cmr_u32 passphrase_index,
                                        const uint32_t seed_record_count,
                                        const SecpEngineTileBuffers& engine_tile_buffers,
                                        const std::string& secp_coin_types,
                                        const std::string& ed_coin_types,
                                        std::string& err) {
        err.clear();
        const bool want_secp_targets = !secp_coin_types.empty();
        const bool want_ed_targets = !ed_coin_types.empty();
        if ((!want_secp_targets && !want_ed_targets) || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (engine_tile_buffers.secp_params_buffer == nil) {
            err = "missing Metal bounded secp params buffer";
            return false;
        }

        const size_t pair_count = static_cast<size_t>(seed_record_count) * derivations.size();
        if (pair_count == 0u || pair_count > static_cast<size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "Metal secp engine batch is too large";
            return false;
        }

        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        const uint32_t secp_out_capacity = want_secp_targets ? final_out_capacity : 0u;
        const uint32_t ed_out_capacity = want_ed_targets ? final_out_capacity : 0u;
        const bool run_secp_eval = want_secp_targets && secp_out_capacity != 0u;
        const bool run_ed_eval = want_ed_targets && ed_out_capacity != 0u;

        RecoveryEvalSecpKernelParams secp_params{};
        secp_params.record_count = static_cast<cmr_u32>(pair_count);
        secp_params.precompute_pitch = secp_precompute_pitch_;
        secp_params.target_mask = run_secp_eval ? recovery_secp_target_mask_for_coin_types(secp_coin_types) : 0u;
        secp_params.out_capacity = run_secp_eval ? secp_out_capacity : static_cast<cmr_u32>(pair_count);
        secp_params.passphrase_count = seed_record_count;
        secp_params.words_count = static_cast<cmr_u32>(derivations.size());
        if (run_secp_eval) {
            secp_params.derivation_type_mask = (1u << RESULT_DERIVATION_BIP32_SECP256K1);
            secp_params.flags = config.use_hash_target ? 0u : RECOVERY_SECP_FLAG_EMIT_ALL;
            secp_params.target_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            if (config.use_hash_target) {
                std::memcpy(secp_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(secp_params.target_bytes)));
            }
        }
        std::memcpy([engine_tile_buffers.secp_params_buffer contents], &secp_params, sizeof(secp_params));

        if (run_ed_eval) {
            if (engine_tile_buffers.ed25519_stage_params_buffer == nil ||
                engine_tile_buffers.ed25519_eval_params_buffer == nil) {
                err = "missing Metal bounded secp promote params buffers";
                return false;
            }

            RecoveryEd25519StageKernelParams promote_params{};
            promote_params.record_count = static_cast<cmr_u32>(pair_count);
            promote_params.out_capacity = static_cast<cmr_u32>(pair_count);
            promote_params.seed_count = seed_record_count;
            promote_params.program_count = static_cast<cmr_u32>(derivations.size());

            RecoveryEd25519EvalParams ed_eval_params{};
            ed_eval_params.candidate_count = static_cast<cmr_u32>(pair_count);
            ed_eval_params.target_flags = recovery_ed25519_target_flags_for_coin_types(ed_coin_types, !config.use_hash_target);
            ed_eval_params.derivation_type = RESULT_DERIVATION_BIP32_SECP256K1;
            ed_eval_params.derivation_type_mask = RECOVERY_ED25519_DERIVATION_FLAG_SECP256K1;
            ed_eval_params.out_capacity = ed_out_capacity;
            ed_eval_params.match_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            ed_eval_params.passphrase_index = passphrase_index;
            if (config.use_hash_target) {
                std::memcpy(ed_eval_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(ed_eval_params.target_bytes)));
            }

            std::memcpy([engine_tile_buffers.ed25519_stage_params_buffer contents], &promote_params, sizeof(promote_params));
            std::memcpy([engine_tile_buffers.ed25519_eval_params_buffer contents], &ed_eval_params, sizeof(ed_eval_params));
        }

        return true;
    }

    bool prepare_ed_engine_tile_buffers(const std::vector<RecoveryPreparedDerivation>& derivations,
                                        const AppConfig& config,
                                        const cmr_u32 passphrase_index,
                                        const uint32_t seed_record_count,
                                        const EdEngineTileBuffers& engine_tile_buffers,
                                        const cmr_u32 derivation_type,
                                        const std::string& secp_coin_types,
                                        const std::string& ed_coin_types,
                                        std::string& err) {
        err.clear();
        const bool want_secp_targets = !secp_coin_types.empty();
        const bool want_ed_targets = !ed_coin_types.empty();
        if ((!want_secp_targets && !want_ed_targets) || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil ||
            ed25519_derive_pipeline_ == nil ||
            (want_ed_targets && ed25519_eval_pipeline_ == nil) ||
            (want_secp_targets && (ed25519_to_secp_pipeline_ == nil || secp_eval_pipeline_ == nil))) {
            err = "Metal ed25519 engine pipelines unavailable";
            return false;
        }

        const size_t pair_count = static_cast<size_t>(seed_record_count) * derivations.size();
        if (pair_count == 0u) {
            return true;
        }
        if (pair_count > static_cast<size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "Metal ed25519 engine batch is too large";
            return false;
        }

        const cmr_u32 representative_coin_type = !ed_coin_types.empty() ? recovery_primary_ed25519_coin_type(ed_coin_types) : 0x60u;
        ensure_ed25519_program_templates(derivations, derivation_type, representative_coin_type, passphrase_index);

        const size_t programs_length = ed25519_program_templates_.size() * sizeof(RecoveryEd25519DerivationProgram);
        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        const uint32_t ed_out_capacity = want_ed_targets ? final_out_capacity : 0u;
        const uint32_t secp_out_capacity = want_secp_targets ? final_out_capacity : 0u;
        const bool run_ed_eval = want_ed_targets && ed_out_capacity != 0u;
        const bool run_secp_eval = want_secp_targets && secp_out_capacity != 0u;

        RecoveryEd25519StageKernelParams derive_params{};
        derive_params.record_count = static_cast<cmr_u32>(pair_count);
        derive_params.out_capacity = static_cast<cmr_u32>(pair_count);
        derive_params.seed_count = seed_record_count;
        derive_params.program_count = static_cast<cmr_u32>(derivations.size());
        std::memcpy([engine_tile_buffers.ed25519_stage_params_buffer contents], &derive_params, sizeof(derive_params));

        if (programs_length > 0u) {
            std::memcpy([engine_tile_buffers.ed25519_programs_buffer contents], ed25519_program_templates_.data(), programs_length);
        }

        if (run_ed_eval) {
            RecoveryEd25519EvalParams ed_eval_params{};
            ed_eval_params.candidate_count = static_cast<cmr_u32>(pair_count);
            ed_eval_params.target_flags = recovery_ed25519_target_flags_for_coin_types(ed_coin_types, !config.use_hash_target);
            ed_eval_params.derivation_type = derivation_type;
            ed_eval_params.derivation_type_mask = recovery_ed25519_derivation_flag_for_type(derivation_type);
            ed_eval_params.out_capacity = ed_out_capacity;
            ed_eval_params.match_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            ed_eval_params.passphrase_index = passphrase_index;
            if (config.use_hash_target) {
                std::memcpy(ed_eval_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(ed_eval_params.target_bytes)));
            }
            std::memcpy([engine_tile_buffers.ed25519_eval_params_buffer contents], &ed_eval_params, sizeof(ed_eval_params));
        }

        if (run_secp_eval) {
            RecoveryEvalSecpKernelParams secp_params{};
            secp_params.record_count = static_cast<cmr_u32>(pair_count);
            secp_params.out_capacity = secp_out_capacity;
            secp_params.target_mask = recovery_secp_target_mask_for_coin_types(secp_coin_types);
            secp_params.derivation_type_mask = derivation_type < 32u ? (1u << derivation_type) : 0u;
            secp_params.flags = config.use_hash_target ? 0u : RECOVERY_SECP_FLAG_EMIT_ALL;
            secp_params.passphrase_count = seed_record_count;
            secp_params.words_count = static_cast<cmr_u32>(derivations.size());
            secp_params.target_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            secp_params.precompute_pitch = secp_precompute_pitch_;
            if (config.use_hash_target) {
                std::memcpy(secp_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(secp_params.target_bytes)));
            }
            std::memcpy([engine_tile_buffers.secp_params_buffer contents], &secp_params, sizeof(secp_params));
        }

        return true;
    }

    bool update_ed_engine_tile_params(const std::vector<RecoveryPreparedDerivation>& derivations,
                                      const AppConfig& config,
                                      const cmr_u32 passphrase_index,
                                      const uint32_t seed_record_count,
                                      const EdEngineTileBuffers& engine_tile_buffers,
                                      const cmr_u32 derivation_type,
                                      const std::string& secp_coin_types,
                                      const std::string& ed_coin_types,
                                      std::string& err) {
        err.clear();
        const bool want_secp_targets = !secp_coin_types.empty();
        const bool want_ed_targets = !ed_coin_types.empty();
        if ((!want_secp_targets && !want_ed_targets) || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (engine_tile_buffers.ed25519_stage_params_buffer == nil) {
            err = "missing Metal bounded ed params buffer";
            return false;
        }

        const size_t pair_count = static_cast<size_t>(seed_record_count) * derivations.size();
        if (pair_count == 0u || pair_count > static_cast<size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "Metal ed25519 engine batch is too large";
            return false;
        }

        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        const uint32_t ed_out_capacity = want_ed_targets ? final_out_capacity : 0u;
        const uint32_t secp_out_capacity = want_secp_targets ? final_out_capacity : 0u;
        const bool run_ed_eval = want_ed_targets && ed_out_capacity != 0u;
        const bool run_secp_eval = want_secp_targets && secp_out_capacity != 0u;

        RecoveryEd25519StageKernelParams derive_params{};
        derive_params.record_count = static_cast<cmr_u32>(pair_count);
        derive_params.out_capacity = static_cast<cmr_u32>(pair_count);
        derive_params.seed_count = seed_record_count;
        derive_params.program_count = static_cast<cmr_u32>(derivations.size());
        std::memcpy([engine_tile_buffers.ed25519_stage_params_buffer contents], &derive_params, sizeof(derive_params));

        if (run_ed_eval) {
            if (engine_tile_buffers.ed25519_eval_params_buffer == nil) {
                err = "missing Metal bounded ed eval params buffer";
                return false;
            }
            RecoveryEd25519EvalParams ed_eval_params{};
            ed_eval_params.candidate_count = static_cast<cmr_u32>(pair_count);
            ed_eval_params.target_flags = recovery_ed25519_target_flags_for_coin_types(ed_coin_types, !config.use_hash_target);
            ed_eval_params.derivation_type = derivation_type;
            ed_eval_params.derivation_type_mask = recovery_ed25519_derivation_flag_for_type(derivation_type);
            ed_eval_params.out_capacity = ed_out_capacity;
            ed_eval_params.match_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            ed_eval_params.passphrase_index = passphrase_index;
            if (config.use_hash_target) {
                std::memcpy(ed_eval_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(ed_eval_params.target_bytes)));
            }
            std::memcpy([engine_tile_buffers.ed25519_eval_params_buffer contents], &ed_eval_params, sizeof(ed_eval_params));
        }

        if (run_secp_eval) {
            if (engine_tile_buffers.secp_params_buffer == nil) {
                err = "missing Metal bounded ed promote params buffer";
                return false;
            }
            RecoveryEvalSecpKernelParams secp_params{};
            secp_params.record_count = static_cast<cmr_u32>(pair_count);
            secp_params.out_capacity = secp_out_capacity;
            secp_params.target_mask = recovery_secp_target_mask_for_coin_types(secp_coin_types);
            secp_params.derivation_type_mask = derivation_type < 32u ? (1u << derivation_type) : 0u;
            secp_params.flags = config.use_hash_target ? 0u : RECOVERY_SECP_FLAG_EMIT_ALL;
            secp_params.passphrase_count = seed_record_count;
            secp_params.words_count = static_cast<cmr_u32>(derivations.size());
            secp_params.target_len = config.use_hash_target ? static_cast<cmr_u32>(std::min<std::size_t>(config.hash_target.size(), 32u)) : 0u;
            secp_params.precompute_pitch = secp_precompute_pitch_;
            if (config.use_hash_target) {
                std::memcpy(secp_params.target_bytes,
                            config.hash_target.data(),
                            std::min<std::size_t>(config.hash_target.size(), sizeof(secp_params.target_bytes)));
            }
            std::memcpy([engine_tile_buffers.secp_params_buffer contents], &secp_params, sizeof(secp_params));
        }

        return true;
    }

    bool run_bounded_batch_passphrase(const RecoveryPreparedTask& task,
                                      const std::vector<RecoveryPreparedDerivation>& derivations,
                                      const AppConfig& config,
                                      const std::string& passphrase,
                                      const cmr_u32 passphrase_index,
                                      const uint32_t tile_seed_capacity,
                                      const uint32_t cursor_tile_capacity,
                                      const uint64_t benchmark_batch_cap,
                                      const ChecksumTileBuffers& checksum_tile_buffers,
                                      std::vector<FoundRecord>& out,
                                      std::string& err) {
        out.clear();
        err.clear();

        if (device_ == nil || command_queue_ == nil ||
            checksum_prepare_pipeline_ == nil ||
            checksum_hit_pipeline_ == nil ||
            master_seed_pipeline_ == nil) {
            err = "Metal bounded batch pipelines unavailable";
            return false;
        }

        const size_t derivation_count = derivations.size();
        const size_t pair_capacity = static_cast<size_t>(tile_seed_capacity) * std::max<size_t>(derivation_count, 1u);
        const size_t final_found_records_length =
            static_cast<size_t>(std::max<uint32_t>(config.found_limit, 1u)) * sizeof(FoundRecord);
        const size_t seeds_length = static_cast<size_t>(std::max<uint32_t>(tile_seed_capacity, 1u)) * sizeof(MasterSeedRecord);
        const size_t secp_master_length =
            static_cast<size_t>(std::max<uint32_t>(tile_seed_capacity, 1u)) * sizeof(RecoverySecpMasterRecord);
        const size_t secp_programs_length = derivation_count * sizeof(RecoverySecpDerivationProgram);
        const size_t ed_programs_length = derivation_count * sizeof(RecoveryEd25519DerivationProgram);
        const bool need_secp_engine = execution_plan_.need_secp_derive;
        const bool need_ed_engine = execution_plan_.need_ed_derive;
        const bool need_secp_targets = execution_plan_.need_secp_targets;
        const bool need_ed_targets = execution_plan_.need_ed_targets;
        const bool use_secp_fast_lane = should_use_bounded_secp_fast_lane();
        const bool use_pure_secp_single_submit =
            use_secp_fast_lane && need_secp_engine && need_secp_targets && !need_ed_engine && !need_ed_targets;
        const bool need_secp_stage_records = need_secp_engine && !use_secp_fast_lane;
        const bool need_ed_promote_secp_stage_records = need_ed_engine && need_secp_targets;
        const size_t secp_stages_length =
            need_secp_stage_records ? pair_capacity * sizeof(RecoverySecpEvalRecord) : 0u;
        const size_t ed_promote_secp_stages_length =
            need_ed_promote_secp_stage_records ? pair_capacity * sizeof(RecoverySecpEvalRecord) : 0u;
        const size_t ed_stages_length = pair_capacity * sizeof(RecoveryEd25519StageRecord);
        const uint64_t checksum_total_batches =
            recovery_checksum_total_batches(task.missing_positions.size(), cursor_tile_capacity, benchmark_batch_cap);
        uint64_t remaining_candidates =
            recovery_checksum_tested_candidates(task.missing_positions.size(), cursor_tile_capacity, benchmark_batch_cap);

        id<MTLBuffer> final_found_records_buffer = nil;
        id<MTLBuffer> final_found_count_buffer = nil;
        SeedTileBuffers seed_tile_buffers;
        SecpEngineTileBuffers secp_engine_tile_buffers;
        EdEngineTileBuffers ed_engine_tile_buffers;

        if (!ensure_shared_buffer(final_found_records_buffer, final_found_records_length, err) ||
            !ensure_shared_buffer(final_found_count_buffer, sizeof(uint32_t), err) ||
            !ensure_shared_buffer(seed_tile_buffers.master_seed_records_buffer,
                                  seeds_length == 0u ? sizeof(MasterSeedRecord) : seeds_length,
                                  err) ||
            !ensure_shared_buffer(seed_tile_buffers.seed_pass_buffer,
                                  passphrase.empty() ? 1u : passphrase.size(),
                                  err) ||
            !ensure_shared_buffer(seed_tile_buffers.seed_params_buffer,
                                  sizeof(SeedBatchParams),
                                  err)) {
            err = "failed to allocate Metal bounded batch buffers";
            return false;
        }

        if (need_secp_engine &&
            (!ensure_shared_buffer(secp_engine_tile_buffers.secp_programs_buffer,
                                   secp_programs_length == 0u ? sizeof(RecoverySecpDerivationProgram) : secp_programs_length,
                                   err) ||
             ((use_secp_fast_lane &&
               (!ensure_shared_buffer(secp_engine_tile_buffers.secp_master_records_buffer,
                                      secp_master_length == 0u ? sizeof(RecoverySecpMasterRecord) : secp_master_length,
                                      err)))) ||
             (need_secp_stage_records &&
              !ensure_shared_buffer(secp_engine_tile_buffers.secp_stage_records_buffer,
                                    secp_stages_length == 0u ? sizeof(RecoverySecpEvalRecord) : secp_stages_length,
                                    err)) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.secp_params_buffer,
                                   sizeof(RecoveryEvalSecpKernelParams),
                                   err))) {
            err = "failed to allocate Metal bounded secp buffers";
            return false;
        }
        if (need_ed_targets &&
            (!ensure_shared_buffer(secp_engine_tile_buffers.ed25519_stage_records_buffer,
                                   ed_stages_length == 0u ? sizeof(RecoveryEd25519StageRecord) : ed_stages_length,
                                   err) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.ed25519_stage_params_buffer,
                                   sizeof(RecoveryEd25519StageKernelParams),
                                   err) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.ed25519_eval_params_buffer,
                                   sizeof(RecoveryEd25519EvalParams),
                                   err))) {
            err = "failed to allocate Metal bounded secp promote buffers";
            return false;
        }

        if (need_ed_engine &&
            (!ensure_shared_buffer(ed_engine_tile_buffers.ed25519_programs_buffer,
                                   ed_programs_length == 0u ? sizeof(RecoveryEd25519DerivationProgram) : ed_programs_length,
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.ed25519_stage_records_buffer,
                                   ed_stages_length == 0u ? sizeof(RecoveryEd25519StageRecord) : ed_stages_length,
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.ed25519_stage_params_buffer,
                                   sizeof(RecoveryEd25519StageKernelParams),
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.ed25519_eval_params_buffer,
                                   sizeof(RecoveryEd25519EvalParams),
                                   err))) {
            err = "failed to allocate Metal bounded ed buffers";
            return false;
        }

        if (need_secp_targets &&
            (!ensure_shared_buffer(ed_engine_tile_buffers.secp_stage_records_buffer,
                                   ed_promote_secp_stages_length == 0u
                                       ? sizeof(RecoverySecpEvalRecord)
                                       : ed_promote_secp_stages_length,
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.secp_params_buffer,
                                   sizeof(RecoveryEvalSecpKernelParams),
                                   err))) {
            err = "failed to allocate Metal bounded ed promote buffers";
            return false;
        }

        cmr_u32 prepared_ed_derivation_type = 0u;
        for (const RecoveryEngineDispatch& engine : execution_plan_.engines) {
            if (engine.kind != RecoveryEngineKind::Secp) {
                prepared_ed_derivation_type = engine.derivation_type;
                break;
            }
        }

        const uint32_t final_found_limit = recovery_effective_found_limit(config);
        ChecksumCursorState cursor_state{};
        cursor_state.missing_count = static_cast<cmr_u32>(std::min<std::size_t>(task.missing_positions.size(), RECOVERY_MAX_WORDS));
        cursor_state.exhausted = 0u;
        cursor_state.batch_candidate_capacity = std::max<uint64_t>(cursor_tile_capacity, 1ull);
        cursor_state.remaining_batches = checksum_total_batches;
        const uint64_t checksum_candidate_chunk_cap = std::max<uint64_t>(
            static_cast<uint64_t>(tile_seed_capacity),
            std::min<uint64_t>(
                static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()),
                recovery_u64_mul_saturating(
                    static_cast<uint64_t>(tile_seed_capacity),
                    static_cast<uint64_t>(recovery_runtime_checksum_candidate_multiplier()))));

        if (!prepare_seed_tile_buffers(task,
                                       passphrase,
                                       config.pbkdf_iterations,
                                       tile_seed_capacity,
                                       seed_tile_buffers,
                                       err)) {
            return false;
        }
        if (need_secp_engine &&
            !prepare_secp_engine_tile_buffers(derivations,
                                              config,
                                              passphrase_index,
                                              tile_seed_capacity,
                                              secp_engine_tile_buffers,
                                              execution_plan_.secp_coin_types,
                                              execution_plan_.ed_coin_types,
                                              err)) {
            return false;
        }
        if (need_ed_engine &&
            !prepare_ed_engine_tile_buffers(derivations,
                                            config,
                                            passphrase_index,
                                            tile_seed_capacity,
                                            ed_engine_tile_buffers,
                                            prepared_ed_derivation_type,
                                            execution_plan_.secp_coin_types,
                                            execution_plan_.ed_coin_types,
                                            err)) {
            return false;
        }

        while (out.size() < static_cast<size_t>(final_found_limit)) {
            if (recovery_checksum_cursor_drained(&cursor_state)) {
                break;
            }

            std::array<uint16_t, RECOVERY_MAX_WORDS> batch_start_digits{};
            for (cmr_u32 i = 0u; i < cursor_state.missing_count && i < RECOVERY_MAX_WORDS; ++i) {
                batch_start_digits[i] = cursor_state.digit_cursor[i];
            }
            std::memcpy([checksum_tile_buffers.start_digits_buffer contents],
                        batch_start_digits.data(),
                        sizeof(batch_start_digits));

            const uint64_t prepared_range_count =
                recovery_checksum_cursor_prepare_next_batch_host(cursor_state, remaining_candidates);
            if (prepared_range_count == 0ull) {
                if (recovery_checksum_cursor_drained(&cursor_state)) {
                    break;
                }
                err = "Metal bounded checksum scheduler produced an empty batch";
                return false;
            }

            uint64_t range_start = 0ull;
            while (range_start < prepared_range_count &&
                   out.size() < static_cast<size_t>(final_found_limit)) {
                const uint32_t subrange_count = static_cast<uint32_t>(std::min<uint64_t>(
                    prepared_range_count - range_start,
                    checksum_candidate_chunk_cap));
                if (subrange_count == 0u) {
                    break;
                }
                const uint64_t next_range_start = range_start + static_cast<uint64_t>(subrange_count);
                uint32_t raw_seed_record_count = 0u;
                if (use_pure_secp_single_submit) {
                    *reinterpret_cast<uint32_t*>([final_found_count_buffer contents]) = 0u;
                    id<MTLCommandBuffer> fastlane_command_buffer = [command_queue_ commandBuffer];
                    if (!dispatch_checksum_hit_range(range_start,
                                                     subrange_count,
                                                     fastlane_command_buffer,
                                                     checksum_tile_buffers,
                                                     err) ||
                        !evaluate_records_metal(task,
                                                derivations,
                                                config,
                                                passphrase,
                                                passphrase_index,
                                                tile_seed_capacity,
                                                seed_tile_buffers,
                                                secp_engine_tile_buffers,
                                                ed_engine_tile_buffers,
                                                checksum_tile_buffers.hits_buffer,
                                                checksum_tile_buffers.out_count_buffer,
                                                final_found_records_buffer,
                                                final_found_count_buffer,
                                                fastlane_command_buffer,
                                                err) ||
                        !commit_bounded_batch_command_buffer(fastlane_command_buffer,
                                                             "bounded-checksum-secp-fastlane",
                                                             err)) {
                        return false;
                    }

                    raw_seed_record_count =
                        *reinterpret_cast<const uint32_t*>([checksum_tile_buffers.out_count_buffer contents]);
                    if (raw_seed_record_count > tile_seed_capacity) {
                        err = "Metal bounded checksum hit buffer overflow;"
                              " lower CMR_RUNTIME_CHECKSUM_CANDIDATE_MULTIPLIER"
                              " or increase stage capacity";
                        return false;
                    }
                    report_live_progress(subrange_count, raw_seed_record_count);
                    if (raw_seed_record_count == 0u) {
                        range_start = next_range_start;
                        continue;
                    }
                } else {
                    id<MTLCommandBuffer> checksum_command_buffer = [command_queue_ commandBuffer];
                    if (!dispatch_checksum_hit_range(range_start,
                                                     subrange_count,
                                                     checksum_command_buffer,
                                                     checksum_tile_buffers,
                                                     err) ||
                        !commit_bounded_batch_command_buffer(checksum_command_buffer, "bounded-checksum-hit", err)) {
                        return false;
                    }

                    raw_seed_record_count =
                        *reinterpret_cast<const uint32_t*>([checksum_tile_buffers.out_count_buffer contents]);
                    if (raw_seed_record_count > tile_seed_capacity) {
                        err = "Metal bounded checksum hit buffer overflow;"
                              " lower CMR_RUNTIME_CHECKSUM_CANDIDATE_MULTIPLIER"
                              " or increase stage capacity";
                        return false;
                    }
                    report_live_progress(subrange_count, raw_seed_record_count);
                    const uint32_t seed_record_count = raw_seed_record_count;
                    if (seed_record_count == 0u) {
                        range_start = next_range_start;
                        continue;
                    }

                    *reinterpret_cast<uint32_t*>([final_found_count_buffer contents]) = 0u;
                    if (need_secp_engine &&
                        !update_secp_engine_tile_params(derivations,
                                                        config,
                                                        passphrase_index,
                                                        seed_record_count,
                                                        secp_engine_tile_buffers,
                                                        execution_plan_.secp_coin_types,
                                                        execution_plan_.ed_coin_types,
                                                        err)) {
                        return false;
                    }
                    if (need_ed_engine &&
                        !update_ed_engine_tile_params(derivations,
                                                      config,
                                                      passphrase_index,
                                                      seed_record_count,
                                                      ed_engine_tile_buffers,
                                                      prepared_ed_derivation_type,
                                                      execution_plan_.secp_coin_types,
                                                      execution_plan_.ed_coin_types,
                                                      err)) {
                        return false;
                    }

                    id<MTLCommandBuffer> evaluate_command_buffer = [command_queue_ commandBuffer];
                    if (!evaluate_records_metal(task,
                                                derivations,
                                                config,
                                                passphrase,
                                                passphrase_index,
                                                seed_record_count,
                                                seed_tile_buffers,
                                                secp_engine_tile_buffers,
                                                ed_engine_tile_buffers,
                                                checksum_tile_buffers.hits_buffer,
                                                checksum_tile_buffers.out_count_buffer,
                                                final_found_records_buffer,
                                                final_found_count_buffer,
                                                evaluate_command_buffer,
                                                err) ||
                        !commit_bounded_batch_command_buffer(evaluate_command_buffer, "bounded-record-eval", err)) {
                        return false;
                    }
                }

                const uint32_t found_count =
                    *reinterpret_cast<const uint32_t*>([final_found_count_buffer contents]);
                if (found_count == 0u) {
                    range_start = next_range_start;
                    continue;
                }

                const uint32_t remaining_found_capacity =
                    static_cast<uint32_t>(std::max<size_t>(0u, static_cast<size_t>(final_found_limit) - out.size()));
                const uint32_t copy_count = std::min(found_count, remaining_found_capacity);
                if (copy_count == 0u) {
                    break;
                }

                const size_t previous_size = out.size();
                out.resize(previous_size + static_cast<size_t>(copy_count));
                std::memcpy(out.data() + previous_size,
                            [final_found_records_buffer contents],
                            static_cast<size_t>(copy_count) * sizeof(FoundRecord));
                range_start = next_range_start;
            }
        }

        return true;
    }

    bool run_unified_runtime_passphrase(const RecoveryPreparedTask& task,
                                        const std::vector<RecoveryPreparedDerivation>& derivations,
                                        const AppConfig& config,
                                        const std::string& passphrase,
                                        const cmr_u32 passphrase_index,
                                        const uint32_t tile_seed_capacity,
                                        const uint32_t cursor_tile_capacity,
                                        const uint64_t benchmark_batch_cap,
                                        const ChecksumTileBuffers& checksum_tile_buffers,
                                        std::vector<FoundRecord>& out,
                                        std::string& err) {
        err.clear();

        if (!initialize_checksum_cursor_state(task, cursor_tile_capacity, benchmark_batch_cap, err)) {
            return false;
        }

        const size_t derivation_count = derivations.size();
        const size_t pair_count = static_cast<size_t>(tile_seed_capacity) * std::max<size_t>(derivation_count, 1u);
        const size_t final_found_records_length =
            static_cast<size_t>(std::max<uint32_t>(config.found_limit, 1u)) * sizeof(FoundRecord);
        const size_t seeds_length = static_cast<size_t>(tile_seed_capacity) * sizeof(MasterSeedRecord);
        const size_t secp_programs_length = derivation_count * sizeof(RecoverySecpDerivationProgram);
        const size_t ed_programs_length = derivation_count * sizeof(RecoveryEd25519DerivationProgram);
        const size_t secp_stages_length = pair_count * sizeof(RecoverySecpEvalRecord);
        const size_t ed_stages_length = pair_count * sizeof(RecoveryEd25519StageRecord);

        const bool need_secp_engine = execution_plan_.need_secp_derive;
        const bool need_ed_engine = execution_plan_.need_ed_derive;
        const bool need_secp_targets = execution_plan_.need_secp_targets;
        const bool need_ed_targets = execution_plan_.need_ed_targets;

        id<MTLBuffer> final_found_records_buffer = nil;
        id<MTLBuffer> final_found_count_buffer = nil;
        SeedTileBuffers seed_tile_buffers;
        SecpEngineTileBuffers secp_engine_tile_buffers;
        EdEngineTileBuffers ed_engine_tile_buffers;
        id<MTLBuffer> ed_seed_records_buffer = nil;
        id<MTLBuffer> runtime_state_buffer = nil;
        id<MTLBuffer> checksum_batch_ring_header_buffer = nil;
        id<MTLBuffer> checksum_batch_records_buffer = nil;
        id<MTLBuffer> checksum_ring_header_buffer = nil;
        id<MTLBuffer> secp_seed_ring_header_buffer = nil;
        id<MTLBuffer> ed_seed_ring_header_buffer = nil;
        id<MTLBuffer> secp_promote_ring_header_buffer = nil;
        id<MTLBuffer> ed_promote_ring_header_buffer = nil;

        if (!ensure_shared_buffer(final_found_records_buffer, final_found_records_length, err) ||
            !ensure_shared_buffer(final_found_count_buffer, sizeof(uint32_t), err) ||
            !ensure_shared_buffer(seed_tile_buffers.master_seed_records_buffer,
                                  seeds_length == 0u ? sizeof(MasterSeedRecord) : seeds_length,
                                  err) ||
            !ensure_shared_buffer(seed_tile_buffers.seed_pass_buffer,
                                  passphrase.empty() ? 1u : passphrase.size(),
                                  err) ||
            !ensure_shared_buffer(seed_tile_buffers.seed_params_buffer,
                                  sizeof(SeedBatchParams),
                                  err) ||
            !ensure_shared_buffer(runtime_state_buffer, sizeof(RecoveryRuntimeState), err) ||
            !ensure_shared_buffer(checksum_ring_header_buffer, sizeof(RecoveryRingHeader), err)) {
            err = "failed to allocate Metal unified runtime buffers";
            return false;
        }

        if (need_secp_engine &&
            (!ensure_shared_buffer(secp_engine_tile_buffers.secp_programs_buffer,
                                   secp_programs_length == 0u ? sizeof(RecoverySecpDerivationProgram) : secp_programs_length,
                                   err) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.secp_stage_records_buffer,
                                   secp_stages_length == 0u ? sizeof(RecoverySecpEvalRecord) : secp_stages_length,
                                   err) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.secp_params_buffer,
                                   sizeof(RecoveryEvalSecpKernelParams),
                                   err))) {
            err = "failed to allocate Metal unified secp buffers";
            return false;
        }
        if (need_ed_targets &&
            (!ensure_shared_buffer(secp_engine_tile_buffers.ed25519_stage_records_buffer,
                                   ed_stages_length == 0u ? sizeof(RecoveryEd25519StageRecord) : ed_stages_length,
                                   err) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.ed25519_stage_params_buffer,
                                   sizeof(RecoveryEd25519StageKernelParams),
                                   err) ||
             !ensure_shared_buffer(secp_promote_ring_header_buffer, sizeof(RecoveryRingHeader), err) ||
             !ensure_shared_buffer(secp_engine_tile_buffers.ed25519_eval_params_buffer,
                                   sizeof(RecoveryEd25519EvalParams),
                                   err))) {
            err = "failed to allocate Metal secp promote buffers";
            return false;
        }

        if (need_ed_engine &&
            (!ensure_shared_buffer(ed_engine_tile_buffers.ed25519_programs_buffer,
                                   ed_programs_length == 0u ? sizeof(RecoveryEd25519DerivationProgram) : ed_programs_length,
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.ed25519_stage_records_buffer,
                                   ed_stages_length == 0u ? sizeof(RecoveryEd25519StageRecord) : ed_stages_length,
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.ed25519_stage_params_buffer,
                                   sizeof(RecoveryEd25519StageKernelParams),
                                   err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.ed25519_eval_params_buffer,
                                   sizeof(RecoveryEd25519EvalParams),
                                   err))) {
            err = "failed to allocate Metal unified ed buffers";
            return false;
        }
        if (need_secp_targets &&
            (!ensure_shared_buffer(ed_engine_tile_buffers.secp_stage_records_buffer,
                                   secp_stages_length == 0u ? sizeof(RecoverySecpEvalRecord) : secp_stages_length,
                                   err) ||
             !ensure_shared_buffer(ed_promote_ring_header_buffer, sizeof(RecoveryRingHeader), err) ||
             !ensure_shared_buffer(ed_engine_tile_buffers.secp_params_buffer,
                                   sizeof(RecoveryEvalSecpKernelParams),
                                   err))) {
            err = "failed to allocate Metal ed promote buffers";
            return false;
        }
        if (need_secp_engine && !ensure_shared_buffer(secp_seed_ring_header_buffer, sizeof(RecoveryRingHeader), err)) {
            err = "failed to allocate Metal secp seed ring";
            return false;
        }
        if (need_ed_engine && !ensure_shared_buffer(ed_seed_ring_header_buffer, sizeof(RecoveryRingHeader), err)) {
            err = "failed to allocate Metal ed seed ring";
            return false;
        }
        if (need_secp_engine && need_ed_engine &&
            !ensure_shared_buffer(ed_seed_records_buffer, seeds_length == 0u ? sizeof(MasterSeedRecord) : seeds_length, err)) {
            err = "failed to allocate Metal ed seed records";
            return false;
        }

        *reinterpret_cast<uint32_t*>([final_found_count_buffer contents]) = 0u;

        if (!prepare_seed_tile_buffers(task, passphrase, config.pbkdf_iterations, tile_seed_capacity, seed_tile_buffers, err)) {
            return false;
        }

        cmr_u32 prepared_ed_derivation_type = 0u;
        for (const RecoveryEngineDispatch& engine : execution_plan_.engines) {
            if (engine.kind != RecoveryEngineKind::Secp) {
                prepared_ed_derivation_type = engine.derivation_type;
                break;
            }
        }

        if (need_secp_engine &&
            !prepare_secp_engine_tile_buffers(derivations,
                                              config,
                                              passphrase_index,
                                              tile_seed_capacity,
                                              secp_engine_tile_buffers,
                                              execution_plan_.secp_coin_types,
                                              execution_plan_.ed_coin_types,
                                              err)) {
            return false;
        }
        if (need_ed_engine &&
            !prepare_ed_engine_tile_buffers(derivations,
                                            config,
                                            passphrase_index,
                                            tile_seed_capacity,
                                            ed_engine_tile_buffers,
                                            prepared_ed_derivation_type,
                                            execution_plan_.secp_coin_types,
                                            execution_plan_.ed_coin_types,
                                            err)) {
            return false;
        }

        const uint64_t checksum_total_batches =
            recovery_checksum_total_batches(task.missing_positions.size(), cursor_tile_capacity, benchmark_batch_cap);
        const NSUInteger checksum_schedule_threads = resolve_threads_per_group(runtime_checksum_schedule_pipeline_);
        const NSUInteger checksum_schedule_groups = 1u;
        const NSUInteger checksum_threads = resolve_threads_per_group(runtime_checksum_consume_pipeline_);
        NSUInteger checksum_groups = resolve_runtime_worker_group_count(
            RecoveryRuntimeWorkerStage::ChecksumProduce,
            cursor_tile_capacity,
            checksum_threads);
        const NSUInteger checksum_batch_ring_capacity_ns =
            std::clamp<NSUInteger>(std::max<NSUInteger>(16u, checksum_groups * 8u), 16u, 256u);
        const uint32_t checksum_batch_ring_capacity = static_cast<uint32_t>(checksum_batch_ring_capacity_ns);
        const size_t checksum_batch_records_length =
            static_cast<size_t>(checksum_batch_ring_capacity) * sizeof(RecoveryChecksumBatchRecord);
        const NSUInteger seed_threads = resolve_threads_per_group(runtime_seed_produce_pipeline_);
        const NSUInteger seed_groups = resolve_runtime_worker_group_count(
            RecoveryRuntimeWorkerStage::SeedProduce,
            tile_seed_capacity,
            seed_threads);
        const NSUInteger secp_threads = need_secp_engine ? resolve_threads_per_group(runtime_secp_consume_pipeline_) : 0u;
        const NSUInteger secp_groups = need_secp_engine ? resolve_runtime_worker_group_count(
            RecoveryRuntimeWorkerStage::SecpConsume,
            pair_count,
            secp_threads) : 0u;
        const NSUInteger ed_threads = need_ed_engine ? resolve_threads_per_group(runtime_ed_consume_pipeline_) : 0u;
        const NSUInteger ed_groups = need_ed_engine ? resolve_runtime_worker_group_count(
            RecoveryRuntimeWorkerStage::EdConsume,
            pair_count,
            ed_threads) : 0u;
        const NSUInteger ed_promote_threads = (need_secp_engine && need_ed_targets)
            ? resolve_threads_per_group(runtime_ed_promote_consume_pipeline_) : 0u;
        const NSUInteger ed_promote_groups = (need_secp_engine && need_ed_targets)
            ? resolve_runtime_worker_group_count(
                RecoveryRuntimeWorkerStage::EdPromoteConsume,
                pair_count,
                ed_promote_threads) : 0u;
        const NSUInteger secp_promote_threads = (need_ed_engine && need_secp_targets)
            ? resolve_threads_per_group(runtime_secp_promote_consume_pipeline_) : 0u;
        const NSUInteger secp_promote_groups = (need_ed_engine && need_secp_targets)
            ? resolve_runtime_worker_group_count(
                RecoveryRuntimeWorkerStage::SecpPromoteConsume,
                pair_count,
                secp_promote_threads) : 0u;

        if (!ensure_shared_buffer(checksum_batch_ring_header_buffer, sizeof(RecoveryRingHeader), err) ||
            !ensure_shared_buffer(checksum_batch_records_buffer,
                                  checksum_batch_records_length == 0u ? sizeof(RecoveryChecksumBatchRecord) : checksum_batch_records_length,
                                  err)) {
            err = "failed to allocate Metal checksum batch ring";
            return false;
        }

        RecoveryRuntimeState runtime_state{};
        runtime_state.found_limit = recovery_effective_found_limit(config);
        runtime_state.checksum_batch_next_lo = 0u;
        runtime_state.checksum_batch_next_hi = 0u;
        runtime_state.checksum_total_batches_lo = static_cast<cmr_u32>(checksum_total_batches & 0xFFFFFFFFull);
        runtime_state.checksum_total_batches_hi = static_cast<cmr_u32>(checksum_total_batches >> 32u);
        runtime_state.checksum_batch_lock = 0u;
        runtime_state.checksum_groups_live = static_cast<cmr_u32>(checksum_groups);
        runtime_state.seed_groups_live = static_cast<cmr_u32>(seed_groups);
        runtime_state.secp_groups_live = static_cast<cmr_u32>(secp_groups);
        runtime_state.ed_groups_live = static_cast<cmr_u32>(ed_groups);
        runtime_state.ed_promote_groups_live = static_cast<cmr_u32>(ed_promote_groups);
        runtime_state.secp_promote_groups_live = static_cast<cmr_u32>(secp_promote_groups);
        std::memcpy([runtime_state_buffer contents], &runtime_state, sizeof(runtime_state));

        auto init_ring = [&](id<MTLBuffer> buffer, const uint64_t capacity) {
            if (buffer == nil) {
                return;
            }
            RecoveryRingHeader header{};
            header.capacity = capacity;
            std::memcpy([buffer contents], &header, sizeof(header));
        };

        init_ring(checksum_batch_ring_header_buffer, checksum_batch_ring_capacity);
        init_ring(checksum_ring_header_buffer, tile_seed_capacity);
        if (need_secp_engine) {
            init_ring(secp_seed_ring_header_buffer, tile_seed_capacity);
        }
        if (need_ed_engine) {
            init_ring(ed_seed_ring_header_buffer, tile_seed_capacity);
        }
        if (need_secp_engine && need_ed_targets) {
            init_ring(secp_promote_ring_header_buffer, pair_count);
        }
        if (need_ed_engine && need_secp_targets) {
            init_ring(ed_promote_ring_header_buffer, pair_count);
        }

        const id<MTLBuffer> secp_seed_records_buffer = need_secp_engine
            ? seed_tile_buffers.master_seed_records_buffer
            : nil;
        const id<MTLBuffer> ed_seed_runtime_records_buffer = need_ed_engine
            ? (need_secp_engine ? ed_seed_records_buffer : seed_tile_buffers.master_seed_records_buffer)
            : nil;
        const id<MTLBuffer> secp_promote_records_buffer =
            (need_secp_engine && need_ed_targets) ? secp_engine_tile_buffers.secp_stage_records_buffer : nil;
        const id<MTLBuffer> ed_promote_records_buffer =
            (need_ed_engine && need_secp_targets) ? ed_engine_tile_buffers.ed25519_stage_records_buffer : nil;

        auto filter_params_buffer = ed25519_filter_params_buffer_;
        auto bloom_buffer = (filter_kernel_mode_ == RecoveryFilterKernelMode::BloomOnly ||
                             filter_kernel_mode_ == RecoveryFilterKernelMode::Full)
                                ? ed25519_bloom_buffer_
                                : nil;
        auto xor_fingerprints_buffer = (filter_kernel_mode_ == RecoveryFilterKernelMode::XorSingle ||
                                        filter_kernel_mode_ == RecoveryFilterKernelMode::Full)
                                           ? ed25519_xor_fingerprints_buffer_
                                           : nil;

        std::vector<id<MTLCommandBuffer>> runtime_worker_buffers;
        runtime_worker_buffers.reserve(7);

        auto commit_runtime_worker = [&](id<MTLCommandBuffer> command_buffer,
                                         const char* label) -> bool {
            if (command_buffer == nil) {
                err = std::string("failed to create Metal runtime command buffer for ") + label;
                return false;
            }

            command_buffer.label = [NSString stringWithUTF8String:label];
            [command_buffer commit];
            runtime_worker_buffers.push_back(command_buffer);
            return true;
        };

        {
            id<MTLCommandBuffer> command_buffer = [runtime_checksum_schedule_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_checksum_schedule_pipeline_];
            [encoder setBuffer:checksum_cursor_state_buffer_ offset:0 atIndex:0];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:1];
            [encoder setBuffer:checksum_batch_ring_header_buffer offset:0 atIndex:2];
            [encoder setBuffer:checksum_batch_records_buffer offset:0 atIndex:3];
            [encoder dispatchThreadgroups:MTLSizeMake(checksum_schedule_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(checksum_schedule_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-checksum-schedule")) {
                return false;
            }
        }

        {
            id<MTLCommandBuffer> command_buffer = [runtime_checksum_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_checksum_consume_pipeline_];
            [encoder setBuffer:checksum_tile_buffers.base_ids_buffer offset:0 atIndex:0];
            [encoder setBuffer:checksum_tile_buffers.missing_positions_buffer offset:0 atIndex:1];
            [encoder setBuffer:checksum_tile_buffers.params_buffer offset:0 atIndex:2];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:3];
            [encoder setBuffer:checksum_batch_ring_header_buffer offset:0 atIndex:4];
            [encoder setBuffer:checksum_batch_records_buffer offset:0 atIndex:5];
            [encoder setBuffer:checksum_ring_header_buffer offset:0 atIndex:6];
            [encoder setBuffer:checksum_tile_buffers.hits_buffer offset:0 atIndex:7];
            [encoder dispatchThreadgroups:MTLSizeMake(checksum_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(checksum_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-checksum")) {
                return false;
            }
        }

        {
            id<MTLCommandBuffer> command_buffer = [runtime_seed_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_seed_produce_pipeline_];
            [encoder setBuffer:checksum_tile_buffers.hits_buffer offset:0 atIndex:0];
            [encoder setBuffer:checksum_ring_header_buffer offset:0 atIndex:1];
            [encoder setBuffer:dict_buffer_ offset:0 atIndex:2];
            [encoder setBuffer:seed_tile_buffers.seed_pass_buffer offset:0 atIndex:3];
            [encoder setBuffer:seed_tile_buffers.seed_params_buffer offset:0 atIndex:4];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:5];
            [encoder setBuffer:secp_seed_ring_header_buffer offset:0 atIndex:6];
            [encoder setBuffer:secp_seed_records_buffer offset:0 atIndex:7];
            [encoder setBuffer:ed_seed_ring_header_buffer offset:0 atIndex:8];
            [encoder setBuffer:ed_seed_runtime_records_buffer offset:0 atIndex:9];
            [encoder dispatchThreadgroups:MTLSizeMake(seed_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(seed_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-seed")) {
                return false;
            }
        }

        if (need_secp_engine) {
            id<MTLCommandBuffer> command_buffer = [runtime_secp_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_secp_consume_pipeline_];
            [encoder setBuffer:secp_seed_records_buffer offset:0 atIndex:0];
            [encoder setBuffer:secp_seed_ring_header_buffer offset:0 atIndex:1];
            [encoder setBuffer:secp_engine_tile_buffers.secp_programs_buffer offset:0 atIndex:2];
            [encoder setBuffer:secp_engine_tile_buffers.secp_params_buffer offset:0 atIndex:3];
            [encoder setBuffer:secp_precompute_buffer_ offset:0 atIndex:4];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:5];
            [encoder setBuffer:final_found_records_buffer offset:0 atIndex:6];
            [encoder setBuffer:final_found_count_buffer offset:0 atIndex:7];
            [encoder setBuffer:filter_params_buffer offset:0 atIndex:8];
            [encoder setBuffer:bloom_buffer offset:0 atIndex:9];
            [encoder setBuffer:xor_fingerprints_buffer offset:0 atIndex:10];
            [encoder setBuffer:secp_promote_ring_header_buffer offset:0 atIndex:11];
            [encoder setBuffer:secp_promote_records_buffer offset:0 atIndex:12];
            [encoder dispatchThreadgroups:MTLSizeMake(secp_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(secp_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-secp")) {
                return false;
            }
        }

        if (need_ed_engine) {
            id<MTLCommandBuffer> command_buffer = [runtime_ed_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_ed_consume_pipeline_];
            [encoder setBuffer:ed_seed_runtime_records_buffer offset:0 atIndex:0];
            [encoder setBuffer:ed_seed_ring_header_buffer offset:0 atIndex:1];
            [encoder setBuffer:ed_engine_tile_buffers.ed25519_programs_buffer offset:0 atIndex:2];
            [encoder setBuffer:ed_engine_tile_buffers.ed25519_stage_params_buffer offset:0 atIndex:3];
            [encoder setBuffer:ed_engine_tile_buffers.ed25519_eval_params_buffer offset:0 atIndex:4];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:5];
            [encoder setBuffer:final_found_records_buffer offset:0 atIndex:6];
            [encoder setBuffer:final_found_count_buffer offset:0 atIndex:7];
            [encoder setBuffer:filter_params_buffer offset:0 atIndex:8];
            [encoder setBuffer:bloom_buffer offset:0 atIndex:9];
            [encoder setBuffer:xor_fingerprints_buffer offset:0 atIndex:10];
            [encoder setBuffer:ed_promote_ring_header_buffer offset:0 atIndex:11];
            [encoder setBuffer:ed_promote_records_buffer offset:0 atIndex:12];
            [encoder dispatchThreadgroups:MTLSizeMake(ed_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(ed_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-ed")) {
                return false;
            }
        }

        if (need_secp_engine && need_ed_targets) {
            id<MTLCommandBuffer> command_buffer = [runtime_ed_promote_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_ed_promote_consume_pipeline_];
            [encoder setBuffer:secp_promote_records_buffer offset:0 atIndex:0];
            [encoder setBuffer:secp_promote_ring_header_buffer offset:0 atIndex:1];
            [encoder setBuffer:secp_engine_tile_buffers.ed25519_eval_params_buffer offset:0 atIndex:2];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:3];
            [encoder setBuffer:final_found_records_buffer offset:0 atIndex:4];
            [encoder setBuffer:final_found_count_buffer offset:0 atIndex:5];
            [encoder setBuffer:filter_params_buffer offset:0 atIndex:6];
            [encoder setBuffer:bloom_buffer offset:0 atIndex:7];
            [encoder setBuffer:xor_fingerprints_buffer offset:0 atIndex:8];
            [encoder dispatchThreadgroups:MTLSizeMake(ed_promote_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(ed_promote_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-ed-promote")) {
                return false;
            }
        }

        if (need_ed_engine && need_secp_targets) {
            id<MTLCommandBuffer> command_buffer = [runtime_secp_promote_queue_ commandBuffer];
            id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
            [encoder setComputePipelineState:runtime_secp_promote_consume_pipeline_];
            [encoder setBuffer:ed_promote_records_buffer offset:0 atIndex:0];
            [encoder setBuffer:ed_promote_ring_header_buffer offset:0 atIndex:1];
            [encoder setBuffer:ed_engine_tile_buffers.secp_params_buffer offset:0 atIndex:2];
            [encoder setBuffer:secp_precompute_buffer_ offset:0 atIndex:3];
            [encoder setBuffer:runtime_state_buffer offset:0 atIndex:4];
            [encoder setBuffer:final_found_records_buffer offset:0 atIndex:5];
            [encoder setBuffer:final_found_count_buffer offset:0 atIndex:6];
            [encoder setBuffer:filter_params_buffer offset:0 atIndex:7];
            [encoder setBuffer:bloom_buffer offset:0 atIndex:8];
            [encoder setBuffer:xor_fingerprints_buffer offset:0 atIndex:9];
            [encoder dispatchThreadgroups:MTLSizeMake(secp_promote_groups, 1, 1)
                  threadsPerThreadgroup:MTLSizeMake(secp_promote_threads, 1, 1)];
            [encoder endEncoding];
            if (!commit_runtime_worker(command_buffer, "runtime-secp-promote")) {
                return false;
            }
        }

        const int64_t completion_timeout_ns = recovery_runtime_completion_timeout_ns();
        const auto completion_deadline =
            std::chrono::steady_clock::now() + std::chrono::nanoseconds(completion_timeout_ns);
        bool all_terminal = false;
        while (std::chrono::steady_clock::now() < completion_deadline) {
            all_terminal = true;
            for (id<MTLCommandBuffer> command_buffer : runtime_worker_buffers) {
                switch (command_buffer.status) {
                case MTLCommandBufferStatusCompleted:
                case MTLCommandBufferStatusError:
                    break;
                default:
                    all_terminal = false;
                    break;
                }
            }
            if (all_terminal) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        if (!all_terminal) {
            auto* runtime_state_ptr =
                reinterpret_cast<RecoveryRuntimeState*>([runtime_state_buffer contents]);
            runtime_state_ptr->stop = 1u;
            const int64_t shutdown_grace_ns =
                std::min<int64_t>(completion_timeout_ns, 5ll * 1000ll * 1000ll * 1000ll);
            all_terminal = true;
            for (id<MTLCommandBuffer> command_buffer : runtime_worker_buffers) {
                all_terminal &=
                    recovery_wait_for_command_buffer_terminal_status(command_buffer, shutdown_grace_ns);
            }
            if (!all_terminal) {
                std::ostringstream timeout_err;
                timeout_err << "Metal unified runtime completion wait timed out";
                for (id<MTLCommandBuffer> command_buffer : runtime_worker_buffers) {
                    const std::string label =
                        (command_buffer.label != nil)
                            ? std::string([command_buffer.label UTF8String])
                            : std::string("unknown");
                    timeout_err << " [" << label << ":" << static_cast<int>(command_buffer.status) << "]";
                }
                err = timeout_err.str();
                return false;
            }
        }

        for (id<MTLCommandBuffer> command_buffer : runtime_worker_buffers) {
            if (command_buffer.status == MTLCommandBufferStatusCompleted) {
                continue;
            }
            const std::string label =
                (command_buffer.label != nil)
                    ? std::string([command_buffer.label UTF8String])
                    : std::string("unknown");
            if (command_buffer.status == MTLCommandBufferStatusError &&
                command_buffer.error != nil &&
                command_buffer.error.localizedDescription != nil) {
                err = "Metal unified runtime worker '" + label + "' failed: " +
                      std::string([command_buffer.error.localizedDescription UTF8String]);
            } else {
                err = "Metal unified runtime worker '" + label + "' failed";
            }
            return false;
        }

        const uint32_t found_count = *reinterpret_cast<const uint32_t*>([final_found_count_buffer contents]);
        const uint32_t copy_count = std::min<uint32_t>(found_count, config.found_limit);
        if (copy_count != 0u) {
            out.resize(copy_count);
            std::memcpy(out.data(),
                        [final_found_records_buffer contents],
                        static_cast<size_t>(copy_count) * sizeof(FoundRecord));
        }
        return true;
    }

    bool encode_seed_batch(id<MTLCommandBuffer> command_buffer,
                           const RecoveryPreparedTask& task,
                           const std::string& passphrase,
                           const uint64_t iterations,
                           const uint32_t record_capacity,
                           id<MTLBuffer> checksum_hits_buffer,
                           id<MTLBuffer> input_count_buffer,
                           id<MTLBuffer> master_seed_records_buffer,
                           id<MTLBuffer> seed_pass_buffer,
                           id<MTLBuffer> seed_params_buffer,
                           std::string& err) {
        (void)task;
        (void)passphrase;
        (void)iterations;
        err.clear();
        if (record_capacity == 0u) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil || master_seed_pipeline_ == nil) {
            err = "Metal master seed pipeline unavailable";
            return false;
        }
        if (dict_buffer_ == nil) {
            err = "missing Metal dictionary buffer";
            return false;
        }

        if (master_seed_records_buffer == nil || seed_pass_buffer == nil || seed_params_buffer == nil) {
            err = "failed to allocate Metal seed staging buffers";
            return false;
        }

        const NSUInteger threads_per_group = resolve_threads_per_group(master_seed_pipeline_);
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        [encoder setComputePipelineState:master_seed_pipeline_];
        [encoder setBuffer:checksum_hits_buffer offset:0 atIndex:0];
        [encoder setBuffer:dict_buffer_ offset:0 atIndex:1];
        [encoder setBuffer:seed_pass_buffer offset:0 atIndex:2];
        [encoder setBuffer:seed_params_buffer offset:0 atIndex:3];
        [encoder setBuffer:master_seed_records_buffer offset:0 atIndex:4];
        [encoder setBuffer:input_count_buffer offset:0 atIndex:5];
        const NSUInteger groups = resolve_threadgroup_count(record_capacity, threads_per_group);
        [encoder dispatchThreadgroups:MTLSizeMake(groups, 1, 1)
                threadsPerThreadgroup:MTLSizeMake(threads_per_group, 1, 1)];
        [encoder endEncoding];
        return true;
    }

    bool encode_secp_master_batch(id<MTLCommandBuffer> command_buffer,
                                  const RecoveryPreparedTask& task,
                                  const std::string& passphrase,
                                  const uint64_t iterations,
                                  const uint32_t record_capacity,
                                  id<MTLBuffer> checksum_hits_buffer,
                                  id<MTLBuffer> input_count_buffer,
                                  id<MTLBuffer> secp_master_records_buffer,
                                  id<MTLBuffer> indirect_dispatch_buffer,
                                  id<MTLBuffer> seed_pass_buffer,
                                  id<MTLBuffer> seed_params_buffer,
                                  std::string& err) {
        (void)task;
        (void)passphrase;
        (void)iterations;
        err.clear();
        if (record_capacity == 0u) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil || secp_master_seed_pipeline_ == nil) {
            err = "Metal secp master seed pipeline unavailable";
            return false;
        }
        if (dict_buffer_ == nil) {
            err = "missing Metal dictionary buffer";
            return false;
        }
        if (secp_master_records_buffer == nil || seed_pass_buffer == nil || seed_params_buffer == nil) {
            err = "failed to allocate Metal secp master staging buffers";
            return false;
        }

        const NSUInteger threads_per_group = resolve_threads_per_group(secp_master_seed_pipeline_);
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        [encoder setComputePipelineState:secp_master_seed_pipeline_];
        [encoder setBuffer:checksum_hits_buffer offset:0 atIndex:0];
        [encoder setBuffer:dict_buffer_ offset:0 atIndex:1];
        [encoder setBuffer:seed_pass_buffer offset:0 atIndex:2];
        [encoder setBuffer:seed_params_buffer offset:0 atIndex:3];
        [encoder setBuffer:secp_master_records_buffer offset:0 atIndex:4];
        [encoder setBuffer:input_count_buffer offset:0 atIndex:5];
        if (indirect_dispatch_buffer != nil) {
            [encoder dispatchThreadgroupsWithIndirectBuffer:indirect_dispatch_buffer
                                       indirectBufferOffset:0
                                      threadsPerThreadgroup:MTLSizeMake(threads_per_group, 1, 1)];
        } else {
            const NSUInteger groups = resolve_threadgroup_count(record_capacity, threads_per_group);
            [encoder dispatchThreadgroups:MTLSizeMake(groups, 1, 1)
                    threadsPerThreadgroup:MTLSizeMake(threads_per_group, 1, 1)];
        }
        [encoder endEncoding];
        return true;
    }

    bool encode_prepare_indirect_dispatch(id<MTLCommandBuffer> command_buffer,
                                          id<MTLBuffer> input_count_buffer,
                                          const uint32_t record_capacity,
                                          const NSUInteger threads_per_group,
                                          id<MTLBuffer> indirect_dispatch_buffer,
                                          std::string& err) {
        err.clear();
        if (record_capacity == 0u) {
            return true;
        }
        if (indirect_dispatch_prepare_pipeline_ == nil ||
            input_count_buffer == nil ||
            indirect_dispatch_buffer == nil) {
            err = "Metal indirect dispatch pipeline unavailable";
            return false;
        }

        const RecoveryIndirectDispatchParams params{
            record_capacity,
            static_cast<cmr_u32>(threads_per_group),
            0u,
            0u
        };

        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        [encoder setComputePipelineState:indirect_dispatch_prepare_pipeline_];
        [encoder setBuffer:input_count_buffer offset:0 atIndex:0];
        [encoder setBytes:&params length:sizeof(params) atIndex:1];
        [encoder setBuffer:indirect_dispatch_buffer offset:0 atIndex:2];
        [encoder dispatchThreadgroups:MTLSizeMake(1, 1, 1)
                threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [encoder endEncoding];
        return true;
    }

    bool evaluate_records_from_secp_engine(const std::vector<RecoveryPreparedDerivation>& derivations,
                                           const AppConfig& config,
                                           const cmr_u32 passphrase_index,
                                           const uint32_t seed_record_count,
                                           id<MTLBuffer> master_seed_records_buffer,
                                           const SecpEngineTileBuffers& engine_tile_buffers,
                                           const std::string& secp_coin_types,
                                           const std::string& ed_coin_types,
                                           id<MTLBuffer> checksum_hits_buffer,
                                           id<MTLBuffer> checksum_out_count_buffer,
                                           id<MTLBuffer> final_found_records_buffer,
                                           id<MTLBuffer> final_found_count_buffer,
                                           id<MTLCommandBuffer> command_buffer,
                                           std::string& err) {
        (void)checksum_hits_buffer;
        err.clear();
        const bool want_secp_targets = !secp_coin_types.empty();
        const bool want_ed_targets = !ed_coin_types.empty();
        if ((!want_secp_targets && !want_ed_targets) || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil ||
            secp_derive_pipeline_ == nil ||
            (want_secp_targets && secp_eval_pipeline_ == nil) ||
            (want_ed_targets && (secp_to_ed25519_pipeline_ == nil || ed25519_eval_pipeline_ == nil))) {
            err = "Metal secp engine pipelines unavailable";
            return false;
        }

        const size_t pair_count = static_cast<size_t>(seed_record_count) * derivations.size();
        if (pair_count == 0u) {
            return true;
        }
        if (pair_count > static_cast<size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "Metal secp engine batch is too large";
            return false;
        }

        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        const uint32_t secp_out_capacity = want_secp_targets ? final_out_capacity : 0u;
        const uint32_t ed_out_capacity = want_ed_targets ? final_out_capacity : 0u;
        const bool run_secp_eval = want_secp_targets && secp_out_capacity != 0u;
        const bool run_ed_eval = want_ed_targets && ed_out_capacity != 0u;

        const NSUInteger derive_threads = resolve_threads_per_group(secp_derive_pipeline_);
        id<MTLComputeCommandEncoder> derive_encoder = [command_buffer computeCommandEncoder];
        [derive_encoder setComputePipelineState:secp_derive_pipeline_];
        [derive_encoder setBuffer:master_seed_records_buffer offset:0 atIndex:0];
        [derive_encoder setBuffer:engine_tile_buffers.secp_programs_buffer offset:0 atIndex:1];
        [derive_encoder setBuffer:engine_tile_buffers.secp_stage_records_buffer offset:0 atIndex:2];
        [derive_encoder setBuffer:engine_tile_buffers.secp_params_buffer offset:0 atIndex:3];
        [derive_encoder setBuffer:secp_precompute_buffer_ offset:0 atIndex:4];
        [derive_encoder setBuffer:checksum_out_count_buffer offset:0 atIndex:5];
        const NSUInteger derive_groups = resolve_threadgroup_count(pair_count, derive_threads);
        [derive_encoder dispatchThreadgroups:MTLSizeMake(derive_groups, 1, 1)
                      threadsPerThreadgroup:MTLSizeMake(derive_threads, 1, 1)];
        [derive_encoder endEncoding];

        if (run_secp_eval) {
            if (!encode_secp_eval(command_buffer,
                                  engine_tile_buffers.secp_stage_records_buffer,
                                  final_found_records_buffer,
                                  final_found_count_buffer,
                                  engine_tile_buffers.secp_params_buffer,
                                  pair_count,
                                  static_cast<uint32_t>(derivations.size()),
                                  err)) {
                return false;
            }
        }

        if (run_ed_eval) {
            const NSUInteger promote_threads = resolve_threads_per_group(secp_to_ed25519_pipeline_);
            id<MTLComputeCommandEncoder> promote_encoder = [command_buffer computeCommandEncoder];
            [promote_encoder setComputePipelineState:secp_to_ed25519_pipeline_];
            [promote_encoder setBuffer:engine_tile_buffers.secp_stage_records_buffer offset:0 atIndex:0];
            [promote_encoder setBuffer:engine_tile_buffers.ed25519_stage_records_buffer offset:0 atIndex:1];
            [promote_encoder setBuffer:engine_tile_buffers.ed25519_stage_params_buffer offset:0 atIndex:2];
            [promote_encoder setBuffer:checksum_out_count_buffer offset:0 atIndex:3];
            const NSUInteger promote_groups = resolve_threadgroup_count(pair_count, promote_threads);
            [promote_encoder dispatchThreadgroups:MTLSizeMake(promote_groups, 1, 1)
                            threadsPerThreadgroup:MTLSizeMake(promote_threads, 1, 1)];
            [promote_encoder endEncoding];

            if (!encode_ed25519_eval(command_buffer,
                                     engine_tile_buffers.ed25519_stage_records_buffer,
                                     final_found_records_buffer,
                                     final_found_count_buffer,
                                     engine_tile_buffers.ed25519_eval_params_buffer,
                                     pair_count,
                                     static_cast<uint32_t>(derivations.size()),
                                     err)) {
                return false;
            }
        }

        return true;
    }

    bool evaluate_records_from_secp_engine_fastlane(const std::vector<RecoveryPreparedDerivation>& derivations,
                                                    const AppConfig& config,
                                                    const cmr_u32 passphrase_index,
                                                    const uint32_t seed_record_count,
                                                    const SecpEngineTileBuffers& engine_tile_buffers,
                                                    id<MTLBuffer> checksum_out_count_buffer,
                                                    id<MTLBuffer> final_found_records_buffer,
                                                    id<MTLBuffer> final_found_count_buffer,
                                                    id<MTLCommandBuffer> command_buffer,
                                                    std::string& err) {
        err.clear();
        const bool want_secp_targets = !execution_plan_.secp_coin_types.empty();
        if (!want_secp_targets || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil ||
            secp_eval_master_pipeline_ == nil ||
            engine_tile_buffers.secp_master_records_buffer == nil ||
            engine_tile_buffers.secp_programs_buffer == nil ||
            engine_tile_buffers.secp_params_buffer == nil) {
            err = "Metal secp fast-lane pipelines unavailable";
            return false;
        }

        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        if (final_out_capacity == 0u) {
            return true;
        }

        const RecoveryEvalSecpKernelParams* secp_params =
            reinterpret_cast<const RecoveryEvalSecpKernelParams*>([engine_tile_buffers.secp_params_buffer contents]);
        id<MTLComputePipelineState> eval_pipeline = secp_eval_master_pipeline_;
        if (secp_params != nullptr &&
            secp_params->target_mask == RecoverySecpTargetBitCompressed) {
            if (!secp_program_templates_have_adjacent_prefix_reuse_ &&
                secp_eval_master_compressed_noreuse_pipeline_ != nil) {
                eval_pipeline = secp_eval_master_compressed_noreuse_pipeline_;
            } else if (secp_eval_master_compressed_pipeline_ != nil) {
                eval_pipeline = secp_eval_master_compressed_pipeline_;
            }
        }
        const NSUInteger eval_threads = resolve_threads_per_group(eval_pipeline);
        id<MTLComputeCommandEncoder> eval_encoder = [command_buffer computeCommandEncoder];
        [eval_encoder setComputePipelineState:eval_pipeline];
        [eval_encoder setBuffer:engine_tile_buffers.secp_master_records_buffer offset:0 atIndex:0];
        [eval_encoder setBuffer:checksum_out_count_buffer offset:0 atIndex:1];
        [eval_encoder setBuffer:engine_tile_buffers.secp_programs_buffer offset:0 atIndex:2];
        [eval_encoder setBuffer:engine_tile_buffers.secp_params_buffer offset:0 atIndex:3];
        [eval_encoder setBuffer:secp_precompute_buffer_ offset:0 atIndex:4];
        [eval_encoder setBuffer:final_found_records_buffer offset:0 atIndex:5];
        [eval_encoder setBuffer:final_found_count_buffer offset:0 atIndex:6];
        const NSUInteger eval_groups = resolve_threadgroup_count(seed_record_count, eval_threads);
        [eval_encoder dispatchThreadgroups:MTLSizeMake(eval_groups, 1, 1)
                     threadsPerThreadgroup:MTLSizeMake(eval_threads, 1, 1)];
        [eval_encoder endEncoding];
        (void)passphrase_index;
        return true;
    }

    bool evaluate_records_from_ed_engine(const std::vector<RecoveryPreparedDerivation>& derivations,
                                         const AppConfig& config,
                                         const cmr_u32 passphrase_index,
                                         const uint32_t seed_record_count,
                                         id<MTLBuffer> master_seed_records_buffer,
                                         const EdEngineTileBuffers& engine_tile_buffers,
                                         const cmr_u32 derivation_type,
                                         const std::string& secp_coin_types,
                                         const std::string& ed_coin_types,
                                         id<MTLBuffer> checksum_hits_buffer,
                                         id<MTLBuffer> checksum_out_count_buffer,
                                         id<MTLBuffer> final_found_records_buffer,
                                         id<MTLBuffer> final_found_count_buffer,
                                         id<MTLCommandBuffer> command_buffer,
                                         std::string& err) {
        (void)checksum_hits_buffer;
        err.clear();
        const bool want_secp_targets = !secp_coin_types.empty();
        const bool want_ed_targets = !ed_coin_types.empty();
        if ((!want_secp_targets && !want_ed_targets) || seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (device_ == nil || command_queue_ == nil ||
            ed25519_derive_pipeline_ == nil ||
            (want_ed_targets && ed25519_eval_pipeline_ == nil) ||
            (want_secp_targets && (ed25519_to_secp_pipeline_ == nil || secp_eval_pipeline_ == nil))) {
            err = "Metal ed25519 engine pipelines unavailable";
            return false;
        }

        const size_t pair_count = static_cast<size_t>(seed_record_count) * derivations.size();
        if (pair_count == 0u) {
            return true;
        }
        if (pair_count > static_cast<size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "Metal ed25519 engine batch is too large";
            return false;
        }

        const uint32_t final_out_capacity = recovery_effective_found_limit(config);
        const uint32_t ed_out_capacity = want_ed_targets ? final_out_capacity : 0u;
        const uint32_t secp_out_capacity = want_secp_targets ? final_out_capacity : 0u;
        const bool run_ed_eval = want_ed_targets && ed_out_capacity != 0u;
        const bool run_secp_eval = want_secp_targets && secp_out_capacity != 0u;

        const NSUInteger derive_threads = resolve_threads_per_group(ed25519_derive_pipeline_);
        id<MTLComputeCommandEncoder> derive_encoder = [command_buffer computeCommandEncoder];
        [derive_encoder setComputePipelineState:ed25519_derive_pipeline_];
        [derive_encoder setBuffer:master_seed_records_buffer offset:0 atIndex:0];
        [derive_encoder setBuffer:engine_tile_buffers.ed25519_programs_buffer offset:0 atIndex:1];
        [derive_encoder setBuffer:engine_tile_buffers.ed25519_stage_records_buffer offset:0 atIndex:2];
        [derive_encoder setBuffer:engine_tile_buffers.ed25519_stage_params_buffer offset:0 atIndex:3];
        [derive_encoder setBuffer:checksum_out_count_buffer offset:0 atIndex:4];
        const NSUInteger derive_groups = resolve_threadgroup_count(pair_count, derive_threads);
        [derive_encoder dispatchThreadgroups:MTLSizeMake(derive_groups, 1, 1)
                      threadsPerThreadgroup:MTLSizeMake(derive_threads, 1, 1)];
        [derive_encoder endEncoding];

        if (run_ed_eval) {
            if (!encode_ed25519_eval(command_buffer,
                                     engine_tile_buffers.ed25519_stage_records_buffer,
                                     final_found_records_buffer,
                                     final_found_count_buffer,
                                     engine_tile_buffers.ed25519_eval_params_buffer,
                                     pair_count,
                                     static_cast<uint32_t>(derivations.size()),
                                     err)) {
                return false;
            }
        }

        if (run_secp_eval) {
            const NSUInteger promote_threads = resolve_threads_per_group(ed25519_to_secp_pipeline_);
            id<MTLComputeCommandEncoder> promote_encoder = [command_buffer computeCommandEncoder];
            [promote_encoder setComputePipelineState:ed25519_to_secp_pipeline_];
            [promote_encoder setBuffer:engine_tile_buffers.ed25519_stage_records_buffer offset:0 atIndex:0];
            [promote_encoder setBuffer:engine_tile_buffers.secp_stage_records_buffer offset:0 atIndex:1];
            [promote_encoder setBuffer:engine_tile_buffers.secp_params_buffer offset:0 atIndex:2];
            [promote_encoder setBuffer:secp_precompute_buffer_ offset:0 atIndex:3];
            [promote_encoder setBuffer:checksum_out_count_buffer offset:0 atIndex:4];
            const NSUInteger promote_groups = resolve_threadgroup_count(pair_count, promote_threads);
            [promote_encoder dispatchThreadgroups:MTLSizeMake(promote_groups, 1, 1)
                            threadsPerThreadgroup:MTLSizeMake(promote_threads, 1, 1)];
            [promote_encoder endEncoding];

            if (!encode_secp_eval(command_buffer,
                                  engine_tile_buffers.secp_stage_records_buffer,
                                  final_found_records_buffer,
                                  final_found_count_buffer,
                                  engine_tile_buffers.secp_params_buffer,
                                  pair_count,
                                  static_cast<uint32_t>(derivations.size()),
                                  err)) {
                return false;
            }
        }

        return true;
    }

    bool evaluate_records_metal(const RecoveryPreparedTask& task,
                                const std::vector<RecoveryPreparedDerivation>& derivations,
                                const AppConfig& config,
                                const std::string& passphrase,
                                const cmr_u32 passphrase_index,
                                const uint32_t seed_record_count,
                                const SeedTileBuffers& seed_tile_buffers,
                                const SecpEngineTileBuffers& secp_engine_tile_buffers,
                                const EdEngineTileBuffers& ed_engine_tile_buffers,
                                id<MTLBuffer> checksum_hits_buffer,
                                id<MTLBuffer> checksum_out_count_buffer,
                                id<MTLBuffer> final_found_records_buffer,
                                id<MTLBuffer> final_found_count_buffer,
                                id<MTLCommandBuffer> command_buffer,
                                std::string& err) {
        err.clear();
        if (seed_record_count == 0u || derivations.empty()) {
            return true;
        }
        if (execution_plan_.engines.empty()) {
            return true;
        }

        const bool use_secp_fast_lane = should_use_bounded_secp_fast_lane();
        if (use_secp_fast_lane) {
            if (!encode_secp_master_batch(command_buffer,
                                          task,
                                          passphrase,
                                          config.pbkdf_iterations,
                                          seed_record_count,
                                          checksum_hits_buffer,
                                          checksum_out_count_buffer,
                                          secp_engine_tile_buffers.secp_master_records_buffer,
                                          nil,
                                          seed_tile_buffers.seed_pass_buffer,
                                          seed_tile_buffers.seed_params_buffer,
                                          err)) {
                return false;
            }
            return evaluate_records_from_secp_engine_fastlane(derivations,
                                                              config,
                                                              passphrase_index,
                                                              seed_record_count,
                                                              secp_engine_tile_buffers,
                                                              checksum_out_count_buffer,
                                                              final_found_records_buffer,
                                                              final_found_count_buffer,
                                                              command_buffer,
                                                              err);
        }

        if (!encode_seed_batch(command_buffer,
                               task,
                               passphrase,
                               config.pbkdf_iterations,
                               seed_record_count,
                               checksum_hits_buffer,
                               checksum_out_count_buffer,
                               seed_tile_buffers.master_seed_records_buffer,
                               seed_tile_buffers.seed_pass_buffer,
                               seed_tile_buffers.seed_params_buffer,
                               err)) {
            return false;
        }

        for (const RecoveryEngineDispatch& engine : execution_plan_.engines) {
            std::string batch_err;
            if (engine.kind == RecoveryEngineKind::Secp) {
                if (!evaluate_records_from_secp_engine(derivations,
                                                       config,
                                                       passphrase_index,
                                                       seed_record_count,
                                                       seed_tile_buffers.master_seed_records_buffer,
                                                       secp_engine_tile_buffers,
                                                       execution_plan_.secp_coin_types,
                                                       execution_plan_.ed_coin_types,
                                                       checksum_hits_buffer,
                                                       checksum_out_count_buffer,
                                                       final_found_records_buffer,
                                                       final_found_count_buffer,
                                                       command_buffer,
                                                       batch_err)) {
                    err = batch_err;
                    return false;
                }
                continue;
            }

            if (!evaluate_records_from_ed_engine(derivations,
                                                 config,
                                                 passphrase_index,
                                                 seed_record_count,
                                                 seed_tile_buffers.master_seed_records_buffer,
                                                 ed_engine_tile_buffers,
                                                 engine.derivation_type,
                                                 execution_plan_.secp_coin_types,
                                                 execution_plan_.ed_coin_types,
                                                 checksum_hits_buffer,
                                                 checksum_out_count_buffer,
                                                 final_found_records_buffer,
                                                 final_found_count_buffer,
                                                 command_buffer,
                                                 batch_err)) {
                err = batch_err;
                return false;
            }
        }

        return true;
    }

    bool commit_bounded_batch_command_buffer(id<MTLCommandBuffer> command_buffer,
                                             const char* label,
                                             std::string& err) const {
        if (command_buffer == nil) {
            err = std::string("failed to create Metal command buffer for ") + label;
            return false;
        }

        command_buffer.label = [NSString stringWithUTF8String:label];
        [command_buffer commit];

        const int64_t timeout_ns = recovery_runtime_completion_timeout_ns();
        if (!recovery_wait_for_command_buffer_terminal_status(command_buffer, timeout_ns)) {
            err = std::string("Metal bounded batch '") + label + "' timed out";
            return false;
        }

        if (command_buffer.status == MTLCommandBufferStatusCompleted) {
            return true;
        }
        if (command_buffer.error != nil && command_buffer.error.localizedDescription != nil) {
            err = std::string("Metal bounded batch '") + label + "' failed: " +
                  std::string([command_buffer.error.localizedDescription UTF8String]);
        } else {
            err = std::string("Metal bounded batch '") + label + "' failed";
        }
        return false;
    }

private:
    static unsigned int normalize_requested_threads(const unsigned int requested) {
        constexpr unsigned int kSimdWidth = 32u;
        const unsigned int clamped = std::max<unsigned int>(requested, kSimdWidth);
        return ((clamped + (kSimdWidth - 1u)) / kSimdWidth) * kSimdWidth;
    }

    bool should_use_bounded_secp_fast_lane() const {
        if (filter_kernel_mode_ != RecoveryFilterKernelMode::None) {
            return false;
        }
        if (secp_master_seed_pipeline_ == nil || secp_eval_master_pipeline_ == nil) {
            return false;
        }
        if (!execution_plan_.need_secp_derive || !execution_plan_.need_secp_targets) {
            return false;
        }
        if (execution_plan_.need_ed_derive || execution_plan_.need_ed_targets) {
            return false;
        }
        return execution_plan_.engines.size() == 1u &&
               execution_plan_.engines.front().kind == RecoveryEngineKind::Secp;
    }

    id<MTLComputePipelineState> checksum_hit_pipeline_for_words(const cmr_u32 words_count) const {
        switch (words_count) {
        case 12u:
            return checksum_hit_12_pipeline_ != nil ? checksum_hit_12_pipeline_ : checksum_hit_pipeline_;
        case 15u:
            return checksum_hit_15_pipeline_ != nil ? checksum_hit_15_pipeline_ : checksum_hit_pipeline_;
        case 18u:
            return checksum_hit_18_pipeline_ != nil ? checksum_hit_18_pipeline_ : checksum_hit_pipeline_;
        case 21u:
            return checksum_hit_21_pipeline_ != nil ? checksum_hit_21_pipeline_ : checksum_hit_pipeline_;
        case 24u:
            return checksum_hit_24_pipeline_ != nil ? checksum_hit_24_pipeline_ : checksum_hit_pipeline_;
        default:
            return checksum_hit_pipeline_;
        }
    }

    void ensure_secp_program_templates(const std::vector<RecoveryPreparedDerivation>& derivations,
                                       const cmr_u32 derivation_type,
                                       const cmr_u32 passphrase_index) {
        if (secp_program_templates_.data() != nullptr &&
            secp_program_template_derivations_ == derivations.data() &&
            secp_program_template_count_ == derivations.size() &&
            secp_program_template_derivation_type_ == derivation_type &&
            secp_program_template_passphrase_index_ == passphrase_index) {
            return;
        }

        secp_program_templates_.resize(derivations.size());
        for (size_t derivation_index = 0u; derivation_index < derivations.size(); ++derivation_index) {
            RecoverySecpDerivationProgram program{};
            const std::vector<cmr_u32>& path = derivations[derivation_index].path;
            program.path_word_count = static_cast<cmr_u32>(std::min<std::size_t>(path.size(), RECOVERY_SECP_MAX_DERIVATION_SEGMENTS));
            for (cmr_u32 i = 0u; i < program.path_word_count; ++i) {
                program.path_words[i] = path[i];
            }
            program.derivation_index = static_cast<cmr_u32>(derivation_index);
            program.derivation_type = derivation_type;
            program.coin_type = 0u;
            program.passphrase_index = passphrase_index;
            secp_program_templates_[derivation_index] = program;
        }
        std::stable_sort(secp_program_templates_.begin(),
                         secp_program_templates_.end(),
                         [](const RecoverySecpDerivationProgram& lhs, const RecoverySecpDerivationProgram& rhs) {
                             const cmr_u32 lhs_count = std::min<cmr_u32>(lhs.path_word_count, RECOVERY_SECP_MAX_DERIVATION_SEGMENTS);
                             const cmr_u32 rhs_count = std::min<cmr_u32>(rhs.path_word_count, RECOVERY_SECP_MAX_DERIVATION_SEGMENTS);
                             const cmr_u32 compare = std::min(lhs_count, rhs_count);
                             for (cmr_u32 i = 0u; i < compare; ++i) {
                                 if (lhs.path_words[i] != rhs.path_words[i]) {
                                     return lhs.path_words[i] < rhs.path_words[i];
                                 }
                             }
                             if (lhs_count != rhs_count) {
                                 return lhs_count < rhs_count;
                             }
                             return lhs.derivation_index < rhs.derivation_index;
                         });
        secp_program_templates_have_adjacent_prefix_reuse_ =
            recovery_secp_program_templates_have_adjacent_prefix_reuse(secp_program_templates_);
        secp_program_template_derivations_ = derivations.data();
        secp_program_template_count_ = derivations.size();
        secp_program_template_derivation_type_ = derivation_type;
        secp_program_template_passphrase_index_ = passphrase_index;
    }

    static bool recovery_secp_program_templates_have_adjacent_prefix_reuse(
        const std::vector<RecoverySecpDerivationProgram>& programs) {
        for (size_t i = 1u; i < programs.size(); ++i) {
            const RecoverySecpDerivationProgram& prev = programs[i - 1u];
            const RecoverySecpDerivationProgram& curr = programs[i];
            const cmr_u32 prev_count =
                std::min<cmr_u32>(prev.path_word_count, RECOVERY_SECP_MAX_DERIVATION_SEGMENTS);
            const cmr_u32 curr_count =
                std::min<cmr_u32>(curr.path_word_count, RECOVERY_SECP_MAX_DERIVATION_SEGMENTS);
            if (prev_count == 0u || curr_count == 0u) {
                continue;
            }

            bool same_except_last = prev_count == curr_count;
            const cmr_u32 same_except_limit = same_except_last ? (curr_count - 1u) : 0u;
            for (cmr_u32 j = 0u; same_except_last && j < same_except_limit; ++j) {
                if (prev.path_words[j] != curr.path_words[j]) {
                    same_except_last = false;
                }
            }
            if (same_except_last) {
                return true;
            }

            bool extends_previous = prev_count < curr_count;
            for (cmr_u32 j = 0u; extends_previous && j < prev_count; ++j) {
                if (prev.path_words[j] != curr.path_words[j]) {
                    extends_previous = false;
                }
            }
            if (extends_previous) {
                return true;
            }
        }
        return false;
    }

    void ensure_ed25519_program_templates(const std::vector<RecoveryPreparedDerivation>& derivations,
                                          const cmr_u32 derivation_type,
                                          const cmr_u32 coin_type,
                                          const cmr_u32 passphrase_index) {
        if (ed25519_program_templates_.data() != nullptr &&
            ed25519_program_template_derivations_ == derivations.data() &&
            ed25519_program_template_count_ == derivations.size() &&
            ed25519_program_template_derivation_type_ == derivation_type &&
            ed25519_program_template_coin_type_ == coin_type &&
            ed25519_program_template_passphrase_index_ == passphrase_index) {
            return;
        }

        ed25519_program_templates_.resize(derivations.size());
        for (size_t derivation_index = 0u; derivation_index < derivations.size(); ++derivation_index) {
            RecoveryEd25519DerivationProgram program{};
            const std::vector<cmr_u32>& path = derivations[derivation_index].path;
            program.path_word_count = static_cast<cmr_u32>(std::min<std::size_t>(path.size(), RECOVERY_ED25519_MAX_DERIVATION_SEGMENTS));
            for (cmr_u32 i = 0u; i < program.path_word_count; ++i) {
                program.path_words[i] = path[i];
            }
            program.derivation_index = static_cast<cmr_u32>(derivation_index);
            program.derivation_type = derivation_type;
            program.coin_type = coin_type;
            program.passphrase_index = passphrase_index;
            ed25519_program_templates_[derivation_index] = program;
        }
        ed25519_program_template_derivations_ = derivations.data();
        ed25519_program_template_count_ = derivations.size();
        ed25519_program_template_derivation_type_ = derivation_type;
        ed25519_program_template_coin_type_ = coin_type;
        ed25519_program_template_passphrase_index_ = passphrase_index;
    }

    bool ensure_shared_buffer(__strong id<MTLBuffer>& buffer, const size_t required_length, std::string& err) {
        const NSUInteger target_length = static_cast<NSUInteger>(std::max<size_t>(required_length, 4u));
        if (buffer != nil &&
            [buffer length] >= target_length &&
            [buffer storageMode] == MTLStorageModeShared) {
            return true;
        }
        buffer = [device_ newBufferWithLength:target_length options:MTLResourceStorageModeShared];
        if (buffer == nil) {
            err = "failed to allocate shared Metal buffer";
            return false;
        }
        return true;
    }

    bool ensure_private_buffer(__strong id<MTLBuffer>& buffer, const size_t required_length, std::string& err) {
        const NSUInteger target_length = static_cast<NSUInteger>(std::max<size_t>(required_length, 4u));
        if (buffer != nil &&
            [buffer length] >= target_length &&
            [buffer storageMode] == MTLStorageModePrivate) {
            return true;
        }
        buffer = [device_ newBufferWithLength:target_length options:MTLResourceStorageModePrivate];
        if (buffer == nil) {
            err = "failed to allocate private Metal buffer";
            return false;
        }
        return true;
    }

    bool assign_private_buffer_copied(__strong id<MTLBuffer>& buffer,
                                      const void* bytes,
                                      const size_t length,
                                      const char* label,
                                      std::string& err) {
        if (bytes == nullptr || length == 0u) {
            err = std::string("invalid ") + label + " source buffer";
            return false;
        }
        if (device_ == nil || command_queue_ == nil) {
            err = std::string("Metal device unavailable for ") + label + " upload";
            return false;
        }

        const NSUInteger target_length = static_cast<NSUInteger>(std::max<size_t>(length, 4u));
        id<MTLBuffer> staging_buffer = [device_ newBufferWithLength:target_length
                                                            options:MTLResourceStorageModeShared];
        if (staging_buffer == nil) {
            err = std::string("failed to allocate Metal staging ") + label + " buffer";
            return false;
        }
        std::memset([staging_buffer contents], 0, target_length);
        std::memcpy([staging_buffer contents], bytes, length);

        id<MTLBuffer> private_buffer = [device_ newBufferWithLength:target_length
                                                            options:MTLResourceStorageModePrivate];
        if (private_buffer == nil) {
            err = std::string("failed to allocate Metal private ") + label + " buffer";
            return false;
        }

        id<MTLCommandBuffer> command_buffer = [command_queue_ commandBuffer];
        if (command_buffer == nil) {
            err = std::string("failed to create Metal upload command buffer for ") + label;
            return false;
        }
        id<MTLBlitCommandEncoder> blit_encoder = [command_buffer blitCommandEncoder];
        if (blit_encoder == nil) {
            err = std::string("failed to create Metal upload blit encoder for ") + label;
            return false;
        }
        [blit_encoder copyFromBuffer:staging_buffer
                        sourceOffset:0
                            toBuffer:private_buffer
                   destinationOffset:0
                                size:target_length];
        [blit_encoder endEncoding];
        [command_buffer commit];
        [command_buffer waitUntilCompleted];
        if (command_buffer.status != MTLCommandBufferStatusCompleted) {
            if (command_buffer.error != nil && command_buffer.error.localizedDescription != nil) {
                err = std::string([command_buffer.error.localizedDescription UTF8String]);
            } else {
                err = std::string("Metal upload failed for ") + label;
            }
            return false;
        }

        buffer = private_buffer;
        return true;
    }

    bool assign_shared_buffer_wrapped_or_copied(__strong id<MTLBuffer>& buffer,
                                                const void* bytes,
                                                const size_t length,
                                                const char* label,
                                                std::string& err) {
        if (bytes == nullptr || length == 0u) {
            err = std::string("invalid ") + label + " source buffer";
            return false;
        }

        buffer = [device_ newBufferWithBytesNoCopy:const_cast<void*>(bytes)
                                            length:static_cast<NSUInteger>(length)
                                           options:MTLResourceStorageModeShared
                                       deallocator:nil];
        if (buffer != nil) {
            return true;
        }

        buffer = [device_ newBufferWithBytes:bytes
                                      length:static_cast<NSUInteger>(length)
                                     options:MTLResourceStorageModeShared];
        if (buffer == nil) {
            err = std::string("failed to allocate Metal ") + label + " buffer";
            return false;
        }
        return true;
    }

    bool ensure_dict_buffer(const RecoveryWordlist& wordlist, std::string& err) {
        if (cached_wordlist_ == &wordlist && dict_buffer_ != nil) {
            return true;
        }
        const std::vector<char> dict_words = pack_wordlist_words(wordlist);
        if (!assign_private_buffer_copied(dict_buffer_,
                                          dict_words.data(),
                                          dict_words.size(),
                                          "dictionary",
                                          err)) {
            return false;
        }
        cached_wordlist_ = &wordlist;
        return true;
    }

    bool ensure_secp_precompute_buffer(std::string& err) {
        if (secp_precompute_buffer_ != nil && secp_precompute_pitch_ != 0u) {
            return true;
        }

        recovery_secp_precompute::Table table;
        std::string load_error = "failed to load secp precompute blob";
        bool loaded = false;
        for (const fs::path& candidate : recovery_packaged_resource_locations("secp-precompute-v1.bin")) {
            std::string candidate_error;
            if (recovery_secp_precompute::load_blob(table, candidate.string(), candidate_error)) {
                loaded = true;
                break;
            }
            if (!candidate_error.empty()) {
                load_error = candidate_error;
            }
        }
        if (!loaded) {
            err = load_error;
            return false;
        }
        if (table.entries.empty() || table.row_pitch == 0u) {
            err = "secp precompute table is empty";
            return false;
        }
        if (table.row_pitch > static_cast<std::size_t>(std::numeric_limits<cmr_u32>::max())) {
            err = "secp precompute pitch exceeds kernel ABI";
            return false;
        }

        const NSUInteger buffer_length = static_cast<NSUInteger>(table.entries.size() * sizeof(secp256k1_ge_storage));
        if (!assign_private_buffer_copied(secp_precompute_buffer_,
                                          table.entries.data(),
                                          buffer_length,
                                          "secp precompute",
                                          err)) {
            return false;
        }
        secp_precompute_pitch_ = static_cast<cmr_u32>(table.row_pitch);
        return true;
    }

    bool ensure_ed25519_filter_buffers(std::string& err) {
        if (ed25519_filters_ready_) {
            return true;
        }
        const RecoveryFilterSet& filter_set = recovery_filter_set();

        RecoveryFilterParams params{};
        if (!ensure_shared_buffer(ed25519_filter_params_buffer_, sizeof(params), err) ||
            !ensure_shared_buffer(ed25519_dummy_filter_buffer_, sizeof(uint32_t), err)) {
            err = "failed to allocate Metal ed25519 filter buffers";
            return false;
        }

        if (filter_set.bloom_count > 0) {
            params.bloom_enabled = 1u;
            if (filter_set.bloom_count == 1) {
                if (!assign_private_buffer_copied(ed25519_bloom_buffer_,
                                                  filter_set.blooms[0],
                                                  BLOOM_SIZE,
                                                  "bloom filter",
                                                  err)) {
                    return false;
                }
            } else {
                std::vector<uint8_t> merged_bloom(BLOOM_SIZE, 0u);
                for (int bloom_index = 0; bloom_index < filter_set.bloom_count; ++bloom_index) {
                    const auto* src = filter_set.blooms[bloom_index];
                    if (src == nullptr) {
                        continue;
                    }
                    for (size_t byte_index = 0; byte_index < BLOOM_SIZE; ++byte_index) {
                        merged_bloom[byte_index] |= src[byte_index];
                    }
                }
                if (!assign_private_buffer_copied(ed25519_bloom_buffer_,
                                                  merged_bloom.data(),
                                                  merged_bloom.size(),
                                                  "bloom filter",
                                                  err)) {
                    return false;
                }
            }
        } else {
            ed25519_bloom_buffer_ = ed25519_dummy_filter_buffer_;
        }

        const cmr_u32 active_xor_count = static_cast<cmr_u32>(std::clamp(filter_set.xor_count, 0, static_cast<int>(RECOVERY_ED25519_MAX_XOR_FILTERS)));
        params.xor_count = active_xor_count;
        params.xor_seed = filter_set.xor_seed;
        size_t xor_total_words = 0u;
        for (cmr_u32 i = 0u; i < RECOVERY_ED25519_MAX_XOR_FILTERS; ++i) {
            if (i >= active_xor_count) {
                continue;
            }
            params.xor_buffer_offset[i] = static_cast<cmr_u64>(xor_total_words);
            params.xor_array_length[i] = static_cast<cmr_u64>(filter_set.arrayLength[i]);
            params.xor_segment_count_length[i] = static_cast<cmr_u64>(filter_set.segmentCountLength[i]);
            params.xor_segment_length[i] = static_cast<cmr_u64>(filter_set.segmentLength[i]);
            params.xor_segment_length_mask[i] = static_cast<cmr_u64>(filter_set.segmentLengthMask[i]);
            xor_total_words += filter_set.arrayLength[i];
        }

        if (active_xor_count != 0u && xor_total_words != 0u) {
            std::vector<uint32_t> packed_words(xor_total_words, 0u);
            size_t xor_word_offset = 0u;
            for (cmr_u32 i = 0u; i < active_xor_count; ++i) {
                const size_t word_count = filter_set.arrayLength[i];
                if (word_count == 0u || filter_set.fingerprints[i] == nullptr) {
                    continue;
                }
                std::memcpy(packed_words.data() + xor_word_offset,
                            filter_set.fingerprints[i],
                            word_count * sizeof(uint32_t));
                xor_word_offset += word_count;
            }
            if (!assign_private_buffer_copied(ed25519_xor_fingerprints_buffer_,
                                              packed_words.data(),
                                              packed_words.size() * sizeof(uint32_t),
                                              "packed xor filter",
                                              err)) {
                return false;
            }
        } else {
            ed25519_xor_fingerprints_buffer_ = ed25519_dummy_filter_buffer_;
        }

        std::memcpy([ed25519_filter_params_buffer_ contents], &params, sizeof(params));
        *reinterpret_cast<uint32_t*>([ed25519_dummy_filter_buffer_ contents]) = 0u;
        ed25519_filters_ready_ = true;
        return true;
    }

    bool encode_ed25519_eval(id<MTLCommandBuffer> command_buffer,
                             id<MTLBuffer> stage_records_buffer,
                             id<MTLBuffer> out_records_buffer,
                             id<MTLBuffer> out_count_buffer,
                             id<MTLBuffer> eval_params_buffer,
                             const size_t pair_count,
                             const uint32_t program_count,
                             std::string& err) {
        (void)program_count;
        (void)err;
        const NSUInteger eval_threads = resolve_threads_per_group(ed25519_eval_pipeline_);
        id<MTLComputeCommandEncoder> eval_encoder = [command_buffer computeCommandEncoder];
        [eval_encoder setComputePipelineState:ed25519_eval_pipeline_];
        [eval_encoder setBuffer:stage_records_buffer offset:0 atIndex:0];
        [eval_encoder setBuffer:out_records_buffer offset:0 atIndex:1];
        [eval_encoder setBuffer:out_count_buffer offset:0 atIndex:2];
        [eval_encoder setBuffer:eval_params_buffer offset:0 atIndex:3];
        switch (filter_kernel_mode_) {
        case RecoveryFilterKernelMode::BloomOnly:
            [eval_encoder setBuffer:ed25519_bloom_buffer_ offset:0 atIndex:4];
            break;
        case RecoveryFilterKernelMode::XorSingle:
            [eval_encoder setBuffer:ed25519_filter_params_buffer_ offset:0 atIndex:4];
            [eval_encoder setBuffer:ed25519_xor_fingerprints_buffer_ offset:0 atIndex:5];
            break;
        case RecoveryFilterKernelMode::Full:
            [eval_encoder setBuffer:ed25519_filter_params_buffer_ offset:0 atIndex:4];
            [eval_encoder setBuffer:ed25519_bloom_buffer_ offset:0 atIndex:5];
            [eval_encoder setBuffer:ed25519_xor_fingerprints_buffer_ offset:0 atIndex:6];
            break;
        case RecoveryFilterKernelMode::None:
            break;
        }
        const NSUInteger eval_groups = resolve_threadgroup_count(pair_count, eval_threads);
        [eval_encoder dispatchThreadgroups:MTLSizeMake(eval_groups, 1, 1)
                    threadsPerThreadgroup:MTLSizeMake(eval_threads, 1, 1)];
        [eval_encoder endEncoding];
        return true;
    }

    bool encode_secp_eval(id<MTLCommandBuffer> command_buffer,
                          id<MTLBuffer> stage_records_buffer,
                          id<MTLBuffer> out_records_buffer,
                          id<MTLBuffer> out_count_buffer,
                          id<MTLBuffer> params_buffer,
                          const size_t pair_count,
                          const uint32_t program_count,
                          std::string& err) {
        (void)program_count;
        (void)err;
        const NSUInteger eval_threads = resolve_threads_per_group(secp_eval_pipeline_);
        id<MTLComputeCommandEncoder> eval_encoder = [command_buffer computeCommandEncoder];
        [eval_encoder setComputePipelineState:secp_eval_pipeline_];
        [eval_encoder setBuffer:stage_records_buffer offset:0 atIndex:0];
        [eval_encoder setBuffer:out_records_buffer offset:0 atIndex:1];
        [eval_encoder setBuffer:out_count_buffer offset:0 atIndex:2];
        [eval_encoder setBuffer:params_buffer offset:0 atIndex:3];
        switch (filter_kernel_mode_) {
        case RecoveryFilterKernelMode::BloomOnly:
            [eval_encoder setBuffer:ed25519_bloom_buffer_ offset:0 atIndex:4];
            break;
        case RecoveryFilterKernelMode::XorSingle:
            [eval_encoder setBuffer:ed25519_filter_params_buffer_ offset:0 atIndex:4];
            [eval_encoder setBuffer:ed25519_xor_fingerprints_buffer_ offset:0 atIndex:5];
            break;
        case RecoveryFilterKernelMode::Full:
            [eval_encoder setBuffer:ed25519_filter_params_buffer_ offset:0 atIndex:4];
            [eval_encoder setBuffer:ed25519_bloom_buffer_ offset:0 atIndex:5];
            [eval_encoder setBuffer:ed25519_xor_fingerprints_buffer_ offset:0 atIndex:6];
            break;
        case RecoveryFilterKernelMode::None:
            break;
        }
        const NSUInteger eval_groups = resolve_threadgroup_count(pair_count, eval_threads);
        [eval_encoder dispatchThreadgroups:MTLSizeMake(eval_groups, 1, 1)
                    threadsPerThreadgroup:MTLSizeMake(eval_threads, 1, 1)];
        [eval_encoder endEncoding];
        return true;
    }

    NSUInteger resolve_threads_per_group(id<MTLComputePipelineState> pipeline) const {
        const NSUInteger width = std::max<NSUInteger>(pipeline.threadExecutionWidth, 1u);
        const NSUInteger limit = std::max<NSUInteger>(pipeline.maxTotalThreadsPerThreadgroup, width);
        NSUInteger target = std::min<NSUInteger>(thread_count_, limit);
        target = std::max<NSUInteger>(width, (target / width) * width);
        if (target > limit) {
            target = std::max<NSUInteger>(width, (limit / width) * width);
        }
        return target == 0u ? width : target;
    }

    NSUInteger resolve_threadgroup_count(const size_t work_items, const NSUInteger threads_per_group) const {
        if (block_count_ != 0u) {
            return static_cast<NSUInteger>(block_count_);
        }
        if (work_items == 0u) {
            return 1u;
        }
        return static_cast<NSUInteger>((work_items + threads_per_group - 1u) / threads_per_group);
    }

    NSUInteger resolve_runtime_worker_group_count(const RecoveryRuntimeWorkerStage stage,
                                                  const size_t work_items,
                                                  const NSUInteger threads_per_group) const {
        const NSUInteger full_coverage = resolve_threadgroup_count(work_items, threads_per_group);
        NSUInteger cap = 1u;
        const char* env_name = nullptr;
        switch (stage) {
        case RecoveryRuntimeWorkerStage::ChecksumProduce:
            cap = 1u;
            env_name = "CMR_RUNTIME_CHECKSUM_GROUP_CAP";
            break;
        case RecoveryRuntimeWorkerStage::SeedProduce:
            cap = 1u;
            env_name = "CMR_RUNTIME_SEED_GROUP_CAP";
            break;
        case RecoveryRuntimeWorkerStage::EdPromoteConsume:
            cap = 1u;
            env_name = "CMR_RUNTIME_ED_PROMOTE_GROUP_CAP";
            break;
        case RecoveryRuntimeWorkerStage::SecpPromoteConsume:
            cap = 1u;
            env_name = "CMR_RUNTIME_SECP_PROMOTE_GROUP_CAP";
            break;
        case RecoveryRuntimeWorkerStage::SecpConsume:
            cap = 1u;
            env_name = "CMR_RUNTIME_SECP_GROUP_CAP";
            break;
        case RecoveryRuntimeWorkerStage::EdConsume:
            cap = 1u;
            env_name = "CMR_RUNTIME_ED_GROUP_CAP";
            break;
        }
        cap = recovery_runtime_worker_cap_override(env_name, cap);
        return std::max<NSUInteger>(1u, std::min(full_coverage, cap));
    }

    bool initialize_checksum_cursor_state(const RecoveryPreparedTask& task,
                                          const uint32_t batch_candidate_capacity,
                                          const uint64_t batch_limit,
                                          std::string& err) {
        ChecksumCursorState state{};
        const uint64_t candidate_capacity = std::max<uint64_t>(batch_candidate_capacity, 1ull);
        const uint64_t batch_count =
            recovery_checksum_total_batches(task.missing_positions.size(), candidate_capacity, batch_limit);
        state.missing_count = static_cast<cmr_u32>(std::min<std::size_t>(task.missing_positions.size(), RECOVERY_MAX_WORDS));
        state.exhausted = 0u;
        state.batch_candidate_capacity = candidate_capacity;
        state.remaining_batches = batch_count;
        if (!ensure_shared_buffer(checksum_cursor_state_buffer_, sizeof(state), err)) {
            err = "failed to allocate Metal checksum cursor buffer";
            return false;
        }
        std::memcpy([checksum_cursor_state_buffer_ contents], &state, sizeof(state));
        return true;
    }

    bool prepare_checksum_batch(id<MTLCommandBuffer> command_buffer,
                                const ChecksumTileBuffers& tile_buffers,
                                std::string& err) {
        if (checksum_cursor_state_buffer_ == nil ||
            tile_buffers.base_ids_buffer == nil ||
            tile_buffers.missing_positions_buffer == nil ||
            tile_buffers.start_digits_buffer == nil ||
            tile_buffers.params_buffer == nil) {
            err = "missing Metal checksum batch buffers";
            return false;
        }

        id<MTLComputeCommandEncoder> prepare_encoder = [command_buffer computeCommandEncoder];
        [prepare_encoder setComputePipelineState:checksum_prepare_pipeline_];
        [prepare_encoder setBuffer:checksum_cursor_state_buffer_ offset:0 atIndex:0];
        [prepare_encoder setBuffer:tile_buffers.start_digits_buffer offset:0 atIndex:1];
        [prepare_encoder setBuffer:tile_buffers.params_buffer offset:0 atIndex:2];
        [prepare_encoder dispatchThreadgroups:MTLSizeMake(1, 1, 1)
                     threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        [prepare_encoder endEncoding];
        return true;
    }

    bool dispatch_checksum_hit_range(const uint64_t range_start,
                                     const uint32_t range_count,
                                     id<MTLCommandBuffer> command_buffer,
                                     const ChecksumTileBuffers& tile_buffers,
                                     std::string& err) {
        if (tile_buffers.base_ids_buffer == nil ||
            tile_buffers.missing_positions_buffer == nil ||
            tile_buffers.start_digits_buffer == nil ||
            tile_buffers.hits_buffer == nil ||
            tile_buffers.out_count_buffer == nil ||
            tile_buffers.params_buffer == nil) {
            err = "missing Metal checksum hit buffers";
            return false;
        }

        ChecksumStageParams params =
            *reinterpret_cast<const ChecksumStageParams*>([tile_buffers.params_buffer contents]);
        params.range_start = range_start;
        params.range_count = range_count;
        std::memcpy([tile_buffers.params_buffer contents], &params, sizeof(params));

        id<MTLBlitCommandEncoder> reset_encoder = [command_buffer blitCommandEncoder];
        [reset_encoder fillBuffer:tile_buffers.out_count_buffer range:NSMakeRange(0u, sizeof(uint32_t)) value:0u];
        [reset_encoder endEncoding];

        id<MTLComputePipelineState> checksum_hit_pipeline =
            checksum_hit_pipeline_for_words(params.words_count);
        id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
        [encoder setComputePipelineState:checksum_hit_pipeline];
        [encoder setBuffer:tile_buffers.base_ids_buffer offset:0 atIndex:0];
        [encoder setBuffer:tile_buffers.missing_positions_buffer offset:0 atIndex:1];
        [encoder setBuffer:tile_buffers.start_digits_buffer offset:0 atIndex:2];
        [encoder setBuffer:tile_buffers.hits_buffer offset:0 atIndex:3];
        [encoder setBuffer:tile_buffers.out_count_buffer offset:0 atIndex:4];
        [encoder setBuffer:tile_buffers.params_buffer offset:0 atIndex:5];

        const NSUInteger threads_per_group = resolve_threads_per_group(checksum_hit_pipeline);
        const NSUInteger groups = resolve_threadgroup_count(static_cast<size_t>(std::max<uint32_t>(range_count, 1u)),
                                                            threads_per_group);
        [encoder dispatchThreadgroups:MTLSizeMake(groups, 1, 1) threadsPerThreadgroup:MTLSizeMake(threads_per_group, 1, 1)];
        [encoder endEncoding];
        return true;
    }

    void report_live_progress(const uint64_t tested_delta,
                              const uint64_t checksum_valid_delta) const {
        if (live_status_ == nullptr) {
            return;
        }
        if (tested_delta != 0ull) {
            live_status_->tested_total.fetch_add(tested_delta, std::memory_order_relaxed);
        }
        if (checksum_valid_delta != 0ull) {
            live_status_->checksum_valid_total.fetch_add(checksum_valid_delta, std::memory_order_relaxed);
        }
    }

    id<MTLDevice> device_;
    id<MTLCommandQueue> command_queue_;
    id<MTLComputePipelineState> checksum_prepare_pipeline_;
    id<MTLComputePipelineState> checksum_hit_pipeline_;
    id<MTLComputePipelineState> checksum_hit_12_pipeline_;
    id<MTLComputePipelineState> checksum_hit_15_pipeline_;
    id<MTLComputePipelineState> checksum_hit_18_pipeline_;
    id<MTLComputePipelineState> checksum_hit_21_pipeline_;
    id<MTLComputePipelineState> checksum_hit_24_pipeline_;
    id<MTLComputePipelineState> master_seed_pipeline_;
    id<MTLComputePipelineState> secp_master_seed_pipeline_;
    id<MTLComputePipelineState> indirect_dispatch_prepare_pipeline_;
    id<MTLComputePipelineState> ed25519_derive_pipeline_;
    id<MTLComputePipelineState> ed25519_eval_pipeline_;
    id<MTLComputePipelineState> secp_derive_pipeline_;
    id<MTLComputePipelineState> secp_to_ed25519_pipeline_;
    id<MTLComputePipelineState> ed25519_to_secp_pipeline_;
    id<MTLComputePipelineState> secp_eval_pipeline_;
    id<MTLComputePipelineState> secp_eval_master_pipeline_;
    id<MTLComputePipelineState> secp_eval_master_compressed_pipeline_;
    id<MTLComputePipelineState> secp_eval_master_compressed_noreuse_pipeline_;
    id<MTLComputePipelineState> runtime_checksum_schedule_pipeline_ = nil;
    id<MTLComputePipelineState> runtime_checksum_consume_pipeline_ = nil;
    id<MTLComputePipelineState> runtime_seed_produce_pipeline_ = nil;
    id<MTLComputePipelineState> runtime_secp_consume_pipeline_ = nil;
    id<MTLComputePipelineState> runtime_ed_consume_pipeline_ = nil;
    id<MTLComputePipelineState> runtime_ed_promote_consume_pipeline_ = nil;
    id<MTLComputePipelineState> runtime_secp_promote_consume_pipeline_ = nil;
    id<MTLCommandQueue> runtime_checksum_schedule_queue_ = nil;
    id<MTLCommandQueue> runtime_checksum_queue_ = nil;
    id<MTLCommandQueue> runtime_seed_queue_ = nil;
    id<MTLCommandQueue> runtime_secp_queue_ = nil;
    id<MTLCommandQueue> runtime_ed_queue_ = nil;
    id<MTLCommandQueue> runtime_ed_promote_queue_ = nil;
    id<MTLCommandQueue> runtime_secp_promote_queue_ = nil;
    RecoveryExecutionPlan execution_plan_;
    RecoveryFilterKernelMode filter_kernel_mode_ = RecoveryFilterKernelMode::None;
    bool filters_requested_ = false;
    unsigned int thread_count_;
    unsigned int block_count_;
    uint32_t stage_capacity_;
    const RecoveryWordlist* cached_wordlist_ = nullptr;
    id<MTLBuffer> dict_buffer_ = nil;
    id<MTLBuffer> checksum_cursor_state_buffer_ = nil;
    id<MTLBuffer> checksum_base_ids_buffer_ = nil;
    id<MTLBuffer> checksum_missing_positions_buffer_ = nil;
    id<MTLBuffer> checksum_start_digits_buffer_ = nil;
    id<MTLBuffer> checksum_hits_buffer_ = nil;
    id<MTLBuffer> checksum_out_count_buffer_ = nil;
    id<MTLBuffer> checksum_params_buffer_ = nil;
    id<MTLBuffer> secp_precompute_buffer_ = nil;
    id<MTLBuffer> ed25519_filter_params_buffer_ = nil;
    id<MTLBuffer> ed25519_bloom_buffer_ = nil;
    id<MTLBuffer> ed25519_xor_fingerprints_buffer_ = nil;
    id<MTLBuffer> ed25519_dummy_filter_buffer_ = nil;
    cmr_u32 secp_precompute_pitch_ = 0u;
    bool ed25519_filters_ready_ = false;
    const RecoveryPreparedDerivation* secp_program_template_derivations_ = nullptr;
    size_t secp_program_template_count_ = 0u;
    cmr_u32 secp_program_template_derivation_type_ = 0u;
    cmr_u32 secp_program_template_passphrase_index_ = 0u;
    const RecoveryPreparedDerivation* ed25519_program_template_derivations_ = nullptr;
    size_t ed25519_program_template_count_ = 0u;
    cmr_u32 ed25519_program_template_derivation_type_ = 0u;
    cmr_u32 ed25519_program_template_coin_type_ = 0u;
    cmr_u32 ed25519_program_template_passphrase_index_ = 0u;
    std::vector<RecoverySecpDerivationProgram> secp_program_templates_;
    bool secp_program_templates_have_adjacent_prefix_reuse_ = true;
    std::vector<RecoveryEd25519DerivationProgram> ed25519_program_templates_;
    RecoveryLiveStatusState* live_status_ = nullptr;
};

static bool load_wordlists(const AppConfig& config,
                           const std::vector<RecoveryTemplateInput>& templates,
                           std::vector<RecoveryWordlist>& out,
                           std::string& err) {
    out.clear();
    if (!config.forced_wordlist.empty()) {
        RecoveryWordlist external_wl;
        if (!recovery_add_file_wordlist(config.forced_wordlist, external_wl, err)) return false;
        out.emplace_back(std::move(external_wl));
        return true;
    }

    std::vector<size_t> selected_indices;
    const bool use_selected_indices = recovery_select_embedded_wordlist_indices(templates, selected_indices);
    if (use_selected_indices) {
        out.reserve(selected_indices.size());
    } else {
        out.reserve(kRecoveryEmbeddedWordlistsCount);
    }

    const auto load_embedded_index = [&](const size_t index) {
        RecoveryWordlist wl;
        std::string local_err;
        if (recovery_add_embedded_wordlist(kRecoveryEmbeddedWordlists[index], wl, local_err)) {
            out.emplace_back(std::move(wl));
        }
    };

    if (use_selected_indices) {
        for (const size_t index : selected_indices) {
            load_embedded_index(index);
        }
    } else {
        for (std::size_t i = 0; i < kRecoveryEmbeddedWordlistsCount; ++i) {
            load_embedded_index(i);
        }
    }
    if (out.empty()) {
        err = "no embedded wordlists available";
        return false;
    }
    return true;
}

static bool expand_templates(const AppConfig& config, std::vector<RecoveryTemplateInput>& out, std::string& err) {
    out.clear();
    for (const RecoveryQueueEntry& entry : config.recovery_queue) {
        if (entry.type == RecoveryQueueEntryType::Phrase) {
            const std::string phrase = recovery_trim_spaces_copy(entry.value);
            if (!phrase.empty()) out.push_back({"<cmd>", 0, phrase});
            continue;
        }
        std::ifstream fin(entry.value.c_str(), std::ios::binary);
        if (!fin) {
            err = "failed to open recovery file: " + entry.value;
            return false;
        }
        std::string line;
        size_t line_no = 0;
        while (std::getline(fin, line)) {
            ++line_no;
            line = recovery_trim_spaces_copy(line);
            if (!line.empty()) out.push_back({entry.value, line_no, line});
        }
    }
    if (out.empty()) {
        err = "recovery queue is empty";
        return false;
    }
    return true;
}

static bool load_derivation_strings(const std::vector<std::string>& files, std::vector<std::string>& out, std::string& err) {
    out.clear();
    for (const std::string& path : files) {
        std::ifstream fin(path.c_str(), std::ios::binary);
        if (!fin) {
            err = "failed to open derivation file: " + path;
            return false;
        }
        std::string line;
        while (std::getline(fin, line)) {
            line = recovery_trim_spaces_copy(line);
            if (!line.empty()) {
                out.emplace_back(std::move(line));
            }
        }
    }
    if (out.empty()) {
        err = "no derivations loaded";
        return false;
    }
    return true;
}

static std::vector<char> pack_wordlist_words(const RecoveryWordlist& wordlist) {
    std::vector<char> packed(wordlist.words.size() * RECOVERY_DICT_WORD_STRIDE, 0);
    for (size_t i = 0; i < wordlist.words.size(); ++i) {
        const std::string_view word = wordlist.words[i];
        const size_t copy_len = std::min<size_t>(word.size(), RECOVERY_DICT_WORD_STRIDE - 1u);
        if (copy_len > 0u) {
            std::memcpy(&packed[i * RECOVERY_DICT_WORD_STRIDE], word.data(), copy_len);
        }
    }
    return packed;
}

static bool pack_candidate_ids(const RecoveryPreparedTask& task, const std::vector<std::string>& candidates, std::vector<uint16_t>& out_ids, std::string& err) {
    out_ids.clear();
    if (task.wordlist == nullptr) {
        err = "missing wordlist for seed batch";
        return false;
    }

    const size_t words_count = task.ids.size();
    out_ids.resize(candidates.size() * words_count);
    for (size_t candidate_index = 0; candidate_index < candidates.size(); ++candidate_index) {
        const std::vector<std::string> tokens = recovery_split_tokens(candidates[candidate_index]);
        if (tokens.size() != words_count) {
            err = "candidate word count mismatch";
            return false;
        }
        for (size_t word_index = 0; word_index < words_count; ++word_index) {
            const std::string norm = recovery_norm_token(tokens[word_index]);
            const auto it = task.wordlist->id_by_norm.find(norm);
            if (it == task.wordlist->id_by_norm.end()) {
                err = "candidate word not found in selected wordlist: " + tokens[word_index];
                return false;
            }
            out_ids[(candidate_index * words_count) + word_index] = static_cast<uint16_t>(it->second);
        }
    }
    return true;
}

static bool read_args(int argc, char** argv, AppConfig& config) {
    g_public_help_requested = false;
    for (int a = 1; a < argc; ++a) {
        const char* arg = argv[a];
        if (!is_public_recovery_flag(arg)) {
            std::fprintf(stderr, "[!] Error: %s is not available in Metal_Mnemonic_Recovery [!]\n", arg);
            return false;
        }

        if (std::strcmp(arg, "-h") == 0 || std::strcmp(arg, "-help") == 0) {
            g_public_help_requested = true;
            continue;
        }

        if (std::strcmp(arg, "-device") == 0) {
            if (++a >= argc) return false;
            parse_list_or_ranges<int>(argv[a], config.device_list, true);
            continue;
        }

        if (std::strcmp(arg, "-recovery") == 0) {
            config.recovery_mode = true;
            if (++a >= argc) return false;
            if (std::strcmp(argv[a], "-i") == 0) {
                if (++a >= argc) return false;
                config.recovery_queue.push_back({RecoveryQueueEntryType::File, argv[a]});
            } else {
                config.recovery_queue.push_back({RecoveryQueueEntryType::Phrase, argv[a]});
            }
            continue;
        }

        if (std::strcmp(arg, "-i") == 0) {
            std::fprintf(stderr, "[!] Error: use '-recovery -i FILE' to add template files [!]\n");
            return false;
        }

        if (std::strcmp(arg, "-wordlist") == 0) {
            if (++a >= argc) return false;
            config.forced_wordlist = argv[a];
            continue;
        }

        if (std::strcmp(arg, "-d") == 0) {
            if (++a >= argc) return false;
            config.derivation_files.emplace_back(argv[a]);
            continue;
        }

        if (std::strcmp(arg, "-d_type") == 0) {
            if (++a >= argc) return false;
            if (!recovery_derivation::parse_policy_argument(argv[a], config.derivation_policy)) {
                std::fprintf(stderr, "[!] Error: -d_type accepts only 1, 2, 3 or 4 [!]\n");
                return false;
            }
            continue;
        }

        if (std::strcmp(arg, "-c") == 0) {
            if (++a >= argc) return false;
            config.coin_types = argv[a];
            for (const char coin : config.coin_types) {
                if (!is_supported_public_target_family(coin)) {
                    std::fprintf(stderr, "[!] Error: unsupported -c letter '%c' [!]\n", coin);
                    return false;
                }
            }
            continue;
        }

        if (std::strcmp(arg, "-hash") == 0) {
            if (++a >= argc) return false;
            std::string parse_err;
            if (!parse_hash_target_argument(argv[a], config.hash_target, config.hash_target_hex, parse_err)) {
                std::fprintf(stderr, "[!] Error: invalid -hash: %s [!]\n", parse_err.c_str());
                return false;
            }
            config.use_hash_target = true;
            continue;
        }

        if (std::strcmp(arg, "-bf") == 0 || std::strcmp(arg, "-xb") == 0) {
            if (++a >= argc) return false;
            bool added = !config.bloom_files.empty();
            add_filter_path(argv[a], config.bloom_files, added, exts_xb, false);
            continue;
        }

        if (std::strcmp(arg, "-xx") == 0 || std::strcmp(arg, "-xu") == 0) {
            if (++a >= argc) return false;
            bool added = !config.xor_filter_files.empty();
            add_filter_path(argv[a], config.xor_filter_files, added, exts_xu, false);
            continue;
        }

        if (std::strcmp(arg, "-xc") == 0 || std::strcmp(arg, "-xuc") == 0 || std::strcmp(arg, "-xh") == 0) {
            if (++a >= argc) return false;
            continue;
        }

        if (std::strcmp(arg, "-pbkdf") == 0) {
            if (++a >= argc) return false;
            config.pbkdf_iterations = static_cast<uint64_t>(std::strtoull(argv[a], nullptr, 10));
            continue;
        }

        if (std::strcmp(arg, "-pass") == 0) {
            if (++a >= argc) return false;
            if (fs::exists(argv[a])) {
                config.passphrases_file = argv[a];
            } else {
                config.passphrases.emplace_back(argv[a]);
            }
            continue;
        }

        if (std::strcmp(arg, "-b") == 0) {
            if (++a >= argc) return false;
            config.block_count = static_cast<unsigned int>(std::strtoul(argv[a], nullptr, 10));
            config.custom_blocks = true;
            continue;
        }

        if (std::strcmp(arg, "-t") == 0) {
            if (++a >= argc) return false;
            config.block_threads = static_cast<unsigned int>(std::strtoul(argv[a], nullptr, 10));
            config.custom_threads = true;
            continue;
        }

        if (std::strcmp(arg, "-fsize") == 0) {
            if (++a >= argc) return false;
            config.found_limit = static_cast<uint32_t>(std::strtoul(argv[a], nullptr, 10));
            continue;
        }

        if (std::strcmp(arg, "-o") == 0) {
            if (++a >= argc) return false;
            config.output_file = argv[a];
            continue;
        }

        if (std::strcmp(arg, "-save") == 0) {
            config.save_output = true;
            continue;
        }

        if (std::strcmp(arg, "-silent") == 0) {
            config.silent = true;
            continue;
        }

        if (std::strcmp(arg, "-full") == 0) {
            config.full = true;
            continue;
        }
    }
    return true;
}

static bool initialize_filters(const AppConfig& config, std::string& err) {
    if (!config.bloom_files.empty()) {
        if (!load_bloom_filter_buffers(config.bloom_files)) {
            err = "failed to load bloom filters";
            return false;
        }
    }
    if (!config.xor_filter_files.empty()) {
        if (!load_xor_filter_buffers(config.xor_filter_files)) {
            err = "failed to load xor filters";
            return false;
        }
    }
    return true;
}

static std::vector<int> select_valid_devices(const std::vector<int>& requested) {
    NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
    const int device_count = static_cast<int>(devices.count);
    std::vector<int> out;
    std::unordered_set<int> seen;
    for (const int dev : requested) {
        if (dev < 0 || dev >= device_count) {
            std::fprintf(stderr, "[!] Warning: device %d is out of range [0..%d], skipped [!]\n", dev, std::max(0, device_count - 1));
            continue;
        }
        if (seen.insert(dev).second) out.emplace_back(dev);
    }
    if (out.empty() && device_count > 0) out.emplace_back(0);
    return out;
}

static void recovery_append_resource_candidate(std::vector<fs::path>& out, const fs::path& candidate) {
    if (candidate.empty()) {
        return;
    }
    if (std::find(out.begin(), out.end(), candidate) == out.end()) {
        out.push_back(candidate);
    }
}

static std::vector<fs::path> recovery_packaged_resource_locations(const std::string_view file_name) {
    std::vector<fs::path> candidates;
    if (file_name.empty()) {
        return candidates;
    }
    const fs::path resource_name(file_name);

    NSArray<NSString*>* arguments = [[NSProcessInfo processInfo] arguments];
    if (arguments.count > 0u && arguments[0] != nil) {
        std::error_code ec;
        fs::path executable_path([[arguments objectAtIndex:0] UTF8String]);
        executable_path = fs::absolute(executable_path, ec);
        if (!ec) {
            recovery_append_resource_candidate(candidates, executable_path.parent_path() / resource_name);
            recovery_append_resource_candidate(candidates, executable_path.parent_path() / "Resources" / resource_name);
        }
    }

    NSBundle* bundle = [NSBundle mainBundle];
    if (bundle != nil && bundle.resourcePath != nil) {
        recovery_append_resource_candidate(candidates, fs::path([[bundle resourcePath] UTF8String]) / resource_name);
    }
    return candidates;
}

static id<MTLLibrary> load_metal_library(id<MTLDevice> device, std::string& err) {
    const std::vector<fs::path> candidates = recovery_packaged_resource_locations("ChecksumKernels.metallib");
    std::string last_error = "failed to load metallib";
    for (const fs::path& candidate : candidates) {
        NSError* error = nil;
        NSString* lib_path = [NSString stringWithUTF8String:candidate.string().c_str()];
        NSURL* lib_url = [NSURL fileURLWithPath:lib_path];
        id<MTLLibrary> library = [device newLibraryWithURL:lib_url error:&error];
        if (library != nil) {
            return library;
        }
        if (error != nil) {
            last_error = [[error localizedDescription] UTF8String];
        }
    }
    err = last_error;
    return nil;
}

static std::string recovery_describe_ns_error(NSError* error) {
    if (error == nil) {
        return "unknown Metal error";
    }

    std::string message;
    if (error.localizedDescription != nil) {
        message = [error.localizedDescription UTF8String];
    } else {
        message = "unknown Metal error";
    }

    if (error.localizedFailureReason != nil) {
        const std::string reason = [error.localizedFailureReason UTF8String];
        if (!reason.empty() && reason != message) {
            message.append(" | reason: ");
            message.append(reason);
        }
    }

    NSDictionary* user_info = error.userInfo;
    if (user_info != nil) {
        id compile_log = [user_info objectForKey:@"MTLCompileLogErrorKey"];
        if ([compile_log isKindOfClass:[NSString class]]) {
            const std::string log = [static_cast<NSString*>(compile_log) UTF8String];
            if (!log.empty()) {
                message.append(" | compile-log: ");
                message.append(log);
            }
        }
    }

    return message;
}

static fs::path recovery_cache_directory_path() {
    const char* home = std::getenv("HOME");
    if (home != nullptr && *home != '\0') {
        return fs::path(home) / "Library" / "Caches" / "Metal_Mnemonic_Recovery";
    }
    std::error_code ec;
    const fs::path temp_dir = fs::temp_directory_path(ec);
    if (!ec) {
        return temp_dir / "Metal_Mnemonic_Recovery";
    }
    return fs::path(".");
}

static std::string recovery_sanitize_cache_component(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (const unsigned char ch : input) {
        if (std::isalnum(ch) != 0 || ch == '-' || ch == '_') {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) {
        out = "default";
    }
    return out;
}

static fs::path recovery_pipeline_archive_path(id<MTLDevice> device) {
    std::string device_name = "default";
    if (device != nil && [device name] != nil) {
        device_name = [[device name] UTF8String];
    }
    const std::string file_name =
        "metal-pipelines-v2-" + recovery_sanitize_cache_component(device_name) + ".binarchive";
    return recovery_cache_directory_path() / file_name;
}

static PipelineArchiveContext prepare_pipeline_archive(id<MTLDevice> device) {
    PipelineArchiveContext context;
    if (device == nil) {
        return context;
    }
    if (@available(macOS 11.0, *)) {
        const fs::path archive_path = recovery_pipeline_archive_path(device);
        std::error_code ec;
        if (archive_path.has_parent_path()) {
            fs::create_directories(archive_path.parent_path(), ec);
        }
        NSString* archive_path_ns = [NSString stringWithUTF8String:archive_path.string().c_str()];
        context.url = [NSURL fileURLWithPath:archive_path_ns];

        MTLBinaryArchiveDescriptor* descriptor = [[MTLBinaryArchiveDescriptor alloc] init];
        if (fs::exists(archive_path, ec) && !ec) {
            descriptor.url = context.url;
        }

        NSError* error = nil;
        context.archive = [device newBinaryArchiveWithDescriptor:descriptor error:&error];
        if (context.archive == nil && descriptor.url != nil) {
            fs::remove(archive_path, ec);
            error = nil;
            descriptor = [[MTLBinaryArchiveDescriptor alloc] init];
            context.archive = [device newBinaryArchiveWithDescriptor:descriptor error:&error];
        }
    }
    return context;
}

static void persist_pipeline_archive(const PipelineArchiveContext& context) {
    if (context.archive == nil || context.url == nil) {
        return;
    }
    if (@available(macOS 11.0, *)) {
        NSError* error = nil;
        (void)[context.archive serializeToURL:context.url error:&error];
    }
}

static id<MTLComputePipelineState> load_compute_pipeline(id<MTLDevice> device,
                                                         id<MTLLibrary> library,
                                                         id<MTLBinaryArchive> binary_archive,
                                                         const char* function_name,
                                                         std::string& err) {
    if (library == nil) {
        err = "Metal library unavailable";
        return nil;
    }
    id<MTLFunction> function = [library newFunctionWithName:[NSString stringWithUTF8String:function_name]];
    if (!function) {
        err = std::string("failed to load Metal function: ") + function_name;
        return nil;
    }
    NSError* error = nil;
    id<MTLComputePipelineState> pipeline = nil;
    if (@available(macOS 11.0, *)) {
        MTLComputePipelineDescriptor* descriptor = [[MTLComputePipelineDescriptor alloc] init];
        descriptor.computeFunction = function;
        if (binary_archive != nil) {
            descriptor.binaryArchives = @[ binary_archive ];
        }
        pipeline = [device newComputePipelineStateWithDescriptor:descriptor
                                                         options:MTLPipelineOptionNone
                                                      reflection:nil
                                                           error:&error];
        if (pipeline == nil) {
            error = nil;
            pipeline = [device newComputePipelineStateWithFunction:function error:&error];
        }
    } else {
        pipeline = [device newComputePipelineStateWithFunction:function error:&error];
    }
    if (!pipeline) {
        err = recovery_describe_ns_error(error);
    }
    return pipeline;
}

static uint32_t choose_stage_capacity(const AppConfig& config) {
    if (config.custom_blocks && config.block_count > 0u) {
        const uint32_t stage_threads =
            config.custom_threads ? config.block_threads : kRecoveryDefaultStageSizingThreads;
        const uint64_t requested = static_cast<uint64_t>(std::max(stage_threads, 32u)) *
                                   static_cast<uint64_t>(config.block_count) * 16ull;
        return static_cast<uint32_t>(std::clamp<uint64_t>(requested, kRecoveryMinStageCapacity, kRecoveryMaxStageCapacity));
    }
    return kRecoveryDefaultStageCapacity;
}

}  // namespace

int RunRecoveryApp(int argc, char** argv) {
    @autoreleasepool {
        setlocale(LC_ALL, "en_US.UTF-8");
        std::ios_base::sync_with_stdio(false);
        std::cin.tie(nullptr);

        std::printf("[!] %s %s by Mikhail Khoroshavin aka \"XopMC\"\n",
            metal_mnemonic_recovery::kProjectName,
            metal_mnemonic_recovery::kProjectVersion);
        std::printf("[!] Standalone BIP39 mnemonic recovery tool (Metal/macOS path) [!]\n");

        if (argc == 1) {
            printHelp();
            return 0;
        }

        AppConfig config;
        if (!read_args(argc, argv, config)) {
            if (g_public_help_requested) {
                printHelp();
                return 0;
            }
            return 1;
        }
        if (g_public_help_requested) {
            printHelp();
            return 0;
        }
        if (!config.recovery_mode) {
            std::fprintf(stderr, "[!] Error: this release supports only -recovery mode [!]\n");
            return 1;
        }
        if (config.recovery_queue.empty()) {
            std::fprintf(stderr, "[!] Error: provide at least one recovery source via -recovery \"...\" or -recovery -i FILE [!]\n");
            return 1;
        }
        if (config.derivation_files.empty()) {
            std::fprintf(stderr, "[!] Error: -d FILE is required [!]\n");
            return 1;
        }
        if (!config.use_hash_target && config.bloom_files.empty() && config.xor_filter_files.empty() && !config.full) {
            std::fprintf(stderr, "[!] Error: provide -hash, filters, or -full for a recovery run [!]\n");
            return 1;
        }
        if (!config.passphrases_file.empty()) {
            std::ifstream pass_file(config.passphrases_file.c_str(), std::ios::binary);
            std::string line;
            while (std::getline(pass_file, line)) {
                line = recovery_trim_spaces_copy(line);
                if (!line.empty()) config.passphrases.emplace_back(line);
            }
        }

        std::vector<RecoveryTemplateInput> templates;
        std::string err;
        if (!expand_templates(config, templates, err)) {
            std::fprintf(stderr, "[!] Recovery error: %s [!]\n", err.c_str());
            return 1;
        }
        std::vector<RecoveryWordlist> wordlists;
        if (!load_wordlists(config, templates, wordlists, err)) {
            std::fprintf(stderr, "[!] Recovery error: %s [!]\n", err.c_str());
            return 1;
        }
        if (!initialize_filters(config, err)) {
            std::fprintf(stderr, "[!] Recovery error: %s [!]\n", err.c_str());
            return 1;
        }
        std::vector<std::string> derivations;
        if (!load_derivation_strings(config.derivation_files, derivations, err)) {
            std::fprintf(stderr, "[!] Recovery error: %s [!]\n", err.c_str());
            return 1;
        }
        const bool filters_requested = !config.bloom_files.empty() || !config.xor_filter_files.empty();
        std::vector<RecoveryPreparedDerivation> prepared_derivations;
        if (!recovery_prepare_derivations(derivations, prepared_derivations, err)) {
            std::fprintf(stderr, "[!] Recovery error: %s [!]\n", err.c_str());
            return 1;
        }
        const std::vector<std::string> passphrases = config.passphrases.empty() ? std::vector<std::string>{""} : config.passphrases;

        std::vector<RecoveryPreparedTask> tasks;
        tasks.reserve(templates.size());
        std::printf("[!] Recovery templates loaded: %llu [!]\n", static_cast<unsigned long long>(templates.size()));
        for (const RecoveryTemplateInput& tmpl : templates) {
            RecoveryPreparedTask task;
            std::string prep_err;
            if (!recovery_prepare_task(tmpl, wordlists, task, prep_err)) {
                std::fprintf(stderr, "[!] Recovery skip: %s -> %s [!]\n", tmpl.source.c_str(), prep_err.c_str());
                continue;
            }
            if (task.added_stars > 0) {
                std::printf("[!] Recovery normalized word count by appending %llu wildcard(s). [!]\n", static_cast<unsigned long long>(task.added_stars));
            }
            for (const auto& repl : task.replacements) {
                std::printf("[!] Recovery replace: '%s' -> '%s' [!]\n", repl.first.c_str(), repl.second.c_str());
            }
            tasks.emplace_back(std::move(task));
        }
        if (tasks.empty()) {
            std::fprintf(stderr, "[!] Recovery error: no valid tasks to process [!]\n");
            return 1;
        }

        std::vector<int> active_devices = select_valid_devices(config.device_list);
        if (active_devices.empty()) {
            std::fprintf(stderr, "[!] Error: no valid Metal devices selected [!]\n");
            return 1;
        }
        const int active_device_index = active_devices.front();
        NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
        id<MTLDevice> device = devices[active_device_index];
        id<MTLCommandQueue> queue = [device newCommandQueue];
        std::string library_err;
        id<MTLLibrary> metal_library = load_metal_library(device, library_err);
        if (metal_library == nil) {
            std::fprintf(stderr, "[!] Recovery error: Metal library unavailable: %s [!]\n", library_err.c_str());
            return 1;
        }
        PipelineArchiveContext pipeline_archive = prepare_pipeline_archive(device);
        RecoveryExecutionPlan execution_plan;
        if (!recovery_prepare_execution_plan(config, execution_plan, err)) {
            std::fprintf(stderr, "[!] Recovery error: %s [!]\n", err.c_str());
            return 1;
        }
        const RecoveryFilterKernelMode filter_kernel_mode = recovery_select_filter_kernel_mode(filters_requested);
        const char* ed_eval_kernel_name = "workerRecoveryEvalEd25519StageNoFilter";
        const char* secp_eval_kernel_name = "workerRecoveryEvalSecpStageNoFilter";
        switch (filter_kernel_mode) {
        case RecoveryFilterKernelMode::BloomOnly:
            ed_eval_kernel_name = "workerRecoveryEvalEd25519StageBloomOnly";
            secp_eval_kernel_name = "workerRecoveryEvalSecpStageBloomOnly";
            break;
        case RecoveryFilterKernelMode::XorSingle:
            ed_eval_kernel_name = "workerRecoveryEvalEd25519StageXorSingle";
            secp_eval_kernel_name = "workerRecoveryEvalSecpStageXorSingle";
            break;
        case RecoveryFilterKernelMode::Full:
            ed_eval_kernel_name = "workerRecoveryEvalEd25519Stage";
            secp_eval_kernel_name = "workerRecoveryEvalSecpStage";
            break;
        case RecoveryFilterKernelMode::None:
            break;
        }

        std::vector<PipelineBuildRequest> pipeline_requests;
        pipeline_requests.reserve(24);
        auto add_pipeline_request = [&](const bool enabled,
                                        const char* function_name,
                                        const char* label,
                                        const bool required = true) {
            if (enabled) {
                pipeline_requests.push_back({function_name, label, required, nil, {}});
            }
        };

        add_pipeline_request(true, "workerRecoveryChecksumPrepareBatch", "checksum prepare");
        add_pipeline_request(true, "workerRecoveryChecksumHitRecords", "checksum hit");
        add_pipeline_request(true, "workerRecoveryChecksumHitRecords12", "checksum hit 12", false);
        add_pipeline_request(true, "workerRecoveryChecksumHitRecords15", "checksum hit 15", false);
        add_pipeline_request(true, "workerRecoveryChecksumHitRecords18", "checksum hit 18", false);
        add_pipeline_request(true, "workerRecoveryChecksumHitRecords21", "checksum hit 21", false);
        add_pipeline_request(true, "workerRecoveryChecksumHitRecords24", "checksum hit 24", false);
        add_pipeline_request(true, "workerRecoveryMasterSeedBatch", "master seed");
        add_pipeline_request(true, "workerRecoverySecpMasterBatch", "secp master seed", false);
        add_pipeline_request(true, "workerRecoveryPrepareIndirectDispatch", "indirect dispatch", false);
        add_pipeline_request(true, "workerRecoveryRuntimeScheduleChecksumBatches", "runtime checksum schedule");
        add_pipeline_request(true, "workerRecoveryRuntimeConsumeChecksumBatches", "runtime checksum");
        add_pipeline_request(true, "workerRecoveryRuntimeProduceSeeds", "runtime seed");
        add_pipeline_request(execution_plan.need_ed_derive, "workerRecoveryDeriveEd25519Stage", "ed25519 derive");
        add_pipeline_request(execution_plan.need_ed_targets, ed_eval_kernel_name, "ed25519 eval");
        add_pipeline_request(execution_plan.need_ed_derive, "workerRecoveryRuntimeConsumeEdSeeds", "runtime ed");
        add_pipeline_request(execution_plan.need_secp_derive, "workerRecoveryDeriveSecpStage", "secp derive");
        add_pipeline_request(execution_plan.need_secp_derive && execution_plan.need_ed_targets, "workerRecoveryPromoteSecpToEd25519Stage", "secp->ed25519");
        add_pipeline_request(execution_plan.need_secp_derive, "workerRecoveryRuntimeConsumeSecpSeeds", "runtime secp");
        add_pipeline_request(execution_plan.need_ed_derive && execution_plan.need_secp_targets, "workerRecoveryPromoteEd25519ToSecpStage", "ed25519->secp");
        add_pipeline_request(execution_plan.need_secp_derive && execution_plan.need_ed_targets, "workerRecoveryRuntimeConsumePromotedSecpStages", "runtime ed promote");
        add_pipeline_request(execution_plan.need_ed_derive && execution_plan.need_secp_targets, "workerRecoveryRuntimeConsumePromotedEdStages", "runtime secp promote");
        add_pipeline_request(execution_plan.need_secp_targets, secp_eval_kernel_name, "secp eval");
        add_pipeline_request(execution_plan.need_secp_targets, "workerRecoveryEvalSecpMasterBatchNoFilter", "secp eval master", false);
        add_pipeline_request(execution_plan.need_secp_targets, "workerRecoveryEvalSecpMasterBatchCompressedOnly", "secp eval master compressed", false);
        add_pipeline_request(execution_plan.need_secp_targets, "workerRecoveryEvalSecpMasterBatchCompressedOnlyNoReuse", "secp eval master compressed noreuse", false);

        auto* pipeline_request_ptr = pipeline_requests.data();
        if (pipeline_archive.archive != nil) {
            for (size_t index = 0; index < pipeline_requests.size(); ++index) {
                PipelineBuildRequest& request = pipeline_request_ptr[index];
                request.pipeline = load_compute_pipeline(device,
                                                         metal_library,
                                                         pipeline_archive.archive,
                                                         request.function_name,
                                                         request.error);
            }
        } else {
            dispatch_queue_t pipeline_queue = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);
            dispatch_apply(pipeline_requests.size(), pipeline_queue, ^(size_t index) {
                PipelineBuildRequest& request = pipeline_request_ptr[index];
                request.pipeline = load_compute_pipeline(device,
                                                         metal_library,
                                                         nil,
                                                         request.function_name,
                                                         request.error);
            });
        }
        for (const PipelineBuildRequest& request : pipeline_requests) {
            if (request.pipeline == nil && request.required) {
                std::fprintf(stderr, "[!] Recovery error: Metal %s pipeline unavailable: %s [!]\n",
                             request.label,
                             request.error.c_str());
                return 1;
            }
        }
        persist_pipeline_archive(pipeline_archive);
        auto pipeline_for = [&](const char* function_name) -> id<MTLComputePipelineState> {
            for (const PipelineBuildRequest& request : pipeline_requests) {
                if (std::strcmp(request.function_name, function_name) == 0) {
                    return request.pipeline;
                }
            }
            return nil;
        };
        id<MTLComputePipelineState> checksum_prepare_pipeline = pipeline_for("workerRecoveryChecksumPrepareBatch");
        id<MTLComputePipelineState> checksum_hit_pipeline = pipeline_for("workerRecoveryChecksumHitRecords");
        id<MTLComputePipelineState> checksum_hit_12_pipeline = pipeline_for("workerRecoveryChecksumHitRecords12");
        id<MTLComputePipelineState> checksum_hit_15_pipeline = pipeline_for("workerRecoveryChecksumHitRecords15");
        id<MTLComputePipelineState> checksum_hit_18_pipeline = pipeline_for("workerRecoveryChecksumHitRecords18");
        id<MTLComputePipelineState> checksum_hit_21_pipeline = pipeline_for("workerRecoveryChecksumHitRecords21");
        id<MTLComputePipelineState> checksum_hit_24_pipeline = pipeline_for("workerRecoveryChecksumHitRecords24");
        id<MTLComputePipelineState> master_seed_pipeline = pipeline_for("workerRecoveryMasterSeedBatch");
        id<MTLComputePipelineState> secp_master_seed_pipeline = pipeline_for("workerRecoverySecpMasterBatch");
        id<MTLComputePipelineState> indirect_dispatch_prepare_pipeline = pipeline_for("workerRecoveryPrepareIndirectDispatch");
        id<MTLComputePipelineState> runtime_checksum_schedule_pipeline = pipeline_for("workerRecoveryRuntimeScheduleChecksumBatches");
        id<MTLComputePipelineState> runtime_checksum_consume_pipeline = pipeline_for("workerRecoveryRuntimeConsumeChecksumBatches");
        id<MTLComputePipelineState> runtime_seed_produce_pipeline = pipeline_for("workerRecoveryRuntimeProduceSeeds");
        id<MTLComputePipelineState> ed25519_derive_pipeline = pipeline_for("workerRecoveryDeriveEd25519Stage");
        id<MTLComputePipelineState> ed25519_eval_pipeline = pipeline_for(ed_eval_kernel_name);
        id<MTLComputePipelineState> runtime_ed_consume_pipeline = pipeline_for("workerRecoveryRuntimeConsumeEdSeeds");
        id<MTLComputePipelineState> runtime_ed_promote_consume_pipeline = pipeline_for("workerRecoveryRuntimeConsumePromotedSecpStages");
        id<MTLComputePipelineState> secp_derive_pipeline = pipeline_for("workerRecoveryDeriveSecpStage");
        id<MTLComputePipelineState> secp_to_ed25519_pipeline = pipeline_for("workerRecoveryPromoteSecpToEd25519Stage");
        id<MTLComputePipelineState> runtime_secp_consume_pipeline = pipeline_for("workerRecoveryRuntimeConsumeSecpSeeds");
        id<MTLComputePipelineState> ed25519_to_secp_pipeline = pipeline_for("workerRecoveryPromoteEd25519ToSecpStage");
        id<MTLComputePipelineState> runtime_secp_promote_consume_pipeline = pipeline_for("workerRecoveryRuntimeConsumePromotedEdStages");
        id<MTLComputePipelineState> secp_eval_pipeline = pipeline_for(secp_eval_kernel_name);
        id<MTLComputePipelineState> secp_eval_master_pipeline = pipeline_for("workerRecoveryEvalSecpMasterBatchNoFilter");
        id<MTLComputePipelineState> secp_eval_master_compressed_pipeline = pipeline_for("workerRecoveryEvalSecpMasterBatchCompressedOnly");
        id<MTLComputePipelineState> secp_eval_master_compressed_noreuse_pipeline = pipeline_for("workerRecoveryEvalSecpMasterBatchCompressedOnlyNoReuse");

        const std::time_t start_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::printf("[!] Active Metal devices: %d\n", active_device_index);
        std::printf("[!] Program started at: %s", std::ctime(&start_time));
        const uint64_t hash_checks_per_candidate =
            recovery_hash_checks_per_candidate(execution_plan, prepared_derivations.size());

        auto backend = std::make_unique<MetalRecoveryBackend>(
            device,
            queue,
            checksum_prepare_pipeline,
            checksum_hit_pipeline,
            checksum_hit_12_pipeline,
            checksum_hit_15_pipeline,
            checksum_hit_18_pipeline,
            checksum_hit_21_pipeline,
            checksum_hit_24_pipeline,
            master_seed_pipeline,
            secp_master_seed_pipeline,
            indirect_dispatch_prepare_pipeline,
            ed25519_derive_pipeline,
            secp_derive_pipeline,
            secp_to_ed25519_pipeline,
            ed25519_to_secp_pipeline,
            ed25519_eval_pipeline,
            secp_eval_pipeline,
            secp_eval_master_pipeline,
            secp_eval_master_compressed_pipeline,
            secp_eval_master_compressed_noreuse_pipeline,
            runtime_checksum_schedule_pipeline,
            runtime_checksum_consume_pipeline,
            runtime_seed_produce_pipeline,
            runtime_secp_consume_pipeline,
            runtime_ed_consume_pipeline,
            runtime_ed_promote_consume_pipeline,
            runtime_secp_promote_consume_pipeline,
            std::move(execution_plan),
            filter_kernel_mode,
            filters_requested,
            config.block_threads,
            config.block_count,
            choose_stage_capacity(config));

        FILE* out_file = std::fopen(config.output_file.c_str(), "a");
        if (out_file == nullptr) {
            std::fprintf(stderr, "[!] Error: failed to open output file '%s' [!]\n", config.output_file.c_str());
            return 1;
        }

        RecoveryLiveStatusState live_status;
        live_status.hash_checks_per_candidate = hash_checks_per_candidate;
        backend->set_live_status(&live_status);

        std::thread speed_thread(recovery_speed_thread_func, &live_status);
        auto stop_speed_thread = [&]() {
            live_status.stop.store(true, std::memory_order_relaxed);
            if (speed_thread.joinable()) {
                speed_thread.join();
            }
            recovery_console_clear_status_line();
        };

        RecoveryStats stats;
        for (size_t idx = 0; idx < tasks.size(); ++idx) {
            uint64_t tested = 0;
            std::string task_err;
            std::vector<std::vector<FoundRecord>> passphrase_records;
            const uint64_t checksum_valid_before =
                live_status.checksum_valid_total.load(std::memory_order_relaxed);
            if (!backend->process_task(tasks[idx],
                                       prepared_derivations,
                                       config,
                                       passphrases,
                                       passphrase_records,
                                       tested,
                                       task_err)) {
                stop_speed_thread();
                std::fprintf(stderr, "[!] Recovery task execution error: %s [!]\n", task_err.c_str());
                std::fclose(out_file);
                return 1;
            }

            stats.tested_total += tested;
            live_status.tested_total.store(stats.tested_total, std::memory_order_relaxed);
            const uint64_t task_checksum_valid =
                live_status.checksum_valid_total.load(std::memory_order_relaxed) - checksum_valid_before;
            for (size_t passphrase_index = 0; passphrase_index < passphrase_records.size(); ++passphrase_index) {
                for (const FoundRecord& record : passphrase_records[passphrase_index]) {
                    if (stats.found_total >= config.found_limit) break;
                    std::string line;
                    if (!recovery_format::format_found_line(record,
                                                           tasks[idx].wordlist->words,
                                                           derivations,
                                                           passphrases,
                                                           config.save_output,
                                                           line,
                                                           task_err)) {
                        stop_speed_thread();
                        std::fprintf(stderr, "[!] Recovery formatting error: %s [!]\n", task_err.c_str());
                        std::fclose(out_file);
                        return 1;
                    }
                    std::fprintf(out_file, "%s\n", line.c_str());
                    if (!config.silent) {
                        recovery_console_write_stdout_line(line + "\n");
                    }
                    ++stats.found_total;
                    live_status.found_total.store(stats.found_total, std::memory_order_relaxed);
                }
                if (stats.found_total >= config.found_limit) {
                    break;
                }
            }
            {
                std::ostringstream line;
                line << "[!] Recovery task done ("
                     << static_cast<unsigned long long>(idx + 1u)
                     << "/"
                     << static_cast<unsigned long long>(tasks.size())
                     << "): tested="
                     << static_cast<unsigned long long>(tested)
                     << " checksum-valid="
                     << static_cast<unsigned long long>(task_checksum_valid)
                     << " [!]\n";
                recovery_console_write_stdout_line(line.str());
            }
            if (stats.found_total >= config.found_limit) {
                break;
            }
        }

        stop_speed_thread();
        std::fclose(out_file);

        const std::time_t end_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << "\n[!] Recovery tested " << stats.tested_total
                  << " candidates. Checksum-valid: "
                  << live_status.checksum_valid_total.load(std::memory_order_relaxed)
                  << ". Found: " << stats.found_total
                  << ". Program finished at " << std::ctime(&end_time);
        return 0;
    }
}
