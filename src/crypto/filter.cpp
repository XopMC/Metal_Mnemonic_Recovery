#include "recovery/filter.h"
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <memory>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <filesystem>
namespace fs = std::filesystem;

const std::vector<std::string> exts_xc = { ".xor_c", ".xc" };
const std::vector<std::string> exts_xu = { ".xor_u", ".xu" };
const std::vector<std::string> exts_xb = { ".blf" };
const std::vector<std::string> exts_xuc = { ".xor_uc", ".xuc" };
const std::vector<std::string> exts_xh = { ".xor_hc", ".xhc" };

// iequals: performs iequals.
static bool iequals(const std::string& a, const std::string& b) {
	if (a.size() != b.size()) {
		return false;
	}
	for (size_t i = 0; i < a.size(); ++i) {
		if (std::tolower(static_cast<unsigned char>(a[i])) !=
			std::tolower(static_cast<unsigned char>(b[i]))) {
			return false;
		}
	}
	return true;
}

// Returns true when the file extension matches one of allowed extensions (case-insensitive).
static bool has_allowed_ext_ci(const fs::path& p, const std::vector<std::string>& exts) {
	const std::string eext = p.extension().string();
	for (const auto& ext : exts) {
		if (iequals(eext, ext)) return true;
	}
	return false;
}

// Returns true if the file path is already in the destination list.
static bool already_added(const std::vector<std::string>& files, const std::string& path) {
	return std::find(files.begin(), files.end(), path) != files.end();
}


// Adds a single filter file or all matching files from a directory into outFiles.
void add_filter_path(const char* p,
	std::vector<std::string>& outFiles,
	bool& useFlag,
	const std::vector<std::string>& allowedExts,
	bool recursive)
{
	std::error_code ec;



	const fs::path& pth(p);

	if (!fs::exists(pth, ec)) {
		std::cerr << "[-] path not found: " << pth.string() << "\n";
		return;
	}

	if (fs::is_directory(pth, ec)) {
		auto add_if_match = [&](const fs::directory_entry& e) {
			if (!e.is_regular_file(ec)) return;
			if (!has_allowed_ext_ci(e.path(), allowedExts)) return;

			const std::string s = e.path().string();
			if (!already_added(outFiles, s)) {
				outFiles.push_back(s);
				std::cerr << "[!] " << s << " Added [!]\n";
			}
			};

		if (recursive) {
			for (const auto& e : fs::recursive_directory_iterator(
				p, fs::directory_options::skip_permission_denied, ec))
			{
				if (ec) break;
				add_if_match(e);
			}
		}
		else {
			for (const auto& e : fs::directory_iterator(
				p, fs::directory_options::skip_permission_denied, ec))
			{
				if (ec) break;
				add_if_match(e);
			}
		}

		if (!outFiles.empty()) useFlag = true;
		return;
	}

	const std::string s = pth.string();
	if (!already_added(outFiles, s)) {
		outFiles.push_back(s);
		std::cerr << "[!] " << s << " Added [!]\n";
	}
	useFlag = true;
}

namespace {

RecoveryFilterSet g_filter_set;

}

const RecoveryFilterSet& recovery_filter_set() {
	return g_filter_set;
}

// Sets all 20 derived Bloom bit positions for HASH160.
void bloom_set_hash160(unsigned char* bloom, uint32_t* h) {
	unsigned int t;
	t = BH00(h); BLOOM_SET_BIT(t);
	t = BH01(h); BLOOM_SET_BIT(t);
	t = BH02(h); BLOOM_SET_BIT(t);
	t = BH03(h); BLOOM_SET_BIT(t);
	t = BH04(h); BLOOM_SET_BIT(t);
	t = BH05(h); BLOOM_SET_BIT(t);
	t = BH06(h); BLOOM_SET_BIT(t);
	t = BH07(h); BLOOM_SET_BIT(t);
	t = BH08(h); BLOOM_SET_BIT(t);
	t = BH09(h); BLOOM_SET_BIT(t);
	t = BH10(h); BLOOM_SET_BIT(t);
	t = BH11(h); BLOOM_SET_BIT(t);
	t = BH12(h); BLOOM_SET_BIT(t);
	t = BH13(h); BLOOM_SET_BIT(t);
	t = BH14(h); BLOOM_SET_BIT(t);
	t = BH15(h); BLOOM_SET_BIT(t);
	t = BH16(h); BLOOM_SET_BIT(t);
	t = BH17(h); BLOOM_SET_BIT(t);
	t = BH18(h); BLOOM_SET_BIT(t);
	t = BH19(h); BLOOM_SET_BIT(t);
}

// SplitMix64 step used to initialize a deterministic XOR filter hash seed.
static uint64_t rng_splitmix64_step(uint64_t* seed)
{
	uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
	z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
	return z ^ (z >> 31);
}

bool load_xor_filter_buffers(const std::vector<std::string>& xorFiles)
{
	uint64_t rng_counter = 0x726b2b9d438b9d4d;
	g_filter_set.xor_seed = rng_splitmix64_step(&rng_counter);
	g_filter_set.xor_count = 0;

	if (xorFiles.size() > 25) {
		std::cerr << "[!] Too many xor files, maximum supported is 25." << std::endl;
		return false;
	}

	for (size_t i = 0; i < xorFiles.size(); ++i) {
		const auto& xorFile = xorFiles[i];
		fprintf(stderr, "[!] Initializing XOR Filter [file=%s]\n", xorFile.c_str());
		std::string raw = xorFiles[i];
		size_t pos = raw.find_last_of("/\\");
		if (pos != std::string::npos) {
			raw = raw.substr(pos + 1);
		}
		std::ifstream in(xorFile, std::ios::binary);
			if (!in.is_open()) {
				return false;
			}

			in.read(reinterpret_cast<char*>(&g_filter_set.size[i]), sizeof(size_t));
			in.read(reinterpret_cast<char*>(&g_filter_set.arrayLength[i]), sizeof(size_t));
			in.read(reinterpret_cast<char*>(&g_filter_set.segmentCount[i]), sizeof(size_t));
			in.read(reinterpret_cast<char*>(&g_filter_set.segmentCountLength[i]), sizeof(size_t));
			in.read(reinterpret_cast<char*>(&g_filter_set.segmentLength[i]), sizeof(size_t));
			in.read(reinterpret_cast<char*>(&g_filter_set.segmentLengthMask[i]), sizeof(size_t));
			if (!in.good()) {
				std::cerr << "[!] Failed to read XOR filter header '" << xorFile << "'." << std::endl;
				in.close();
				return false;
			}
			const uint64_t xor_bytes = sizeof(uint32_t) * g_filter_set.arrayLength[i];

			std::unique_ptr<uint32_t[]> heap_filter(new (std::nothrow) uint32_t[g_filter_set.arrayLength[i]]);
			if (!heap_filter) {
				std::cerr << "[!] Failed to allocate XOR filter buffer '" << xorFile << "'." << std::endl;
				in.close();
				return false;
			}
			in.read(reinterpret_cast<char*>(heap_filter.get()), xor_bytes);
			if (!in.good()) {
				std::cerr << "[!] Failed to read XOR filter body '" << xorFile << "'." << std::endl;
				in.close();
				return false;
			}

			g_filter_set.fingerprints[i] = heap_filter.release();

			in.close();
			g_filter_set.xor_count++;
		}
	return true;
}

bool load_bloom_filter_buffers(const std::vector<std::string>& bloomFiles) {
	if (bloomFiles.size() > 100) {
		std::cerr << "[!] Too many bloom files, maximum supported is 100." << std::endl;
		return false;
	}
	g_filter_set.bloom_count = 0;

	for (size_t i = 0; i < bloomFiles.size(); ++i) {
		const auto& bloomFile = bloomFiles[i];
		int fd = open(bloomFile.c_str(), O_RDONLY);
		if (fd == -1) {
			std::cerr << "[!] Failed to open '" << bloomFile << "'." << std::endl;
			return false;
		}

		struct stat st;
		if (fstat(fd, &st) != 0) {
			std::cerr << "[!] fstat failed for '" << bloomFile << "'." << std::endl;
			close(fd);
			return false;
		}
		if ((size_t)st.st_size < BLOOM_SIZE) {
			std::cerr << "[!] File too small for bloom '" << bloomFile << "'." << std::endl;
			close(fd);
			return false;
		}

		unsigned char* mmap_ptr = static_cast<unsigned char*>(mmap(
			NULL,
			BLOOM_SIZE,
			PROT_READ,
			MAP_SHARED
#ifdef MAP_POPULATE
			| MAP_POPULATE
#endif
			,
			fd,
			0
		));

		if (mmap_ptr == MAP_FAILED) {
			std::cerr << "[!] Failed to mmap '" << bloomFile << "'." << std::endl;
			close(fd);
			return false;
		}

		g_filter_set.blooms[i] = mmap_ptr;
		++g_filter_set.bloom_count;
		close(fd);
	}

	return true;
}
