// PatchAuthKey.cpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#include "../../Framework.h"
#include "../../util.h"
#include "PatchAuthKey.hpp"
#include "PatchSSL.hpp"  // For PatternByte

// Forward declarations from PatchSSL.cpp
extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);

// Safe pattern search that checks memory accessibility
static std::byte* SafeFindPattern(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern)
{
	if (pattern.empty() || search_length < pattern.size()) {
		return nullptr;
	}

	size_t i = 0;
	while (i <= search_length - pattern.size()) {
		// Check if this memory region is readable using VirtualQuery
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(start_address + i, &mbi, sizeof(mbi)) == 0) {
			// Can't query, skip ahead
			i += 0x1000;
			continue;
		}

		// Check if memory is readable
		if (mbi.State != MEM_COMMIT ||
			(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
			!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY))) {
			// Skip this region
			size_t region_end = reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize;
			size_t current_pos = reinterpret_cast<size_t>(start_address + i);
			if (region_end > current_pos) {
				i += (region_end - current_pos);
			} else {
				i += 0x1000;
			}
			continue;
		}

		// Calculate how many bytes we can safely read in this region
		size_t region_end = reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize;
		size_t current_pos = reinterpret_cast<size_t>(start_address + i);
		size_t bytes_in_region = region_end - current_pos;

		// Search within this readable region
		size_t search_end = (std::min)(i + bytes_in_region, search_length - pattern.size() + 1);

		for (; i < search_end; ++i) {
			bool match = true;
			for (size_t j = 0; j < pattern.size(); ++j) {
				if (!pattern[j].is_wildcard) {
					if (start_address[i + j] != pattern[j].value.value()) {
						match = false;
						break;
					}
				}
			}
			if (match) {
				return &start_address[i];
			}
		}
	}
	return nullptr;
}

// Find all matches safely
static std::vector<std::byte*> SafeFindAllPatterns(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern)
{
	std::vector<std::byte*> results;

	if (pattern.empty() || search_length < pattern.size()) {
		return results;
	}

	size_t i = 0;
	while (i <= search_length - pattern.size()) {
		// Check if this memory region is readable
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(start_address + i, &mbi, sizeof(mbi)) == 0) {
			i += 0x1000;
			continue;
		}

		if (mbi.State != MEM_COMMIT ||
			(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
			!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY))) {
			size_t region_end = reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize;
			size_t current_pos = reinterpret_cast<size_t>(start_address + i);
			if (region_end > current_pos) {
				i += (region_end - current_pos);
			} else {
				i += 0x1000;
			}
			continue;
		}

		size_t region_end = reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize;
		size_t current_pos = reinterpret_cast<size_t>(start_address + i);
		size_t bytes_in_region = region_end - current_pos;
		size_t search_end = (std::min)(i + bytes_in_region, search_length - pattern.size() + 1);

		for (; i < search_end; ++i) {
			bool match = true;
			for (size_t j = 0; j < pattern.size(); ++j) {
				if (!pattern[j].is_wildcard) {
					if (start_address[i + j] != pattern[j].value.value()) {
						match = false;
						break;
					}
				}
			}
			if (match) {
				results.push_back(&start_address[i]);
			}
		}
	}
	return results;
}

PatchAuthKey::PatchAuthKey()
{
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);
	size_ = GetModuleSize(hModule);
	offset_ = GetEntryPointOffset(hModule);
	entryPoint_ = baseAddress_ + offset_;
}

BOOL PatchAuthKey::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("AuthKeyPatch")

	BOOST_LOG_TRIVIAL(info) << "=== AUTH KEY PATTERN SEARCH (DEBUG MODE - NO PATCHING) ===";
	BOOST_LOG_TRIVIAL(info) << "Base: 0x" << std::hex << baseAddress_ << ", Entry: 0x" << entryPoint_ << ", Size: 0x" << size_;

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	// Define multiple patterns to try, from most specific to most generic
	// Pattern based on v1.12 memory dump:
	// Before: 83 C4 14 F7 D8
	// Patch:  1B C0 83 C0 01
	// After:  5E 81 C4 D0 02 00 00 C3

	struct PatternInfo {
		const char* name;
		const char* pattern;
		int patch_offset;  // Offset from pattern start to patch point
	};

	PatternInfo patterns[] = {
		// Most specific - full function epilogue
		{ "Full epilogue (v1.12)", "F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3", 2 },

		// Without specific stack size
		{ "Epilogue generic stack", "F7 D8 1B C0 83 C0 01 5E 81 C4", 2 },

		// Core return value calculation
		{ "Return calc + pop", "1B C0 83 C0 01 5E 81 C4", 0 },

		// Just the sbb/add sequence with context
		{ "sbb/add with neg", "F7 D8 1B C0 83 C0 01", 2 },

		// Very generic - just the return value idiom
		{ "sbb/add idiom", "1B C0 83 C0 01", 0 },
	};

	for (const auto& pi : patterns) {
		BOOST_LOG_TRIVIAL(info) << "";
		BOOST_LOG_TRIVIAL(info) << "--- Testing pattern: " << pi.name << " ---";
		BOOST_LOG_TRIVIAL(info) << "Pattern: " << pi.pattern;

		std::vector<PatternByte> parsed = ParsePattern(pi.pattern);
		if (parsed.empty()) {
			BOOST_LOG_TRIVIAL(error) << "Failed to parse pattern!";
			continue;
		}

		BOOST_LOG_TRIVIAL(debug) << "Pattern size: " << parsed.size() << " bytes. Searching...";

		std::vector<std::byte*> found = SafeFindAllPatterns(ptr, size_, parsed);

		BOOST_LOG_TRIVIAL(info) << "Found " << std::dec << found.size() << " match(es)";

		for (size_t idx = 0; idx < found.size() && idx < 10; ++idx) {
			DWORD addr = reinterpret_cast<DWORD>(found[idx]);
			DWORD patch_addr = addr + pi.patch_offset;
			BOOST_LOG_TRIVIAL(info) << "  Match " << (idx + 1) << ": Pattern at 0x" << std::hex << addr
				<< ", Patch point at 0x" << patch_addr;

			// Dump bytes around match for verification
			BYTE* match_ptr = reinterpret_cast<BYTE*>(found[idx]);
			std::stringstream ss;
			ss << "  Bytes: ";
			for (int b = 0; b < static_cast<int>(parsed.size()) && b < 20; ++b) {
				ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
					<< static_cast<int>(match_ptr[b]) << " ";
			}
			BOOST_LOG_TRIVIAL(info) << ss.str();
		}

		if (found.size() > 10) {
			BOOST_LOG_TRIVIAL(info) << "  ... and " << (found.size() - 10) << " more matches";
		}
	}

	BOOST_LOG_TRIVIAL(info) << "";
	BOOST_LOG_TRIVIAL(info) << "=== PATTERN SEARCH COMPLETE (NO PATCHES APPLIED) ===";
	BOOST_LOG_TRIVIAL(info) << "Review the results above to find the correct address for v1.13";

	// Return TRUE so the game continues (no patch applied)
	return TRUE;
}
