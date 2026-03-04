// PatchAuthKey.cpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#include "../../Framework.h"
#include "../../util.h"
#include "PatchAuthKey.hpp"
#include "PatchSSL.hpp"  // For PatternByte

// Forward declarations from PatchSSL.cpp
extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);
extern std::vector<std::byte*> FindAllPatterns(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern);

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

		// Ensure the entire pattern fits within the readable region
		size_t safe_region_end = (bytes_in_region >= pattern.size()) ? (i + bytes_in_region - pattern.size() + 1) : i;
		size_t search_end = (std::min)(safe_region_end, search_length - pattern.size() + 1);

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

		// If region was too small for the pattern, skip past it
		if (bytes_in_region < pattern.size()) {
			i = (region_end - reinterpret_cast<size_t>(start_address));
		}
	}
	return nullptr;
}

// Helper: dump hex bytes around an address for diagnostic logging
static std::string DumpHex(std::byte* base, std::byte* addr, size_t total_size, int before, int after)
{
	std::ostringstream oss;
	std::byte* start = addr - before;
	std::byte* end = addr + after;

	// Clamp to valid range
	if (start < base) start = base;
	if (end > base + total_size) end = base + total_size;

	for (std::byte* p = start; p < end; ++p) {
		if (p == addr) oss << "[";
		oss << std::hex << std::setfill('0') << std::setw(2)
		    << static_cast<unsigned int>(*reinterpret_cast<unsigned char*>(p));
		if (p == addr) oss << "]";
		oss << " ";
	}
	return oss.str();
}

// Diagnostic scan: search for a short pattern and log all matches with surrounding context
static void DiagnosticScan(std::byte* base, size_t size, const std::string& pattern_str, const char* description)
{
	std::vector<PatternByte> parsed = ParsePattern(pattern_str);
	if (parsed.empty()) return;

	std::vector<std::byte*> matches = FindAllPatterns(base, size, parsed);

	BOOST_LOG_TRIVIAL(info) << "Diagnostic: \"" << description << "\" (" << pattern_str << ") => " << matches.size() << " match(es)";

	int count = 0;
	for (std::byte* match : matches) {
		if (count >= 20) {
			BOOST_LOG_TRIVIAL(info) << "  ... (truncated, " << matches.size() << " total matches)";
			break;
		}
		BOOST_LOG_TRIVIAL(info) << "  [" << count << "] 0x" << std::hex << reinterpret_cast<DWORD>(match)
		                        << ": " << DumpHex(base, match, size, 4, 24);
		++count;
	}
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

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	// === Check if already patched ===
	// After patching, "1B C0 83 C0 01" becomes "B8 01 00 00 00" (mov eax, 1)
	// We wildcard the register pop since it varies between games
	const char* patched_patterns[] = {
		"F7 D8 B8 01 00 00 00 ?? 81 C4 ?? ?? 00 00 C3",  // pop r32; add esp, imm32; ret
		"F7 D8 B8 01 00 00 00 ?? 83 C4 ?? C3",            // pop r32; add esp, imm8; ret
		"F7 D8 B8 01 00 00 00 ?? ?? 83 C4 ?? C3",         // pop r32; pop r32; add esp, imm8; ret
		"F7 D8 B8 01 00 00 00 ?? C3",                     // pop r32; ret
		"F7 D8 B8 01 00 00 00 C3",                        // just ret (no pop)
	};

	BOOST_LOG_TRIVIAL(debug) << "Checking if already patched...";

	for (const auto& pat_str : patched_patterns) {
		std::vector<PatternByte> parsed = ParsePattern(pat_str);
		if (!parsed.empty()) {
			std::byte* found = SafeFindPattern(ptr, size_, parsed);
			if (found != nullptr) {
				BOOST_LOG_TRIVIAL(info) << "Auth certificate check is already patched at: 0x"
				                        << std::hex << reinterpret_cast<DWORD>(found)
				                        << " (pattern: " << pat_str << ")";
				return TRUE;
			}
		}
	}

	// === Try unpatched patterns (most specific to most generic) ===
	// The core idiom is: neg eax; sbb eax,eax; add eax,1 (F7 D8 1B C0 83 C0 01)
	// This converts 0 -> 1 (success) and nonzero -> 0 (failure)
	// Patch replaces "1B C0 83 C0 01" at offset 2 with "B8 01 00 00 00" (mov eax, 1)
	struct PatternCandidate {
		const char* pattern;
		int patch_offset;       // offset to "1B C0 83 C0 01" within the pattern
		const char* description;
	};

	PatternCandidate unpatched_patterns[] = {
		// RA3 exact: pop esi; add esp, imm32; ret
		{"F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3", 2, "RA3 exact (pop esi; add esp,imm32; ret)"},
		// Generic: pop r32; add esp, imm32; ret
		{"F7 D8 1B C0 83 C0 01 ?? 81 C4 ?? ?? 00 00 C3", 2, "pop r32; add esp,imm32; ret"},
		// pop r32; add esp, imm8; ret
		{"F7 D8 1B C0 83 C0 01 ?? 83 C4 ?? C3", 2, "pop r32; add esp,imm8; ret"},
		// pop r32; pop r32; add esp, imm8; ret
		{"F7 D8 1B C0 83 C0 01 ?? ?? 83 C4 ?? C3", 2, "pop r32; pop r32; add esp,imm8; ret"},
		// pop r32; pop r32; add esp, imm32; ret
		{"F7 D8 1B C0 83 C0 01 ?? ?? 81 C4 ?? ?? 00 00 C3", 2, "pop r32; pop r32; add esp,imm32; ret"},
		// pop r32; ret (small stack frame)
		{"F7 D8 1B C0 83 C0 01 ?? C3", 2, "pop r32; ret"},
		// Just ret, no register restore
		{"F7 D8 1B C0 83 C0 01 C3", 2, "ret (no epilogue)"},
		// leave; ret (frame pointer based)
		{"F7 D8 1B C0 83 C0 01 C9 C3", 2, "leave; ret"},
	};

	BOOST_LOG_TRIVIAL(info) << "Searching for auth certificate check...";

	for (const auto& candidate : unpatched_patterns) {
		BOOST_LOG_TRIVIAL(debug) << "Trying pattern: " << candidate.description
		                         << " [" << candidate.pattern << "]";

		std::vector<PatternByte> parsed = ParsePattern(candidate.pattern);
		if (parsed.empty()) continue;

		std::byte* found = SafeFindPattern(ptr, size_, parsed);
		if (found != nullptr) {
			BOOST_LOG_TRIVIAL(info) << "Found auth certificate check with pattern: " << candidate.description;
			BOOST_LOG_TRIVIAL(info) << "  Address: 0x" << std::hex << reinterpret_cast<DWORD>(found);
			BOOST_LOG_TRIVIAL(info) << "  Context: " << DumpHex(ptr, found, size_, 8, 24);

			// Patch at offset (after "F7 D8"): replace "1B C0 83 C0 01" with "B8 01 00 00 00"
			BYTE* patchAddress = reinterpret_cast<BYTE*>(found + candidate.patch_offset);
			static constexpr BYTE patch_bytes[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 };

			DWORD oldProtect;
			if (!VirtualProtect(patchAddress, sizeof(patch_bytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
				BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at: 0x"
				                         << std::hex << reinterpret_cast<DWORD>(patchAddress);
				return FALSE;
			}

			memcpy(patchAddress, patch_bytes, sizeof(patch_bytes));
			VirtualProtect(patchAddress, sizeof(patch_bytes), oldProtect, &oldProtect);

			BOOST_LOG_TRIVIAL(info) << "Patched auth certificate check at: 0x"
			                        << std::hex << reinterpret_cast<DWORD>(patchAddress);
			return TRUE;
		}
	}

	// === Diagnostic scan ===
	// No standard pattern matched. Scan for the core idioms to help identify KW's code layout.
	BOOST_LOG_TRIVIAL(warning) << "No auth pattern matched. Running diagnostic scan to help identify the correct pattern...";

	// Core boolean conversion: neg eax; sbb eax,eax; add eax,1
	DiagnosticScan(ptr, size_, "F7 D8 1B C0 83 C0 01", "neg eax; sbb eax,eax; add eax,1");

	// Variant: neg eax; sbb eax,eax; and eax,1 (functionally different but similar idiom)
	DiagnosticScan(ptr, size_, "F7 D8 1B C0 83 E0 01", "neg eax; sbb eax,eax; and eax,1");

	// Alternative compiler idiom: test eax,eax; sete al; movzx eax,al
	DiagnosticScan(ptr, size_, "85 C0 0F 94 C0 0F B6 C0", "test eax,eax; sete al; movzx eax,al");

	// Alternative: test eax,eax; setz al; movzx eax,al (same encoding)
	// Already covered above since sete and setz are the same opcode

	// Alternative: xor eax,eax; test ecx,ecx; sete al
	DiagnosticScan(ptr, size_, "33 C0 85 C9 0F 94 C0", "xor eax,eax; test ecx,ecx; sete al");

	// Broader: just neg eax; sbb eax,eax (fewer bytes, might get more matches)
	DiagnosticScan(ptr, size_, "F7 D8 1B C0", "neg eax; sbb eax,eax (broad)");

	BOOST_LOG_TRIVIAL(error) << "Auth certificate check pattern not found! Review diagnostic output above to identify the correct pattern for this game.";
	return FALSE;
}
