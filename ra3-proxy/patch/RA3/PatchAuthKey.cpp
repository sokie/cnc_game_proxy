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

	// Pattern for already patched executable:
	// F7 D8 B8 01 00 00 00 5E 81 C4 ?? ?? 00 00 C3
	// (neg eax; mov eax, 1; pop esi; add esp, imm32; ret)
	std::string patched_pattern = "F7 D8 B8 01 00 00 00 5E 81 C4 ?? ?? 00 00 C3";

	BOOST_LOG_TRIVIAL(debug) << "Checking if already patched...";

	std::vector<PatternByte> parsed = ParsePattern(patched_pattern);
	if (!parsed.empty()) {
		std::byte* found = SafeFindPattern(ptr, size_, parsed);
		if (found != nullptr) {
			BOOST_LOG_TRIVIAL(info) << "Auth certificate check is already patched at: 0x" << std::hex << reinterpret_cast<DWORD>(found);
			return TRUE;
		}
	}

	// Pattern for unpatched executable (works on v1.12 and v1.13):
	// F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3
	// (neg eax; sbb eax, eax; add eax, 1; pop esi; add esp, imm32; ret)
	// Patch point is at offset 2 (where "1B C0 83 C0 01" starts)
	std::string unpatched_pattern = "F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3";

	BOOST_LOG_TRIVIAL(info) << "Searching for auth certificate check...";

	parsed = ParsePattern(unpatched_pattern);
	if (parsed.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Failed to parse pattern!";
		return FALSE;
	}

	std::byte* found = SafeFindPattern(ptr, size_, parsed);
	if (found == nullptr) {
		BOOST_LOG_TRIVIAL(error) << "Auth certificate check pattern not found!";
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Found auth certificate check at: 0x" << std::hex << reinterpret_cast<DWORD>(found);

	// Patch point is at offset 2 (after "F7 D8")
	// Replace "1B C0 83 C0 01" (5 bytes) with "B8 01 00 00 00" (mov eax, 1)
	BYTE* patchAddress = reinterpret_cast<BYTE*>(found + 2);

	static constexpr BYTE patch_bytes[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 };

	DWORD oldProtect;
	if (!VirtualProtect(patchAddress, sizeof(patch_bytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at: 0x" << std::hex << reinterpret_cast<DWORD>(patchAddress);
		return FALSE;
	}

	memcpy(patchAddress, patch_bytes, sizeof(patch_bytes));

	VirtualProtect(patchAddress, sizeof(patch_bytes), oldProtect, &oldProtect);

	BOOST_LOG_TRIVIAL(info) << "Patched auth certificate check at: 0x" << std::hex << reinterpret_cast<DWORD>(patchAddress);
	return TRUE;
}
