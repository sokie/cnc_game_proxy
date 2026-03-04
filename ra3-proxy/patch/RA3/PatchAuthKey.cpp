// PatchAuthKey.cpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#include "../../Framework.h"
#include "../../util.h"
#include "../../GameVersion.h"
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

// RA3 auth patch:
//   Unpatched: F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3
//              neg eax; sbb eax,eax; add eax,1; pop esi; add esp,imm32; ret
//   Patch: replace "1B C0 83 C0 01" (offset 2, 5 bytes) with "B8 01 00 00 00" (mov eax, 1)
//   Patched:  F7 D8 B8 01 00 00 00 5E 81 C4 ?? ?? 00 00 C3
static BOOL PatchRA3(std::byte* ptr, DWORD size)
{
	std::string patched_pattern = "F7 D8 B8 01 00 00 00 5E 81 C4 ?? ?? 00 00 C3";
	std::vector<PatternByte> parsed = ParsePattern(patched_pattern);
	std::byte* found = SafeFindPattern(ptr, size, parsed);
	if (found != nullptr) {
		BOOST_LOG_TRIVIAL(info) << "Auth certificate check is already patched at: 0x"
		                        << std::hex << reinterpret_cast<DWORD>(found);
		return TRUE;
	}

	std::string unpatched_pattern = "F7 D8 1B C0 83 C0 01 5E 81 C4 ?? ?? 00 00 C3";
	parsed = ParsePattern(unpatched_pattern);
	found = SafeFindPattern(ptr, size, parsed);
	if (found == nullptr) {
		BOOST_LOG_TRIVIAL(error) << "Auth certificate check pattern not found!";
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Found auth certificate check at: 0x"
	                        << std::hex << reinterpret_cast<DWORD>(found);

	// Replace "1B C0 83 C0 01" with "B8 01 00 00 00" (mov eax, 1)
	BYTE* patchAddress = reinterpret_cast<BYTE*>(found + 2);
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

// KW auth patch:
//   The auth RSA signature verification function ends with:
//     83 C4 ?? F7 D8 1B C0 ?? 40 ?? ?? ?? ?? C9 C3
//     add esp,imm8; neg eax; sbb eax,eax; pop r32; inc eax; pop r32; add ebp,imm8; leave; ret
//   KW's compiler uses INC EAX (40) instead of ADD EAX,1 (83 C0 01) and interleaves pops.
//   Patch: replace "F7 D8" (neg eax) with "33 C0" (xor eax,eax) at offset 3.
//     xor clears EAX and CF, so sbb eax,eax gives 0, then inc eax gives 1 (always success).
//   Patched:  83 C4 ?? 33 C0 1B C0 ?? 40 ?? ?? ?? ?? C9 C3
static BOOL PatchKW(std::byte* ptr, DWORD size)
{
	std::string patched_pattern = "83 C4 ?? 33 C0 1B C0 ?? 40 ?? ?? ?? ?? C9 C3";
	std::vector<PatternByte> parsed = ParsePattern(patched_pattern);
	std::byte* found = SafeFindPattern(ptr, size, parsed);
	if (found != nullptr) {
		BOOST_LOG_TRIVIAL(info) << "Auth certificate check is already patched at: 0x"
		                        << std::hex << reinterpret_cast<DWORD>(found);
		return TRUE;
	}

	std::string unpatched_pattern = "83 C4 ?? F7 D8 1B C0 ?? 40 ?? ?? ?? ?? C9 C3";
	parsed = ParsePattern(unpatched_pattern);
	found = SafeFindPattern(ptr, size, parsed);
	if (found == nullptr) {
		BOOST_LOG_TRIVIAL(error) << "Auth certificate check pattern not found!";
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Found auth certificate check at: 0x"
	                        << std::hex << reinterpret_cast<DWORD>(found);

	// Replace "F7 D8" (neg eax) with "33 C0" (xor eax,eax) at offset 3
	BYTE* patchAddress = reinterpret_cast<BYTE*>(found + 3);
	static constexpr BYTE patch_bytes[] = { 0x33, 0xC0 };

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

BOOL PatchAuthKey::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("AuthKeyPatch")

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);
	const auto& gameInfo = GameVersion::GetInstance().GetInfo();

	if (gameInfo.executableName == L"cnc3ep1.dat" || gameInfo.executableName == L"cnc3game.dat") {
		BOOST_LOG_TRIVIAL(info) << "Using CnC3 auth patch...";
		return PatchKW(ptr, size_);
	}

	BOOST_LOG_TRIVIAL(info) << "Using Red Alert 3 auth patch...";
	return PatchRA3(ptr, size_);
}
