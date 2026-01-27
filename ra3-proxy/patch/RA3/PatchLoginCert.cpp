// PatchLoginCert.cpp : Hooks wsLoginCertIsValid to bypass GameSpy login certificate verification.
#include "../../Framework.h"
#include "../../util.h"
#include "PatchLoginCert.hpp"
#include "PatchSSL.hpp"  // For PatternByte

// Forward declarations from PatchSSL.cpp
extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);

// Static member initialization
wsLoginCertIsValid_t PatchLoginCert::pOriginal = nullptr;

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

// Detour function - always returns true (certificate is valid)
static gsi_bool __cdecl detourWsLoginCertIsValid(const GSLoginCertificate* cert)
{
	BOOST_LOG_TRIVIAL(info) << "wsLoginCertIsValid called - bypassing certificate verification";
	return gsi_true;
}

PatchLoginCert::PatchLoginCert()
{
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);
	size_ = GetModuleSize(hModule);
	offset_ = GetEntryPointOffset(hModule);
	entryPoint_ = baseAddress_ + offset_;
}

BOOL PatchLoginCert::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("LoginCertPatch")

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	// Pattern for the call site that invokes wsLoginCertIsValid
	// From IDA disassembly:
	//   push    esi                    ; 56
	//   call    wsLoginCertIsValid     ; E8 ?? ?? ?? ??
	//   add     esp, 4                 ; 83 C4 04
	//   test    eax, eax               ; 85 C0
	//   jnz     short loc_success      ; 75 ??
	//   mov     eax, 2                 ; B8 02 00 00 00
	//   pop     esi                    ; 5E
	//   retn                           ; C3
	//
	// We find the call instruction and calculate the target function address.

	std::string call_site_pattern = "56 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 ?? B8 02 00 00 00 5E C3";

	BOOST_LOG_TRIVIAL(info) << "Searching for wsLoginCertIsValid call site...";

	std::vector<PatternByte> parsed = ParsePattern(call_site_pattern);
	if (parsed.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Failed to parse pattern!";
		return FALSE;
	}

	std::byte* found = SafeFindPattern(ptr, size_, parsed);
	if (found == nullptr) {
		BOOST_LOG_TRIVIAL(error) << "wsLoginCertIsValid call site not found!";
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Found call site at: 0x" << std::hex << reinterpret_cast<DWORD>(found);

	// The E8 (call) instruction is at offset 1 (after push esi)
	// E8 is a relative call: target = next_instruction_address + relative_offset
	// next_instruction_address = call_address + 5 (size of E8 XX XX XX XX)
	BYTE* callInstruction = reinterpret_cast<BYTE*>(found + 1);

	// Read the 4-byte relative offset (little-endian)
	DWORD relativeOffset = *reinterpret_cast<DWORD*>(callInstruction + 1);

	// Calculate the absolute address of wsLoginCertIsValid
	// target = (address_of_call_instruction + 5) + relative_offset
	DWORD callInstructionAddr = reinterpret_cast<DWORD>(callInstruction);
	DWORD functionAddr = callInstructionAddr + 5 + relativeOffset;

	BOOST_LOG_TRIVIAL(info) << "Calculated wsLoginCertIsValid address: 0x" << std::hex << functionAddr;

	// Store the original function pointer
	pOriginal = reinterpret_cast<wsLoginCertIsValid_t>(functionAddr);

	// Hook the function using Detours
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	LONG error = DetourAttach(
		reinterpret_cast<PVOID*>(&pOriginal),
		reinterpret_cast<PVOID>(detourWsLoginCertIsValid)
	);

	if (error != NO_ERROR) {
		BOOST_LOG_TRIVIAL(error) << "DetourAttach failed with error: " << error;
		DetourTransactionAbort();
		return FALSE;
	}

	error = DetourTransactionCommit();
	if (error != NO_ERROR) {
		BOOST_LOG_TRIVIAL(error) << "DetourTransactionCommit failed with error: " << error;
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Successfully hooked wsLoginCertIsValid";
	return TRUE;
}
