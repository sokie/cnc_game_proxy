// PatchAuthKey.cpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#include "../../Framework.h"
#include "PatchAuthKey.hpp"

PatchAuthKey::PatchAuthKey()
{
	// Get the base address of the current module
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);
}

// Helper function to dump memory bytes as hex string
static std::string DumpMemoryAsHex(BYTE* address, size_t length)
{
	std::stringstream ss;
	for (size_t i = 0; i < length; ++i)
	{
		ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(address[i]);
		if (i < length - 1) ss << " ";
	}
	return ss.str();
}

// Debug function to dump memory at auth check addresses for pattern creation
void PatchAuthKey::DumpAuthCheckMemory() const
{
	BOOST_LOG_NAMED_SCOPE("AuthKeyPatch")

	// Known addresses for version 1.12
	constexpr DWORD auth_check_addresses[] = {
		0xB36CBFu,
		0x9444BFu
	};

	// How many bytes to dump before and after the patch point
	constexpr size_t DUMP_BEFORE = 16;
	constexpr size_t DUMP_AFTER = 16;
	constexpr size_t TOTAL_DUMP = DUMP_BEFORE + DUMP_AFTER;

	BOOST_LOG_TRIVIAL(info) << "=== AUTH CHECK MEMORY DUMP FOR PATTERN CREATION ===";
	BOOST_LOG_TRIVIAL(info) << "Dumping " << DUMP_BEFORE << " bytes before and " << DUMP_AFTER << " bytes after each address";

	for (size_t idx = 0; idx < 2; ++idx)
	{
		DWORD address = auth_check_addresses[idx];
		BYTE* startAddress = reinterpret_cast<BYTE*>(address - DUMP_BEFORE);

		DWORD oldProtect;
		if (!VirtualProtect(startAddress, TOTAL_DUMP, PAGE_EXECUTE_READ, &oldProtect))
		{
			BOOST_LOG_TRIVIAL(error) << "Failed to read memory at address: 0x" << std::hex << address;
			continue;
		}

		BOOST_LOG_TRIVIAL(info) << "";
		BOOST_LOG_TRIVIAL(info) << "--- Location " << (idx + 1) << " at 0x" << std::hex << address << " ---";
		BOOST_LOG_TRIVIAL(info) << "Start dump address: 0x" << std::hex << reinterpret_cast<DWORD>(startAddress);

		// Dump bytes before
		BOOST_LOG_TRIVIAL(info) << "Before (-" << std::dec << DUMP_BEFORE << " bytes): " << DumpMemoryAsHex(startAddress, DUMP_BEFORE);

		// Dump bytes at patch point
		BOOST_LOG_TRIVIAL(info) << "At patch point:      " << DumpMemoryAsHex(reinterpret_cast<BYTE*>(address), 5) << " (these 5 bytes will be replaced)";

		// Dump bytes after
		BOOST_LOG_TRIVIAL(info) << "After (+" << std::dec << DUMP_AFTER << " bytes):  " << DumpMemoryAsHex(reinterpret_cast<BYTE*>(address), DUMP_AFTER);

		VirtualProtect(startAddress, TOTAL_DUMP, oldProtect, &oldProtect);
	}

	BOOST_LOG_TRIVIAL(info) << "";
	BOOST_LOG_TRIVIAL(info) << "=== COMPARE BOTH LOCATIONS TO CREATE PATTERN ===";
	BOOST_LOG_TRIVIAL(info) << "Bytes that differ between locations should use ?? wildcard";
	BOOST_LOG_TRIVIAL(info) << "Example pattern format: \"83 C4 ?? 85 C0 74 ?? 8B\"";
}

BOOL PatchAuthKey::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("AuthKeyPatch")

	// First dump memory to help create patterns (can be removed after pattern is finalized)
	DumpAuthCheckMemory();

	BOOST_LOG_TRIVIAL(info) << "Patching auth certificate check...";

	// mov eax, 0x01 - makes the function return 1 (success)
	static constexpr BYTE new_auth_certificate_check_return_value[] = {
		0xB8, 0x01, 0x00, 0x00, 0x00  // mov eax, 0x01
	};

	// Addresses to patch (relative to module base would be offset, but these appear to be absolute)
	constexpr DWORD auth_check_addresses[] = {
		0xB36CBFu,
		0x9444BFu
	};

	int patchedCount = 0;

	for (DWORD address : auth_check_addresses)
	{
		BYTE* patchAddress = reinterpret_cast<BYTE*>(address);

		DWORD oldProtect;
		// Change page protection to allow writing
		if (!VirtualProtect(patchAddress, sizeof(new_auth_certificate_check_return_value), PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at address: 0x" << std::hex << address;
			continue;
		}

		// Write the patch bytes
		memcpy(patchAddress, new_auth_certificate_check_return_value, sizeof(new_auth_certificate_check_return_value));

		// Restore original protection
		VirtualProtect(patchAddress, sizeof(new_auth_certificate_check_return_value), oldProtect, &oldProtect);

		BOOST_LOG_TRIVIAL(info) << "Successfully patched auth certificate check at address: 0x" << std::hex << address;
		patchedCount++;
	}

	if (patchedCount == 2)
	{
		BOOST_LOG_TRIVIAL(info) << "Auth certificate check patching complete!";
		return TRUE;
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to patch all auth certificate check addresses. Patched: " << patchedCount << "/2";
		return FALSE;
	}
}
