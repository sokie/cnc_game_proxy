// PatchSSL.cpp : Defines the PatchSSL class, which handles the patching of SSL certificate verification.
#include "../../Framework.h"
#include "PatchSSL.hpp"
#include "../../util.h"

PatchSSL::PatchSSL()
{
	//USED for debug
	//MessageBoxA(nullptr, "Unknown client/server detected!", "Failed to initialize hook!", MB_OK | MB_ICONERROR);

	// Get the handle of the current module
	HANDLE hModule = GetModuleHandle(nullptr);

	// Get the size and entry point offset of the module
	size_ = GetModuleSize(hModule);
	offset_ = GetEntryPointOffset(hModule);
	// Calculate the entry point of the module
	entryPoint_ = reinterpret_cast<DWORD>(hModule) + offset_;
}

std::vector<PatternByte> ParsePattern(const std::string& pattern_str) {
	std::vector<PatternByte> parsed_pattern;
	std::stringstream ss(pattern_str);
	std::string byte_str;

	while (ss >> byte_str) {
		if (byte_str == "??") {
			parsed_pattern.emplace_back(); // Add wildcard
		}
		else {
			try {
				unsigned int val = std::stoul(byte_str, nullptr, 16);
				if (val > 0xFF) {
					BOOST_LOG_TRIVIAL(warning) << "Byte value '" << byte_str << "' is out of range. Treating as wildcard.";
					parsed_pattern.emplace_back();
				}
				else {
					parsed_pattern.emplace_back(static_cast<std::byte>(val));
				}
			}
			catch (const std::invalid_argument& ia) {
				BOOST_LOG_TRIVIAL(warning) << "Invalid byte string '" << byte_str << "'. Treating as wildcard.";
				parsed_pattern.emplace_back();
			}
			catch (const std::out_of_range& oor) {
				BOOST_LOG_TRIVIAL(warning) << "Byte value '" << byte_str << "' is out of range. Treating as wildcard.";
				parsed_pattern.emplace_back();
			}
		}
	}
	return parsed_pattern;
}

// Function to search for the pattern in a memory region
std::byte* FindPattern(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern) {
	if (pattern.empty() || search_length < pattern.size()) {
		return nullptr; // Pattern is empty or longer than the search area
	}

	for (size_t i = 0; i <= search_length - pattern.size(); ++i) {
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
	return nullptr; // Pattern not found
}

// Function to search for all occurrences of the pattern in a memory region
std::vector<std::byte*> FindAllPatterns(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern) {
	std::vector<std::byte*> results;

	if (pattern.empty() || search_length < pattern.size()) {
		return results; // Pattern is empty or longer than the search area
	}

	for (size_t i = 0; i <= search_length - pattern.size(); ++i) {
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
	return results;
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

// Debug function to dump memory at SSL check addresses for pattern creation
void PatchSSL::DumpSSLCheckMemory() const
{
	BOOST_LOG_NAMED_SCOPE("SSLPatch")

	// Known addresses for version 1.12
	constexpr DWORD ssl_check_addresses[] = {
		0xAECCFFu,
		0xB5ADEFu
	};

	// How many bytes to dump before and after the patch point
	constexpr size_t DUMP_BEFORE = 16;
	constexpr size_t DUMP_AFTER = 16;
	constexpr size_t TOTAL_DUMP = DUMP_BEFORE + DUMP_AFTER;

	BOOST_LOG_TRIVIAL(info) << "=== SSL CHECK MEMORY DUMP FOR PATTERN CREATION ===";
	BOOST_LOG_TRIVIAL(info) << "Dumping " << DUMP_BEFORE << " bytes before and " << DUMP_AFTER << " bytes after each address";

	for (size_t idx = 0; idx < 2; ++idx)
	{
		DWORD address = ssl_check_addresses[idx];
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

		// Dump bytes at patch point (the pattern starts 6 bytes before where we write)
		BOOST_LOG_TRIVIAL(info) << "At address:          " << DumpMemoryAsHex(reinterpret_cast<BYTE*>(address), 16);

		// Dump bytes after
		BOOST_LOG_TRIVIAL(info) << "After (+" << std::dec << DUMP_AFTER << " bytes):  " << DumpMemoryAsHex(reinterpret_cast<BYTE*>(address + DUMP_AFTER), DUMP_AFTER);

		VirtualProtect(startAddress, TOTAL_DUMP, oldProtect, &oldProtect);
	}

	BOOST_LOG_TRIVIAL(info) << "";
	BOOST_LOG_TRIVIAL(info) << "=== COMPARE BOTH LOCATIONS TO CREATE PATTERN ===";
	BOOST_LOG_TRIVIAL(info) << "Bytes that differ between locations should use ?? wildcard";
	BOOST_LOG_TRIVIAL(info) << "Example pattern format: \"81 ?? EE 0F 00 00 83 ?? 15 8B ??\"";
}

BOOL PatchSSL::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("SSLPatch")

	// First dump memory to help create patterns (can be removed after pattern is finalized)
	DumpSSLCheckMemory();

	//We first try to find if executable is patched already
	std::string pattern_string = "81 ?? EE 0F 00 00 B8 15 00 00 00";

	BOOST_LOG_TRIVIAL(debug) << "Searching for pattern of already patched executable: \"" << pattern_string << "\"";

	// 2. Parse the pattern
	std::vector<PatternByte> parsed_pattern = ParsePattern(pattern_string);

	if (parsed_pattern.empty() && !pattern_string.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Pattern string resulted in an empty pattern. Check for parsing errors.";
		return FALSE;
	}
	if (parsed_pattern.empty() && pattern_string.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Empty pattern string provided.";
		return FALSE;
	}

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);


	std::vector<std::byte*> patched_addresses = FindAllPatterns(ptr, size_, parsed_pattern);
	if (!patched_addresses.empty()) {
		BOOST_LOG_TRIVIAL(info) << "Executable is already patched! Found " << patched_addresses.size() << " patched location(s).";
		for (const auto& addr : patched_addresses) {
			BOOST_LOG_TRIVIAL(debug) << "  - Patched at: 0x" << std::hex << reinterpret_cast<DWORD>(addr);
		}
		return TRUE;
	}
	else {
		BOOST_LOG_TRIVIAL(info) << "Executable is not patched, patching SSL verification!";
		std::string unpatched_pattern_string = "81 ?? EE 0F 00 00 83 ?? 15 8B ??";

		BOOST_LOG_TRIVIAL(debug) << "Searching for pattern: \"" << unpatched_pattern_string << "\"";

		// 2. Parse the pattern
		parsed_pattern = ParsePattern(unpatched_pattern_string);

		if (parsed_pattern.empty() && !unpatched_pattern_string.empty()) {
			BOOST_LOG_TRIVIAL(error) << "Pattern string resulted in an empty pattern. Check for parsing errors.";
			return FALSE;
		}
		if (parsed_pattern.empty() && unpatched_pattern_string.empty()) {
			BOOST_LOG_TRIVIAL(error) << "Empty pattern string provided.";
			return FALSE;
		}

		std::vector<std::byte*> found_addresses = FindAllPatterns(ptr, size_, parsed_pattern);
		if (!found_addresses.empty()) {
			BOOST_LOG_TRIVIAL(info) << "Found " << found_addresses.size() << " SSL verification location(s) to patch.";

			int patchedCount = 0;
			for (std::byte* found_address : found_addresses) {
				DWORD oldProtect;
				// Change page protection to allow writing
				if (!VirtualProtect(found_address, 15, PAGE_EXECUTE_READWRITE, &oldProtect)) {
					BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at: 0x" << std::hex << reinterpret_cast<DWORD>(found_address);
					continue;
				}

				//patch B8 15 00 00 00
				*reinterpret_cast<BYTE*>(found_address + 6) = 0xB8;
				*reinterpret_cast<BYTE*>(found_address + 7) = 0x15;
				*reinterpret_cast<BYTE*>(found_address + 8) = 0x00;
				*reinterpret_cast<BYTE*>(found_address + 9) = 0x00;
				*reinterpret_cast<BYTE*>(found_address + 10) = 0x00;

				VirtualProtect(found_address, 15, oldProtect, &oldProtect);

				BOOST_LOG_TRIVIAL(info) << "Patched SSL verification at: 0x" << std::hex << reinterpret_cast<DWORD>(found_address);
				patchedCount++;
			}

			BOOST_LOG_TRIVIAL(info) << "Successfully patched " << std::dec << patchedCount << "/" << found_addresses.size() << " SSL verification location(s)!";
			return patchedCount > 0 ? TRUE : FALSE;
		}
		else {
			BOOST_LOG_TRIVIAL(error) << "Failed to find SSL verification code. This will cause things to break!";
			return FALSE;
		}
	}
	return FALSE;
}
