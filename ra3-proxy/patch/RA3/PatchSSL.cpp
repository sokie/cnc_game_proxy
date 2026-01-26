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

BOOL PatchSSL::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("SSLPatch")

	BOOST_LOG_TRIVIAL(debug) << "Entry point: 0x" << std::hex << entryPoint_ << ", size: 0x" << size_;

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

	BOOST_LOG_TRIVIAL(debug) << "Pattern parsed, " << parsed_pattern.size() << " bytes. Starting search...";

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	if (ptr == nullptr || size_ == 0) {
		BOOST_LOG_TRIVIAL(error) << "Invalid entry point or size!";
		return FALSE;
	}

	std::byte* found_address = FindPattern(ptr, size_, parsed_pattern);
	BOOST_LOG_TRIVIAL(debug) << "Search complete.";
	if (found_address != nullptr) {
		BOOST_LOG_TRIVIAL(info) << "Executable is already patched! Found at: 0x" << std::hex << reinterpret_cast<DWORD>(found_address);
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

		found_address = FindPattern(ptr, size_, parsed_pattern);
		if (found_address != nullptr) {
			BOOST_LOG_TRIVIAL(info) << "Found SSL verification location to patch.";

			DWORD oldProtect;
			// Change page protection to allow writing
			if (!VirtualProtect(found_address, 15, PAGE_EXECUTE_READWRITE, &oldProtect)) {
				BOOST_LOG_TRIVIAL(error) << "Failed to change memory protection at: 0x" << std::hex << reinterpret_cast<DWORD>(found_address);
				return FALSE;
			}

			//patch B8 15 00 00 00
			*reinterpret_cast<BYTE*>(found_address + 6) = 0xB8;
			*reinterpret_cast<BYTE*>(found_address + 7) = 0x15;
			*reinterpret_cast<BYTE*>(found_address + 8) = 0x00;
			*reinterpret_cast<BYTE*>(found_address + 9) = 0x00;
			*reinterpret_cast<BYTE*>(found_address + 10) = 0x00;

			VirtualProtect(found_address, 15, oldProtect, &oldProtect);

			BOOST_LOG_TRIVIAL(info) << "Patched SSL verification at: 0x" << std::hex << reinterpret_cast<DWORD>(found_address);
			return TRUE;
		}
		else {
			BOOST_LOG_TRIVIAL(error) << "Failed to find SSL verification code. This will cause things to break!";
			return FALSE;
		}
	}
	return FALSE;
}
