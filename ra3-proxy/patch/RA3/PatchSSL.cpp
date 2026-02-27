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

// Helper to check if a memory region is readable
static bool IsRegionReadable(const MEMORY_BASIC_INFORMATION& mbi) {
	if (mbi.State != MEM_COMMIT)
		return false;
	if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
		return false;
	if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)))
		return false;
	return true;
}

// Function to search for the pattern in a memory region, safely skipping unreadable pages
std::byte* FindPattern(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern) {
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

		if (!IsRegionReadable(mbi)) {
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

		// If we didn't advance (region too small for pattern), skip past it
		if (i < safe_region_end || bytes_in_region < pattern.size()) {
			i = (region_end - reinterpret_cast<size_t>(start_address));
		}
	}
	return nullptr;
}

// Function to search for all occurrences of the pattern in a memory region, safely skipping unreadable pages
std::vector<std::byte*> FindAllPatterns(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern) {
	std::vector<std::byte*> results;

	if (pattern.empty() || search_length < pattern.size()) {
		return results;
	}

	size_t i = 0;
	while (i <= search_length - pattern.size()) {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(start_address + i, &mbi, sizeof(mbi)) == 0) {
			i += 0x1000;
			continue;
		}

		if (!IsRegionReadable(mbi)) {
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
				results.push_back(&start_address[i]);
			}
		}

		if (i < safe_region_end || bytes_in_region < pattern.size()) {
			i = (region_end - reinterpret_cast<size_t>(start_address));
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

			// Patch at offset 6: replace "83 ?? 15" with "B8 15 00 00 00" (mov eax, 0x15)
			BYTE* patchAddress = reinterpret_cast<BYTE*>(found_address + 6);
			patchAddress[0] = 0xB8;
			patchAddress[1] = 0x15;
			patchAddress[2] = 0x00;
			patchAddress[3] = 0x00;
			patchAddress[4] = 0x00;

			VirtualProtect(found_address, 15, oldProtect, &oldProtect);

			BOOST_LOG_TRIVIAL(info) << "Patched SSL verification at: 0x" << std::hex << reinterpret_cast<DWORD>(patchAddress);
			return TRUE;
		}
		else {
			BOOST_LOG_TRIVIAL(error) << "Failed to find SSL verification code. This will cause things to break!";
			return FALSE;
		}
	}
	return FALSE;
}
