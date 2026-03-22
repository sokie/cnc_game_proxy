// PatchDesync.cpp : Desync mitigation for CNC3 Tiberium Wars.
//
// Hooks:
//   - GameLogic_CheckDesync (0x004cdefd): logs CRC mismatches, optionally forces match
//   - GameLogic_HandleDesync (0x004c8410): optionally suppresses desync dialog
//
// Binary patches:
//   - CRC interval override (g_defaultCRCInterval / g_NetCRCInterval)
//   - Object CRC disable (NOP liteCRC override + set g_xObjectCRC)
//
#include "../../Framework.h"
#include "../../util.h"
#include "../../GameVersion.h"
#include "PatchDesync.hpp"

extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);
extern std::byte* FindPattern(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern);

// ---------------------------------------------------------------------------
// Module base for resolving Ghidra addresses at runtime
// ---------------------------------------------------------------------------
static DWORD s_moduleBase = 0;
static const DWORD PE_IMAGE_BASE = 0x00400000;

inline DWORD* GlobalPtr(DWORD ghidraAddr)
{
	return reinterpret_cast<DWORD*>(s_moduleBase + (ghidraAddr - PE_IMAGE_BASE));
}

// ---------------------------------------------------------------------------
// CRC entry node in the linked list at GameLogic+0x40
// ---------------------------------------------------------------------------
struct CRCEntry {
	DWORD frameNumber;    // +0x00
	DWORD crcValue;       // +0x04
	DWORD playerCount;    // +0x08
	DWORD playerBitmask;  // +0x0C
	DWORD binaryCRCData;  // +0x10
	CRCEntry* next;       // +0x14
};

// ---------------------------------------------------------------------------
// Function typedefs (__fastcall trick for __thiscall hooks)
// ---------------------------------------------------------------------------

typedef void(__fastcall* CheckDesync_t)(
	void* thisPtr, void* edx,
	UINT crcValue, UINT playerSlot, UINT frameNumber,
	int context, char forceFlag, UINT binaryCRCData);

typedef void(__fastcall* HandleDesync_t)(
	void* thisPtr, void* edx,
	int frameData, UINT frameNumber, UINT playerSlot);

static CheckDesync_t pOriginalCheckDesync = nullptr;
static HandleDesync_t pOriginalHandleDesync = nullptr;

// ---------------------------------------------------------------------------
// Hook: GameLogic_CheckDesync
// ---------------------------------------------------------------------------
static void __fastcall hookCheckDesync(
	void* thisPtr, void* edx,
	UINT crcValue, UINT playerSlot, UINT frameNumber,
	int context, char forceFlag, UINT binaryCRCData)
{
	const auto& config = Config::GetInstance();

	// Walk the CRC linked list to find existing entry for this frame
	CRCEntry* entry = *reinterpret_cast<CRCEntry**>(
		static_cast<BYTE*>(thisPtr) + 0x40);

	while (entry != nullptr && entry->frameNumber < frameNumber)
		entry = entry->next;

	bool isMismatch = entry != nullptr &&
		entry->frameNumber == frameNumber &&
		crcValue != entry->crcValue;

	if (isMismatch && config.logDesyncMismatch)
	{
		BOOST_LOG_TRIVIAL(warning)
			<< "[DESYNC] CRC mismatch on frame " << frameNumber
			<< ": first=0x" << std::hex << std::setfill('0') << std::setw(8) << entry->crcValue
			<< ", incoming=0x" << std::setw(8) << crcValue
			<< std::dec << " from player " << playerSlot;
	}

	if (isMismatch && config.forceCRCMatch)
	{
		BOOST_LOG_TRIVIAL(info)
			<< "[DESYNC] Forcing CRC match on frame " << frameNumber;
		crcValue = entry->crcValue;
	}

	pOriginalCheckDesync(thisPtr, edx, crcValue, playerSlot, frameNumber,
		context, forceFlag, binaryCRCData);
}

// ---------------------------------------------------------------------------
// Hook: GameLogic_HandleDesync
// ---------------------------------------------------------------------------
static void __fastcall hookHandleDesync(
	void* thisPtr, void* edx,
	int frameData, UINT frameNumber, UINT playerSlot)
{
	const auto& config = Config::GetInstance();

	if (config.suppressDesyncDialog)
	{
		*reinterpret_cast<BYTE*>(static_cast<BYTE*>(thisPtr) + 0x6a) = 1;
		BOOST_LOG_TRIVIAL(info) << "[DESYNC] Desync dialog suppressed on frame " << frameNumber;
		return;
	}

	pOriginalHandleDesync(thisPtr, edx, frameData, frameNumber, playerSlot);
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

static const char* PATTERN_CHECK_DESYNC =
	"55 8B EC 51 53 56 8B F1 33 DB 57 8B 7E 40";

static const char* PATTERN_HANDLE_DESYNC =
	"55 8B EC 81 EC 1C 01 00 00 53 8B D9 57 C6 43 6A 01 33 FF";

// ---------------------------------------------------------------------------
// PatchDesync implementation
// ---------------------------------------------------------------------------

PatchDesync::PatchDesync()
{
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);
	size_ = GetModuleSize(hModule);
	offset_ = GetEntryPointOffset(hModule);
	entryPoint_ = baseAddress_ + offset_;
}

BOOL PatchDesync::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("DesyncPatch")

	const auto& config = Config::GetInstance();
	s_moduleBase = baseAddress_;

	bool needCheckDesync = config.logDesyncMismatch || config.forceCRCMatch;
	bool needHandleDesync = config.suppressDesyncDialog;
	bool needCRCInterval = config.crcInterval > 0;
	bool needDisableObjectCRC = config.disableObjectCRC;

	if (!needCheckDesync && !needHandleDesync && !needCRCInterval && !needDisableObjectCRC)
	{
		BOOST_LOG_TRIVIAL(info) << "Desync patches disabled in config, skipping.";
		return TRUE;
	}

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	auto findFunc = [&](const char* patternStr, const char* name) -> std::byte* {
		auto pattern = ParsePattern(patternStr);
		std::byte* addr = FindPattern(ptr, size_, pattern);
		if (addr)
			BOOST_LOG_TRIVIAL(info) << "Found " << name << " at: 0x"
				<< std::hex << reinterpret_cast<DWORD>(addr);
		else
			BOOST_LOG_TRIVIAL(error) << "Failed to find " << name << " pattern!";
		return addr;
	};

	// --- Detours hooks ---
	if (needCheckDesync || needHandleDesync)
	{
		std::byte* addrCheckDesync = needCheckDesync
			? findFunc(PATTERN_CHECK_DESYNC, "GameLogic_CheckDesync") : nullptr;
		std::byte* addrHandleDesync = needHandleDesync
			? findFunc(PATTERN_HANDLE_DESYNC, "GameLogic_HandleDesync") : nullptr;

		if ((needCheckDesync && !addrCheckDesync) || (needHandleDesync && !addrHandleDesync))
		{
			BOOST_LOG_TRIVIAL(error) << "Required function pattern(s) not found.";
			return FALSE;
		}

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		if (addrCheckDesync)
		{
			pOriginalCheckDesync = reinterpret_cast<CheckDesync_t>(addrCheckDesync);
			DetourAttach(&reinterpret_cast<PVOID&>(pOriginalCheckDesync), hookCheckDesync);
			BOOST_LOG_TRIVIAL(info) << "Hooked GameLogic_CheckDesync.";
		}
		if (addrHandleDesync)
		{
			pOriginalHandleDesync = reinterpret_cast<HandleDesync_t>(addrHandleDesync);
			DetourAttach(&reinterpret_cast<PVOID&>(pOriginalHandleDesync), hookHandleDesync);
			BOOST_LOG_TRIVIAL(info) << "Hooked GameLogic_HandleDesync.";
		}

		LONG result = DetourTransactionCommit();
		if (result != NO_ERROR)
		{
			BOOST_LOG_TRIVIAL(error) << "DetourTransactionCommit failed: " << result;
			return FALSE;
		}
	}

	// --- CRC interval override ---
	if (needCRCInterval)
	{
		DWORD* pDefaultInterval = GlobalPtr(0x00bf3600);
		DWORD* pNetInterval = GlobalPtr(0x00bf360c);
		DWORD oldProtect;

		if (VirtualProtect(pDefaultInterval, 4, PAGE_READWRITE, &oldProtect))
		{
			*pDefaultInterval = static_cast<DWORD>(config.crcInterval);
			VirtualProtect(pDefaultInterval, 4, oldProtect, &oldProtect);
		}
		if (VirtualProtect(pNetInterval, 4, PAGE_READWRITE, &oldProtect))
		{
			*pNetInterval = static_cast<DWORD>(config.crcInterval);
			VirtualProtect(pNetInterval, 4, oldProtect, &oldProtect);
		}

		BOOST_LOG_TRIVIAL(info) << "CRC interval overridden to " << config.crcInterval << " frames.";
	}

	// --- Disable object CRC ---
	// GameLogic_Update forces g_liteCRC=1 around CRC computation, which ignores all
	// exclusion flags. We NOP that write so g_xObjectCRC is honored.
	//
	// 004ee3f8: C6 05 53 34 BF 00 01  MOV BYTE [g_liteCRC], 1
	// 004ee406: C6 05 53 34 BF 00 00  MOV BYTE [g_liteCRC], 0
	if (needDisableObjectCRC)
	{
		auto liteCRCPattern = ParsePattern("C6 05 53 34 BF 00 01");
		std::byte* liteCRCSet = FindPattern(ptr, size_, liteCRCPattern);
		if (liteCRCSet != nullptr)
		{
			DWORD oldProtect;
			if (VirtualProtect(liteCRCSet, 7, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				memset(liteCRCSet, 0x90, 7);
				VirtualProtect(liteCRCSet, 7, oldProtect, &oldProtect);
			}

			BYTE* pXObjectCRC = reinterpret_cast<BYTE*>(GlobalPtr(0x00bf3448));
			if (VirtualProtect(pXObjectCRC, 1, PAGE_READWRITE, &oldProtect))
			{
				*pXObjectCRC = 1;
				VirtualProtect(pXObjectCRC, 1, oldProtect, &oldProtect);
			}

			BOOST_LOG_TRIVIAL(info) << "Disabled object CRC (g_xObjectCRC=1, liteCRC override NOPed).";
		}
		else
		{
			BOOST_LOG_TRIVIAL(error) << "Failed to find liteCRC override pattern!";
		}
	}

	BOOST_LOG_TRIVIAL(info) << "Desync patches applied successfully.";
	return TRUE;
}
