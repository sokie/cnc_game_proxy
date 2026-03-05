// PatchDesync.cpp : Hooks for CNC3 desync detection and handling.
//
// Hooks two game functions:
//   1. GameLogic_CheckDesync (0x004cdefd in cnc3game.dat)
//      - Called every NetCRCInterval frames to compare CRC values between peers
//      - Hook logs CRC mismatches with frame, player, and CRC values
//
//   2. GameLogic_HandleDesync (0x004c8410 in cnc3game.dat)
//      - Called when a desync is confirmed, shows dialog and writes dump files
//      - Hook can suppress the dialog/disconnect via config flag
//
#include "../../Framework.h"
#include "../../util.h"
#include "../../GameVersion.h"
#include "PatchDesync.hpp"

extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);
extern std::byte* FindPattern(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern);

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

// GameLogic_CheckDesync:
//   void __thiscall(this, uint crcValue, uint playerSlot, uint frameNumber,
//                   int context, char forceFlag, uint binaryCRCData)
typedef void(__fastcall* CheckDesync_t)(
	void* thisPtr, void* edx,
	UINT crcValue, UINT playerSlot, UINT frameNumber,
	int context, char forceFlag, UINT binaryCRCData);

// GameLogic_HandleDesync:
//   void __thiscall(this, int frameData, uint frameNumber, uint playerSlot)
typedef void(__fastcall* HandleDesync_t)(
	void* thisPtr, void* edx,
	int frameData, UINT frameNumber, UINT playerSlot);

static CheckDesync_t pOriginalCheckDesync = nullptr;
static HandleDesync_t pOriginalHandleDesync = nullptr;

// ---------------------------------------------------------------------------
// Hook: GameLogic_CheckDesync
// Logs CRC mismatches before passing through to original
// ---------------------------------------------------------------------------
static void __fastcall hookCheckDesync(
	void* thisPtr, void* edx,
	UINT crcValue, UINT playerSlot, UINT frameNumber,
	int context, char forceFlag, UINT binaryCRCData)
{
	const auto& config = Config::GetInstance();

	if (config.logDesyncMismatch)
	{
		// Walk the CRC linked list at this+0x40 to find existing entry for this frame
		CRCEntry* entry = *reinterpret_cast<CRCEntry**>(
			static_cast<BYTE*>(thisPtr) + 0x40);

		while (entry != nullptr && entry->frameNumber < frameNumber)
		{
			entry = entry->next;
		}

		if (entry != nullptr && entry->frameNumber == frameNumber)
		{
			// Entry exists for this frame -- check if incoming CRC matches
			if (crcValue != entry->crcValue)
			{
				BOOST_LOG_TRIVIAL(warning)
					<< "[DESYNC] CRC mismatch on frame " << frameNumber
					<< ": first=0x" << std::hex << std::setfill('0') << std::setw(8) << entry->crcValue
					<< ", incoming=0x" << std::setw(8) << crcValue
					<< std::dec << " from player " << playerSlot
					<< " (confirmed by " << entry->playerCount << " player(s) so far"
					<< ", bitmask=0x" << std::hex << entry->playerBitmask << std::dec << ")";
			}
			else
			{
				BOOST_LOG_TRIVIAL(debug)
					<< "[DESYNC] CRC match on frame " << frameNumber
					<< ": 0x" << std::hex << std::setfill('0') << std::setw(8) << crcValue
					<< std::dec << " from player " << playerSlot;
			}
		}
		else
		{
			// First CRC for this frame -- log it
			BOOST_LOG_TRIVIAL(debug)
				<< "[DESYNC] CRC check frame " << frameNumber
				<< ": 0x" << std::hex << std::setfill('0') << std::setw(8) << crcValue
				<< std::dec << " from player " << playerSlot << " (first)";
		}
	}

	pOriginalCheckDesync(thisPtr, edx, crcValue, playerSlot, frameNumber,
		context, forceFlag, binaryCRCData);
}

// ---------------------------------------------------------------------------
// Hook: GameLogic_HandleDesync
// Optionally suppresses the desync dialog/disconnect
// ---------------------------------------------------------------------------
static void __fastcall hookHandleDesync(
	void* thisPtr, void* edx,
	int frameData, UINT frameNumber, UINT playerSlot)
{
	const auto& config = Config::GetInstance();

	BOOST_LOG_TRIVIAL(warning)
		<< "[DESYNC] Desync handler invoked (frameData=" << frameData
		<< ", frameNumber=" << frameNumber
		<< ", playerSlot=" << playerSlot << ")";

	if (config.suppressDesyncDialog)
	{
		// Set the desync flag (this+0x6a) so the game stops re-triggering
		// desync checks for subsequent frames, but skip the dialog and dump files
		*reinterpret_cast<BYTE*>(static_cast<BYTE*>(thisPtr) + 0x6a) = 1;

		BOOST_LOG_TRIVIAL(info)
			<< "[DESYNC] Desync dialog suppressed (config: desync.suppressDialog=true)";
		return;
	}

	pOriginalHandleDesync(thisPtr, edx, frameData, frameNumber, playerSlot);
}

// ---------------------------------------------------------------------------
// Pattern-based function lookup
// ---------------------------------------------------------------------------

// GameLogic_CheckDesync prologue:
//   55 8B EC 51 53 56 8B F1 33 DB 57 8B 7E 40
//   PUSH EBP; MOV EBP,ESP; PUSH ECX; PUSH EBX; PUSH ESI; MOV ESI,ECX;
//   XOR EBX,EBX; PUSH EDI; MOV EDI,[ESI+0x40]
static const char* PATTERN_CHECK_DESYNC = "55 8B EC 51 53 56 8B F1 33 DB 57 8B 7E 40";

// GameLogic_HandleDesync prologue:
//   55 8B EC 81 EC 1C 01 00 00 53 8B D9 57 C6 43 6A 01 33 FF
//   PUSH EBP; MOV EBP,ESP; SUB ESP,0x11C; PUSH EBX; MOV EBX,ECX;
//   PUSH EDI; MOV BYTE [EBX+0x6A],1; XOR EDI,EDI
static const char* PATTERN_HANDLE_DESYNC = "55 8B EC 81 EC 1C 01 00 00 53 8B D9 57 C6 43 6A 01 33 FF";

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

	if (!config.logDesyncMismatch && !config.suppressDesyncDialog)
	{
		BOOST_LOG_TRIVIAL(info) << "Desync hooks disabled in config, skipping.";
		return TRUE;
	}

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	// --- Find GameLogic_CheckDesync ---
	auto pattern = ParsePattern(PATTERN_CHECK_DESYNC);
	std::byte* addrCheckDesync = FindPattern(ptr, size_, pattern);
	if (addrCheckDesync == nullptr)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to find GameLogic_CheckDesync pattern!";
		return FALSE;
	}
	BOOST_LOG_TRIVIAL(info) << "Found GameLogic_CheckDesync at: 0x"
		<< std::hex << reinterpret_cast<DWORD>(addrCheckDesync);

	// --- Find GameLogic_HandleDesync ---
	pattern = ParsePattern(PATTERN_HANDLE_DESYNC);
	std::byte* addrHandleDesync = FindPattern(ptr, size_, pattern);
	if (addrHandleDesync == nullptr)
	{
		BOOST_LOG_TRIVIAL(error) << "Failed to find GameLogic_HandleDesync pattern!";
		return FALSE;
	}
	BOOST_LOG_TRIVIAL(info) << "Found GameLogic_HandleDesync at: 0x"
		<< std::hex << reinterpret_cast<DWORD>(addrHandleDesync);

	// --- Install Detours hooks ---
	pOriginalCheckDesync = reinterpret_cast<CheckDesync_t>(addrCheckDesync);
	pOriginalHandleDesync = reinterpret_cast<HandleDesync_t>(addrHandleDesync);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (config.logDesyncMismatch)
	{
		DetourAttach(&reinterpret_cast<PVOID&>(pOriginalCheckDesync), hookCheckDesync);
		BOOST_LOG_TRIVIAL(info) << "Hooked GameLogic_CheckDesync for mismatch logging.";
	}

	if (config.suppressDesyncDialog)
	{
		DetourAttach(&reinterpret_cast<PVOID&>(pOriginalHandleDesync), hookHandleDesync);
		BOOST_LOG_TRIVIAL(info) << "Hooked GameLogic_HandleDesync for dialog suppression.";
	}

	LONG result = DetourTransactionCommit();
	if (result != NO_ERROR)
	{
		BOOST_LOG_TRIVIAL(error) << "DetourTransactionCommit failed: " << result;
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Desync hooks installed successfully.";
	return TRUE;
}
