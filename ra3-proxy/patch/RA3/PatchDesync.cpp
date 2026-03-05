// PatchDesync.cpp : Hooks for CNC3 desync detection and handling.
//
// Hooks four game functions:
//   1. GameLogic_CheckDesync (0x004cdefd)
//      - Logs CRC mismatches, optionally forces CRC match to prevent desync
//   2. GameLogic_HandleDesync (0x004c8410)
//      - Optionally suppresses the desync dialog/disconnect
//   3. GameLogic_ComputeStateCRC (0x004b6901)
//      - Tracks per-subsystem CRC contributions
//   4. XferCRC_XferSnapshot (0x009dc6a3)
//      - Captures before/after CRC for each subsystem during computation
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
// Per-subsystem CRC tracking state
// ---------------------------------------------------------------------------
struct SubsystemCRCEntry {
	const char* name;
	DWORD crcBefore;
	DWORD crcAfter;
};

// Object CRC checkpoint: CRC value sampled at every Nth object
static const int OBJECT_CHECKPOINT_INTERVAL = 100;
static const int MAX_OBJECT_CHECKPOINTS = 64; // supports up to 6400 objects

struct ObjectCheckpoint {
	int objectIndex;   // which object number (0-based)
	DWORD crcAfter;    // CRC after this object was xfered
};

static struct {
	bool active;
	int objectCount;
	DWORD objectsCRCStart;
	DWORD objectsCRCEnd;
	SubsystemCRCEntry subsystems[12];
	int subsystemCount;
	DWORD totalCRC;
	DWORD frameNumber;
	// XferInt tracking: frame seed + player commands
	int xferIntCount;        // total xferInt calls seen
	DWORD frameSeedValue;    // the frame seed integer value
	DWORD frameSeedCRCBefore;
	DWORD frameSeedCRCAfter;
	bool frameSeedCaptured;
	bool insideXferSnapshot; // true while inside a xferSnapshot call (to ignore nested xferInt)
	int playerCmdCount;
	DWORD playerCmdSums[20]; // per-player command sums
	// Object CRC checkpoints: sampled every N objects
	ObjectCheckpoint objectCheckpoints[MAX_OBJECT_CHECKPOINTS];
	int checkpointCount;
} g_crcTrack = {};

// Last completed CRC breakdown (dumped on mismatch)
static struct {
	bool valid;
	DWORD frameNumber;
	DWORD totalCRC;
	int objectCount;
	DWORD objectsCRCStart;
	DWORD objectsCRCEnd;
	SubsystemCRCEntry subsystems[12];
	int subsystemCount;
	DWORD frameSeedValue;
	DWORD frameSeedCRCBefore;
	DWORD frameSeedCRCAfter;
	int playerCmdCount;
	DWORD playerCmdSums[20];
	ObjectCheckpoint objectCheckpoints[MAX_OBJECT_CHECKPOINTS];
	int checkpointCount;
} g_lastBreakdown = {};

// ---------------------------------------------------------------------------
// Subsystem identification from snapshot pointer
// ---------------------------------------------------------------------------
struct SubsystemGlobal {
	DWORD ghidraAddr;
	const char* name;
};

static const SubsystemGlobal KNOWN_SUBSYSTEMS[] = {
	{ 0x00bf3490, "Partition" },
	{ 0x00bf349c, "Collision" },
	{ 0x00bf3494, "Shroud" },
	{ 0x00bf3498, "Taint" },
	{ 0x00bf958c, "SkirmishAI" },
	{ 0x00bee110, "PlayerList" },
	{ 0x00bf4d24, "AI" },
	{ 0x00bf9548, "Display" },
};

static const char* identifySubsystem(void* snapshotPtr)
{
	DWORD addr = reinterpret_cast<DWORD>(snapshotPtr);
	for (const auto& sys : KNOWN_SUBSYSTEMS)
	{
		DWORD globalVal = *GlobalPtr(sys.ghidraAddr);
		if (globalVal != 0 && addr == globalVal + 0x18)
			return sys.name;
	}
	return nullptr;
}

static void logCRCBreakdown(const char* prefix)
{
	if (!g_lastBreakdown.valid)
		return;

	BOOST_LOG_TRIVIAL(warning)
		<< prefix << "Frame " << g_lastBreakdown.frameNumber
		<< " total=0x" << std::hex << std::setfill('0') << std::setw(8) << g_lastBreakdown.totalCRC;

	if (g_lastBreakdown.objectCount > 0)
	{
		BOOST_LOG_TRIVIAL(warning)
			<< prefix << "  Objects (" << std::dec << g_lastBreakdown.objectCount << "): 0x"
			<< std::hex << std::setfill('0') << std::setw(8) << g_lastBreakdown.objectsCRCStart
			<< " -> 0x" << std::setw(8) << g_lastBreakdown.objectsCRCEnd;

		// Log object checkpoints (CRC sampled every N objects)
		for (int i = 0; i < g_lastBreakdown.checkpointCount; i++)
		{
			const auto& cp = g_lastBreakdown.objectCheckpoints[i];
			BOOST_LOG_TRIVIAL(warning)
				<< prefix << "    obj[" << std::dec << cp.objectIndex << "]: 0x"
				<< std::hex << std::setfill('0') << std::setw(8) << cp.crcAfter;
		}
	}

	BOOST_LOG_TRIVIAL(warning)
		<< prefix << "  FrameSeed: value=0x"
		<< std::hex << std::setfill('0') << std::setw(8) << g_lastBreakdown.frameSeedValue
		<< " crc: 0x" << std::setw(8) << g_lastBreakdown.frameSeedCRCBefore
		<< " -> 0x" << std::setw(8) << g_lastBreakdown.frameSeedCRCAfter;

	for (int i = 0; i < g_lastBreakdown.subsystemCount; i++)
	{
		const auto& s = g_lastBreakdown.subsystems[i];
		BOOST_LOG_TRIVIAL(warning)
			<< prefix << "  " << s.name << ": 0x"
			<< std::hex << std::setfill('0') << std::setw(8) << s.crcBefore
			<< " -> 0x" << std::setw(8) << s.crcAfter;
	}

	if (g_lastBreakdown.playerCmdCount > 0)
	{
		std::ostringstream oss;
		oss << prefix << "  PlayerCmds (" << std::dec << g_lastBreakdown.playerCmdCount << "): ";
		for (int i = 0; i < g_lastBreakdown.playerCmdCount && i < 20; i++)
		{
			if (i > 0) oss << ", ";
			oss << "[" << i << "]=0x" << std::hex << g_lastBreakdown.playerCmdSums[i];
		}
		BOOST_LOG_TRIVIAL(warning) << oss.str();
	}
}

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

// GameLogic_ComputeStateCRC: returns CRC value
typedef DWORD(__fastcall* ComputeStateCRC_t)(
	void* thisPtr, void* edx, UINT debugFileHandle);

// XferCRC_XferSnapshot: returns this
typedef void* (__fastcall* XferSnapshot_t)(
	void* thisXfer, void* edx, void* snapshotPtr);

// XferCRC_XferInt: feeds a 4-byte int into CRC, returns this
typedef void* (__fastcall* XferInt_t)(
	void* thisXfer, void* edx, void* valuePtr);

static CheckDesync_t pOriginalCheckDesync = nullptr;
static HandleDesync_t pOriginalHandleDesync = nullptr;
static ComputeStateCRC_t pOriginalComputeStateCRC = nullptr;
static XferSnapshot_t pOriginalXferSnapshot = nullptr;
static XferInt_t pOriginalXferInt = nullptr;

// ---------------------------------------------------------------------------
// Hook: XferCRC_XferSnapshot
// Captures per-subsystem CRC contributions during state CRC computation
// ---------------------------------------------------------------------------
static void* __fastcall hookXferSnapshot(
	void* thisXfer, void* edx, void* snapshotPtr)
{
	if (!g_crcTrack.active)
		return pOriginalXferSnapshot(thisXfer, edx, snapshotPtr);

	DWORD crcBefore = *reinterpret_cast<DWORD*>(static_cast<BYTE*>(thisXfer) + 0x144);
	const char* name = identifySubsystem(snapshotPtr);

	// Mark that we're inside xferSnapshot so hookXferInt ignores nested calls
	// (objects call xferInt internally for their fields)
	g_crcTrack.insideXferSnapshot = true;
	void* result = pOriginalXferSnapshot(thisXfer, edx, snapshotPtr);
	g_crcTrack.insideXferSnapshot = false;

	DWORD crcAfter = *reinterpret_cast<DWORD*>(static_cast<BYTE*>(thisXfer) + 0x144);

	if (name)
	{
		// Known subsystem
		if (g_crcTrack.subsystemCount < 12)
		{
			auto& entry = g_crcTrack.subsystems[g_crcTrack.subsystemCount++];
			entry.name = name;
			entry.crcBefore = crcBefore;
			entry.crcAfter = crcAfter;
		}
	}
	else
	{
		// Game object
		if (g_crcTrack.objectCount == 0)
			g_crcTrack.objectsCRCStart = crcBefore;
		g_crcTrack.objectCount++;
		g_crcTrack.objectsCRCEnd = crcAfter;

		// Record checkpoint every N objects
		if ((g_crcTrack.objectCount % OBJECT_CHECKPOINT_INTERVAL) == 0 &&
			g_crcTrack.checkpointCount < MAX_OBJECT_CHECKPOINTS)
		{
			auto& cp = g_crcTrack.objectCheckpoints[g_crcTrack.checkpointCount++];
			cp.objectIndex = g_crcTrack.objectCount;
			cp.crcAfter = crcAfter;
		}
	}

	return result;
}

// ---------------------------------------------------------------------------
// Hook: XferCRC_XferInt
// Captures frame seed and player command sums during CRC computation
// Order in ComputeStateCRC: CRCParams(xferInt*N) -> Objects -> FrameSeed(xferInt)
//                           -> Subsystems -> PlayerCmds(xferInt*20) -> VerifyBool
// ---------------------------------------------------------------------------
static void* __fastcall hookXferInt(
	void* thisXfer, void* edx, void* valuePtr)
{
	// Skip if not tracking, or if we're inside a xferSnapshot call
	// (objects call xferInt internally for their fields — we only want
	// top-level xferInt calls: frame seed and player commands)
	if (!g_crcTrack.active || g_crcTrack.insideXferSnapshot)
		return pOriginalXferInt(thisXfer, edx, valuePtr);

	DWORD intValue = *reinterpret_cast<DWORD*>(valuePtr);
	DWORD crcBefore = *reinterpret_cast<DWORD*>(static_cast<BYTE*>(thisXfer) + 0x144);

	void* result = pOriginalXferInt(thisXfer, edx, valuePtr);

	DWORD crcAfter = *reinterpret_cast<DWORD*>(static_cast<BYTE*>(thisXfer) + 0x144);

	// Frame seed: first top-level xferInt AFTER objects, BEFORE subsystems
	if (g_crcTrack.objectCount > 0 && !g_crcTrack.frameSeedCaptured &&
		g_crcTrack.subsystemCount == 0)
	{
		g_crcTrack.frameSeedValue = intValue;
		g_crcTrack.frameSeedCRCBefore = crcBefore;
		g_crcTrack.frameSeedCRCAfter = crcAfter;
		g_crcTrack.frameSeedCaptured = true;
	}
	// Player command sums: top-level xferInt calls AFTER subsystems
	else if (g_crcTrack.subsystemCount > 0 && g_crcTrack.playerCmdCount < 20)
	{
		g_crcTrack.playerCmdSums[g_crcTrack.playerCmdCount++] = intValue;
	}

	g_crcTrack.xferIntCount++;
	return result;
}

// ---------------------------------------------------------------------------
// Hook: GameLogic_ComputeStateCRC
// Wraps the CRC computation to track per-subsystem contributions
// ---------------------------------------------------------------------------
static DWORD __fastcall hookComputeStateCRC(
	void* thisPtr, void* edx, UINT debugFileHandle)
{
	// Reset tracking state
	memset(&g_crcTrack, 0, sizeof(g_crcTrack));
	g_crcTrack.active = true;

	DWORD result = pOriginalComputeStateCRC(thisPtr, edx, debugFileHandle);

	g_crcTrack.active = false;
	g_crcTrack.totalCRC = result;
	g_crcTrack.frameNumber = *reinterpret_cast<DWORD*>(static_cast<BYTE*>(thisPtr) + 0x38);

	// Save breakdown for later (dumped on mismatch)
	g_lastBreakdown.valid = true;
	g_lastBreakdown.frameNumber = g_crcTrack.frameNumber;
	g_lastBreakdown.totalCRC = result;
	g_lastBreakdown.objectCount = g_crcTrack.objectCount;
	g_lastBreakdown.objectsCRCStart = g_crcTrack.objectsCRCStart;
	g_lastBreakdown.objectsCRCEnd = g_crcTrack.objectsCRCEnd;
	g_lastBreakdown.subsystemCount = g_crcTrack.subsystemCount;
	memcpy(g_lastBreakdown.subsystems, g_crcTrack.subsystems,
		sizeof(SubsystemCRCEntry) * g_crcTrack.subsystemCount);
	g_lastBreakdown.frameSeedValue = g_crcTrack.frameSeedValue;
	g_lastBreakdown.frameSeedCRCBefore = g_crcTrack.frameSeedCRCBefore;
	g_lastBreakdown.frameSeedCRCAfter = g_crcTrack.frameSeedCRCAfter;
	g_lastBreakdown.playerCmdCount = g_crcTrack.playerCmdCount;
	memcpy(g_lastBreakdown.playerCmdSums, g_crcTrack.playerCmdSums,
		sizeof(DWORD) * g_crcTrack.playerCmdCount);
	g_lastBreakdown.checkpointCount = g_crcTrack.checkpointCount;
	memcpy(g_lastBreakdown.objectCheckpoints, g_crcTrack.objectCheckpoints,
		sizeof(ObjectCheckpoint) * g_crcTrack.checkpointCount);

	const auto& config = Config::GetInstance();
	if (config.logSubsystemCRC)
	{
		logCRCBreakdown("[CRC] ");
	}

	return result;
}

// ---------------------------------------------------------------------------
// Hook: GameLogic_CheckDesync
// Logs mismatches, dumps per-subsystem CRC, optionally forces match
// ---------------------------------------------------------------------------
static void __fastcall hookCheckDesync(
	void* thisPtr, void* edx,
	UINT crcValue, UINT playerSlot, UINT frameNumber,
	int context, char forceFlag, UINT binaryCRCData)
{
	const auto& config = Config::GetInstance();

	if (config.logDesyncMismatch)
	{
		CRCEntry* entry = *reinterpret_cast<CRCEntry**>(
			static_cast<BYTE*>(thisPtr) + 0x40);

		while (entry != nullptr && entry->frameNumber < frameNumber)
			entry = entry->next;

		if (entry != nullptr && entry->frameNumber == frameNumber)
		{
			if (crcValue != entry->crcValue)
			{
				BOOST_LOG_TRIVIAL(warning)
					<< "[DESYNC] CRC mismatch on frame " << frameNumber
					<< ": first=0x" << std::hex << std::setfill('0') << std::setw(8) << entry->crcValue
					<< ", incoming=0x" << std::setw(8) << crcValue
					<< std::dec << " from player " << playerSlot
					<< " (confirmed by " << entry->playerCount << " player(s) so far"
					<< ", bitmask=0x" << std::hex << entry->playerBitmask << std::dec << ")";

				// Dump per-subsystem CRC breakdown if available
				logCRCBreakdown("[DESYNC-DETAIL] ");
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
			BOOST_LOG_TRIVIAL(debug)
				<< "[DESYNC] CRC check frame " << frameNumber
				<< ": 0x" << std::hex << std::setfill('0') << std::setw(8) << crcValue
				<< std::dec << " from player " << playerSlot << " (first)";
		}
	}

	// Force CRC match: override incoming CRC to prevent desync detection
	if (config.forceCRCMatch)
	{
		CRCEntry* entry = *reinterpret_cast<CRCEntry**>(
			static_cast<BYTE*>(thisPtr) + 0x40);

		while (entry != nullptr && entry->frameNumber < frameNumber)
			entry = entry->next;

		if (entry != nullptr && entry->frameNumber == frameNumber && crcValue != entry->crcValue)
		{
			BOOST_LOG_TRIVIAL(info)
				<< "[DESYNC] Forcing CRC match on frame " << frameNumber
				<< ": overriding 0x" << std::hex << std::setfill('0') << std::setw(8) << crcValue
				<< " with 0x" << std::setw(8) << entry->crcValue << std::dec;
			crcValue = entry->crcValue;
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

// GameLogic_CheckDesync: 55 8B EC 51 53 56 8B F1 33 DB 57 8B 7E 40
static const char* PATTERN_CHECK_DESYNC =
	"55 8B EC 51 53 56 8B F1 33 DB 57 8B 7E 40";

// GameLogic_HandleDesync: 55 8B EC 81 EC 1C 01 00 00 53 8B D9 57 C6 43 6A 01 33 FF
static const char* PATTERN_HANDLE_DESYNC =
	"55 8B EC 81 EC 1C 01 00 00 53 8B D9 57 C6 43 6A 01 33 FF";

// GameLogic_ComputeStateCRC: 55 8D 6C 24 8C 81 EC 5C 01 00 00 53 56 57 8B F9
static const char* PATTERN_COMPUTE_CRC =
	"55 8D 6C 24 8C 81 EC 5C 01 00 00 53 56 57 8B F9";

// XferCRC_XferSnapshot: 53 8B 5C 24 08 56 8B F1 80 BE 0C 01 00 00 00
static const char* PATTERN_XFER_SNAPSHOT =
	"53 8B 5C 24 08 56 8B F1 80 BE 0C 01 00 00 00";

// XferCRC_XferInt: 56 6A 04 FF 74 24 0C 8B F1 8B 06 68
static const char* PATTERN_XFER_INT =
	"56 6A 04 FF 74 24 0C 8B F1 8B 06 68";

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
	bool needSubsystemCRC = config.logSubsystemCRC || config.logDesyncMismatch;

	if (!needCheckDesync && !needHandleDesync && !needSubsystemCRC)
	{
		BOOST_LOG_TRIVIAL(info) << "Desync hooks disabled in config, skipping.";
		return TRUE;
	}

	std::byte* ptr = reinterpret_cast<std::byte*>(entryPoint_);

	// --- Find all required functions ---
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

	std::byte* addrCheckDesync = nullptr;
	std::byte* addrHandleDesync = nullptr;
	std::byte* addrComputeCRC = nullptr;
	std::byte* addrXferSnapshot = nullptr;
	std::byte* addrXferInt = nullptr;

	if (needCheckDesync)
		addrCheckDesync = findFunc(PATTERN_CHECK_DESYNC, "GameLogic_CheckDesync");
	if (needHandleDesync)
		addrHandleDesync = findFunc(PATTERN_HANDLE_DESYNC, "GameLogic_HandleDesync");
	if (needSubsystemCRC)
	{
		addrComputeCRC = findFunc(PATTERN_COMPUTE_CRC, "GameLogic_ComputeStateCRC");
		addrXferSnapshot = findFunc(PATTERN_XFER_SNAPSHOT, "XferCRC_XferSnapshot");
		addrXferInt = findFunc(PATTERN_XFER_INT, "XferCRC_XferInt");
	}

	// Verify all required functions were found
	if ((needCheckDesync && !addrCheckDesync) ||
		(needHandleDesync && !addrHandleDesync) ||
		(needSubsystemCRC && (!addrComputeCRC || !addrXferSnapshot || !addrXferInt)))
	{
		BOOST_LOG_TRIVIAL(error) << "Required function pattern(s) not found, aborting.";
		return FALSE;
	}

	// --- Install Detours hooks ---
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
	if (addrComputeCRC)
	{
		pOriginalComputeStateCRC = reinterpret_cast<ComputeStateCRC_t>(addrComputeCRC);
		DetourAttach(&reinterpret_cast<PVOID&>(pOriginalComputeStateCRC), hookComputeStateCRC);
		BOOST_LOG_TRIVIAL(info) << "Hooked GameLogic_ComputeStateCRC.";
	}
	if (addrXferSnapshot)
	{
		pOriginalXferSnapshot = reinterpret_cast<XferSnapshot_t>(addrXferSnapshot);
		DetourAttach(&reinterpret_cast<PVOID&>(pOriginalXferSnapshot), hookXferSnapshot);
		BOOST_LOG_TRIVIAL(info) << "Hooked XferCRC_XferSnapshot.";
	}
	if (addrXferInt)
	{
		pOriginalXferInt = reinterpret_cast<XferInt_t>(addrXferInt);
		DetourAttach(&reinterpret_cast<PVOID&>(pOriginalXferInt), hookXferInt);
		BOOST_LOG_TRIVIAL(info) << "Hooked XferCRC_XferInt.";
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
