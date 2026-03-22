// PatchAutomatch.cpp : Debug hooks for KW automatch staging room flow.
//
// Hooks:
//   - joinStagingRoom (0x0098d385): logs error codes (5/6/7/8/10) during room creation
//   - NetworkInit (0x0099e109): logs whether SDK network layer is already initialized
//   - isConnected (0x0098cd59): logs connection state at SDK context + 0x33c8
//
#include "../../Framework.h"
#include "../../util.h"
#include "../../GameVersion.h"
#include "PatchAutomatch.hpp"

extern std::vector<PatternByte> ParsePattern(const std::string& pattern_str);
extern std::byte* FindPattern(std::byte* start_address, size_t search_length, const std::vector<PatternByte>& pattern);

// ---------------------------------------------------------------------------
// Function typedefs (all __cdecl — no this pointer, params on stack)
// ---------------------------------------------------------------------------

// FUN_0098d385: joinStagingRoom inner
// param_1=SDK context, param_2..param_8=room params, param_9=blocking flag
typedef void(__cdecl* JoinStagingRoom_t)(
	int ctx, int param_2, int param_3, const char* param_4,
	int param_5, int param_6, int param_7, int param_8, int blocking);

// FUN_0099e109: NetworkInit — returns true if init succeeded
typedef int(__cdecl* NetworkInit_t)(int ctx, int param_2, short param_3);

// FUN_0098cd59: isConnected — returns true if connected (state != 0 && state != 5)
typedef int(__cdecl* IsConnected_t)(int ctx);

static JoinStagingRoom_t pOrigJoinStagingRoom = nullptr;
static NetworkInit_t pOrigNetworkInit = nullptr;
static IsConnected_t pOrigIsConnected = nullptr;

// ---------------------------------------------------------------------------
// Hook: joinStagingRoom (FUN_0098d385)
// Logs which error path would be taken based on SDK context state,
// then calls the original function.
// ---------------------------------------------------------------------------
static void __cdecl hookJoinStagingRoom(
	int ctx, int param_2, int param_3, const char* param_4,
	int param_5, int param_6, int param_7, int param_8, int blocking)
{
	// Replicate the error-code checks from FUN_0098d385 for logging
	int predictedCode = 10; // default

	if (ctx != 0) {
		bool nickEmpty = (*(char*)(ctx + 0x60) == '\0');
		int field48 = *(int*)(ctx + 0x48);
		int field1654 = *(int*)(ctx + 0x1654);
		int field1660 = *(int*)(ctx + 0x1660);

		if (nickEmpty) {
			predictedCode = 6;
		}
		else if (field48 == 0) {
			predictedCode = 7;
		}
		else if (field1654 != 0 || field1660 != 0) {
			predictedCode = 5;
		}
		else {
			// Would call isConnected next
			int connState = *(int*)(ctx + 0x33c8);
			bool isConn = (connState != 0 && connState != 5);
			if (isConn) {
				predictedCode = 8;
			}
			else {
				predictedCode = 0; // will attempt JOIN
			}
		}

		BOOST_LOG_TRIVIAL(info)
			<< "[AUTOMATCH] joinStagingRoom: ctx=0x" << std::hex << ctx << std::dec
			<< " nick=" << (*(char*)(ctx + 0x60) != '\0' ? "set" : "EMPTY")
			<< " field48=" << *(int*)(ctx + 0x48)
			<< " field1654=" << *(int*)(ctx + 0x1654)
			<< " field1660=" << *(int*)(ctx + 0x1660)
			<< " connState=" << *(int*)(ctx + 0x33c8)
			<< " predicted=" << predictedCode
			<< " blocking=" << blocking;
	}
	else {
		BOOST_LOG_TRIVIAL(warning) << "[AUTOMATCH] joinStagingRoom: ctx is NULL!";
	}

	pOrigJoinStagingRoom(ctx, param_2, param_3, param_4,
		param_5, param_6, param_7, param_8, blocking);
}

// ---------------------------------------------------------------------------
// Hook: NetworkInit (FUN_0099e109)
// ---------------------------------------------------------------------------
static int __cdecl hookNetworkInit(int ctx, int param_2, short param_3)
{
	int alreadyInit = *(int*)(ctx + 0x1e08);

	BOOST_LOG_TRIVIAL(info)
		<< "[AUTOMATCH] NetworkInit: ctx=0x" << std::hex << ctx << std::dec
		<< " alreadyInit=" << alreadyInit
		<< " param_2=" << param_2
		<< " param_3=" << param_3;

	int result = pOrigNetworkInit(ctx, param_2, param_3);

	BOOST_LOG_TRIVIAL(info)
		<< "[AUTOMATCH] NetworkInit returned: " << result
		<< (alreadyInit ? " (was already initialized — returned false)" : "");

	return result;
}

// ---------------------------------------------------------------------------
// Hook: isConnected (FUN_0098cd59)
// ---------------------------------------------------------------------------
static int __cdecl hookIsConnected(int ctx)
{
	int connState = *(int*)(ctx + 0x33c8);
	int result = pOrigIsConnected(ctx);

	BOOST_LOG_TRIVIAL(debug)
		<< "[AUTOMATCH] isConnected: state=" << connState
		<< " result=" << result;

	return result;
}

// ---------------------------------------------------------------------------
// Patterns (first unique bytes of each function)
// ---------------------------------------------------------------------------

// FUN_0098d385: 55 8BEC 51 53 56 8B7508 57 56 C745FC 0A000000
static const char* PATTERN_JOIN_STAGING =
	"55 8B EC 51 53 56 8B 75 08 57 56 C7 45 FC 0A 00 00 00";

// FUN_0099e109: 8B4C2404 8D81 081E0000 833800
static const char* PATTERN_NETWORK_INIT =
	"8B 4C 24 04 8D 81 08 1E 00 00 83 38 00";

// FUN_0098cd59: 8B442404 8B80 C8330000 85C0
static const char* PATTERN_IS_CONNECTED =
	"8B 44 24 04 8B 80 C8 33 00 00 85 C0";

// ---------------------------------------------------------------------------
// PatchAutomatch implementation
// ---------------------------------------------------------------------------

PatchAutomatch::PatchAutomatch()
{
	HANDLE hModule = GetModuleHandle(nullptr);
	baseAddress_ = reinterpret_cast<DWORD>(hModule);
	size_ = GetModuleSize(hModule);
	offset_ = GetEntryPointOffset(hModule);
	entryPoint_ = baseAddress_ + offset_;
}

BOOL PatchAutomatch::Patch() const
{
	BOOST_LOG_NAMED_SCOPE("AutomatchPatch")

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

	std::byte* addrJoinStaging = findFunc(PATTERN_JOIN_STAGING, "joinStagingRoom");
	std::byte* addrNetworkInit = findFunc(PATTERN_NETWORK_INIT, "NetworkInit");
	std::byte* addrIsConnected = findFunc(PATTERN_IS_CONNECTED, "isConnected");

	if (!addrJoinStaging && !addrNetworkInit && !addrIsConnected) {
		BOOST_LOG_TRIVIAL(error) << "No automatch patterns found.";
		return FALSE;
	}

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	if (addrJoinStaging) {
		pOrigJoinStagingRoom = reinterpret_cast<JoinStagingRoom_t>(addrJoinStaging);
		DetourAttach(&reinterpret_cast<PVOID&>(pOrigJoinStagingRoom), hookJoinStagingRoom);
		BOOST_LOG_TRIVIAL(info) << "Hooked joinStagingRoom.";
	}
	if (addrNetworkInit) {
		pOrigNetworkInit = reinterpret_cast<NetworkInit_t>(addrNetworkInit);
		DetourAttach(&reinterpret_cast<PVOID&>(pOrigNetworkInit), hookNetworkInit);
		BOOST_LOG_TRIVIAL(info) << "Hooked NetworkInit.";
	}
	if (addrIsConnected) {
		pOrigIsConnected = reinterpret_cast<IsConnected_t>(addrIsConnected);
		DetourAttach(&reinterpret_cast<PVOID&>(pOrigIsConnected), hookIsConnected);
		BOOST_LOG_TRIVIAL(info) << "Hooked isConnected.";
	}

	LONG result = DetourTransactionCommit();
	if (result != NO_ERROR) {
		BOOST_LOG_TRIVIAL(error) << "DetourTransactionCommit failed: " << result;
		return FALSE;
	}

	BOOST_LOG_TRIVIAL(info) << "Automatch debug hooks installed successfully.";
	return TRUE;
}
