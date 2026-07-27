// RA3BNDelegate.hpp : Hands RA3 Battle.net connectivity over to RA3BN's own
// NativeDll.dll, which the user already has installed. It covers what hostname
// redirection cannot: the relay mesh, master proxy, query master and Sake.
#pragma once
#include "../../Framework.h"
#include <string>

class RA3BNDelegate
{
public:
	static RA3BNDelegate& GetInstance()
	{
		static RA3BNDelegate instance;
		return instance;
	}

	RA3BNDelegate(const RA3BNDelegate&) = delete;
	RA3BNDelegate& operator=(const RA3BNDelegate&) = delete;

	// Spawns a worker that waits for the game window, then loads and invokes
	// RA3BN's client. False if we did not start: wrong build, or client not found.
	bool Start();

	// Locates RA3BN's NativeDll.dll. Empty if it cannot be found.
	static std::wstring ResolveClientDll();

private:
	RA3BNDelegate() = default;

	static bool IsSupportedGame();
	static std::wstring ResolveLogFolder(const std::wstring& clientDllPath);
	static bool WaitForGameWindow(DWORD timeoutMs);
	static void Worker();
};
