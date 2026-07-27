// RA3BNDelegate.cpp : Loads RA3 Battle.net's own NativeDll.dll and invokes it.
//
// We are already inside the game, so we call its in-process entry point directly
// rather than injecting the way their launcher does.
//
// Two constraints:
//   1. Load it from its installed location. Their asset loader resolves game
//      content relative to the DLL's own directory (contents\data\).
//   2. Do not invoke it before the game window exists. Their entry point
//      dereferences live game objects and fail-fasts if they are not ready.
#include "../../Framework.h"
#include "../../util.h"
#include "../../GameVersion.h"
#include "RA3BNDelegate.hpp"

#include <thread>
#include <string>
#include <vector>

namespace {

// Matches the anonymous struct their entry point expects (native_dll.cpp).
// user_data is a UTF-8 *folder* path; they create it and write NativeDll.dll.txt.
struct RemoteEntryInfo
{
	std::uint32_t host_pid;
	const char* user_data;
	std::uint32_t user_data_size;
};

// native_invoke_entry_point is __cdecl and exports undecorated; it forwards to
// NativeInjectionEntryPoint, which is __stdcall (_NativeInjectionEntryPoint@4).
using NativeInvokeCdecl = void(__cdecl*)(RemoteEntryInfo*);
using NativeInvokeStdcall = void(__stdcall*)(RemoteEntryInfo*);

// Their window class, and the variant a modded RA3 uses (see their Injector.cs).
constexpr wchar_t RA3_WINDOW_CLASS[] = L"41DAF790-16F5-4881-8754-59FD8CF3B8D2";
constexpr wchar_t RA3_WINDOW_CLASS_MODDED[] = L"71DAF790-16F5-4881-8754-59FD8CF3B8D2";

constexpr wchar_t CLIENT_APP_PATHS_KEY[] =
	L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Ra3.BattleNet.Client.exe";
constexpr wchar_t CLIENT_DLL_RELATIVE[] = L"contents\\NativeDll.dll";

std::wstring ParentDirectory(const std::wstring& path)
{
	const size_t slash = path.find_last_of(L"\\/");
	return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

bool FileExists(const std::wstring& path)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

// Reads the install path their NSIS installer records under App Paths. We are a
// 32-bit process, so check both registry views rather than relying on redirection.
std::wstring ReadClientInstallDirFromRegistry()
{
	for (const REGSAM view : { KEY_WOW64_32KEY, KEY_WOW64_64KEY }) {
		for (const HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
			HKEY key = nullptr;
			if (RegOpenKeyExW(root, CLIENT_APP_PATHS_KEY, 0, KEY_READ | view, &key) != ERROR_SUCCESS) {
				continue;
			}

			wchar_t buffer[MAX_PATH] = { 0 };
			DWORD size = sizeof(buffer) - sizeof(wchar_t);
			DWORD type = 0;
			const LSTATUS status = RegQueryValueExW(key, nullptr, nullptr, &type,
			                                        reinterpret_cast<LPBYTE>(buffer), &size);
			RegCloseKey(key);

			if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
				// The value is the full path to Ra3.BattleNet.Client.exe.
				std::wstring directory = ParentDirectory(buffer);
				if (!directory.empty()) {
					return directory;
				}
			}
		}
	}
	return std::wstring();
}

// Lets ra3bn.clientDll use %APPDATA%, handy inside a Wine prefix.
std::wstring ExpandEnv(const std::wstring& value)
{
	if (value.find(L'%') == std::wstring::npos) {
		return value;
	}
	wchar_t buffer[1024] = { 0 };
	const DWORD written = ExpandEnvironmentStringsW(value.c_str(), buffer,
	                                               static_cast<DWORD>(std::size(buffer)));
	if (written == 0 || written > std::size(buffer)) {
		return value;
	}
	return std::wstring(buffer);
}

std::wstring AppDataInstallDir()
{
	wchar_t* appData = nullptr;
	size_t length = 0;
	if (_wdupenv_s(&appData, &length, L"APPDATA") != 0 || appData == nullptr) {
		return std::wstring();
	}
	std::wstring result(appData);
	free(appData);
	if (result.empty()) {
		return result;
	}
	return result + L"\\RA3BattleNet";
}

std::string ToUtf8(const std::wstring& wide)
{
	if (wide.empty()) {
		return std::string();
	}
	const int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.length()),
	                                     nullptr, 0, nullptr, nullptr);
	if (size <= 0) {
		return std::string();
	}
	std::string result(size, '\0');
	WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.length()),
	                    result.data(), size, nullptr, nullptr);
	return result;
}

// Narrow a path for logging only.
std::string LogPath(const std::wstring& path)
{
	return ToUtf8(path);
}

}  // namespace

std::wstring RA3BNDelegate::ResolveClientDll()
{
	const auto& config = Config::GetInstance();

	// 1. Explicit override always wins.
	if (!config.ra3bnClientDll.empty()) {
		const std::wstring configured = ExpandEnv(toWString(config.ra3bnClientDll));
		if (FileExists(configured)) {
			return configured;
		}
		BOOST_LOG_TRIVIAL(error) << "ra3bn.clientDll is set but no file exists at: "
		                         << LogPath(configured);
		return std::wstring();
	}

	// 2. Where their installer recorded itself.
	// 3. Their default install location.
	std::vector<std::wstring> attempted;
	for (const std::wstring& installDir : { ReadClientInstallDirFromRegistry(), AppDataInstallDir() }) {
		if (installDir.empty()) {
			continue;
		}
		const std::wstring candidate = installDir + L"\\" + CLIENT_DLL_RELATIVE;
		if (FileExists(candidate)) {
			return candidate;
		}
		attempted.push_back(candidate);
	}

	// Autodetection needs their installer to have run. Under Wine it usually has not.
	if (attempted.empty()) {
		BOOST_LOG_TRIVIAL(error) << "Could not autodetect the RA3 Battle.net client: their "
		                            "installer left no registry entry and %APPDATA% is unset.";
	}
	else {
		for (const std::wstring& candidate : attempted) {
			BOOST_LOG_TRIVIAL(error) << "  no RA3BN client at: " << LogPath(candidate);
		}
	}
	BOOST_LOG_TRIVIAL(error) << "Set ra3bn.clientDll to the full path of NativeDll.dll, "
	                            "e.g. \"Z:\\\\home\\\\you\\\\RA3BattleNet\\\\contents\\\\NativeDll.dll\"";

	return std::wstring();
}

std::wstring RA3BNDelegate::ResolveLogFolder(const std::wstring& clientDllPath)
{
	const auto& config = Config::GetInstance();
	if (!config.ra3bnLogFolder.empty()) {
		return toWString(config.ra3bnLogFolder);
	}

	// clientDllPath is <install>\contents\NativeDll.dll; their client logs to <install>\logs.
	const std::wstring installDir = ParentDirectory(ParentDirectory(clientDllPath));
	if (!installDir.empty()) {
		return installDir + L"\\logs";
	}
	return std::wstring();
}

bool RA3BNDelegate::IsSupportedGame()
{
	const auto& info = GameVersion::GetInstance().GetInfo();

	// RA3BN only supports RA3 1.12; its address table fail-fasts on anything else,
	// which would terminate the game.
	if (_wcsnicmp(info.executableName.c_str(), L"ra3_", 4) != 0) {
		BOOST_LOG_TRIVIAL(error) << "RA3BN delegation is Red Alert 3 only; this is not RA3.";
		return false;
	}

	if (info.major != 1 || info.minor != 12) {
		BOOST_LOG_TRIVIAL(error) << "RA3BN delegation requires Red Alert 3 1.12, found "
		                         << info.major << "." << info.minor
		                         << ". Their client does not support this build and would "
		                            "terminate the game; not loading it.";
		return false;
	}

	return true;
}

bool RA3BNDelegate::WaitForGameWindow(DWORD timeoutMs)
{
	const DWORD ourPid = GetCurrentProcessId();
	const DWORD deadline = GetTickCount() + timeoutMs;

	for (;;) {
		for (const wchar_t* className : { RA3_WINDOW_CLASS, RA3_WINDOW_CLASS_MODDED }) {
			// Only ours counts, and FindWindowW returns just the first match, which
			// may belong to another RA3 instance. Walk every window of this class.
			HWND window = nullptr;
			while ((window = FindWindowExW(nullptr, window, className, nullptr)) != nullptr) {
				DWORD windowPid = 0;
				GetWindowThreadProcessId(window, &windowPid);
				if (windowPid == ourPid) {
					return true;
				}
			}
		}

		if (static_cast<LONG>(GetTickCount() - deadline) >= 0) {
			return false;
		}
		Sleep(250);
	}
}

void RA3BNDelegate::Worker()
{
	BOOST_LOG_NAMED_SCOPE("RA3BNDelegate")

	const auto& config = Config::GetInstance();

	const std::wstring clientDll = ResolveClientDll();
	if (clientDll.empty()) {
		BOOST_LOG_TRIVIAL(error) << "RA3 Battle.net client not found. Install it, or set "
		                            "ra3bn.clientDll to the full path of its NativeDll.dll.";
		return;
	}
	BOOST_LOG_TRIVIAL(info) << "Found RA3 Battle.net client: " << LogPath(clientDll);

	const DWORD timeoutMs = static_cast<DWORD>(config.ra3bnWaitSeconds) * 1000;
	BOOST_LOG_TRIVIAL(info) << "Waiting for the game window before handing over (up to "
	                        << config.ra3bnWaitSeconds << "s)...";
	if (!WaitForGameWindow(timeoutMs)) {
		BOOST_LOG_TRIVIAL(error) << "Game window did not appear within "
		                         << config.ra3bnWaitSeconds << "s; not loading the RA3BN client. "
		                            "Raise ra3bn.waitSeconds if the game is slow to start.";
		return;
	}

	// Load in place: their asset loader resolves game content relative to this path.
	const HMODULE module = LoadLibraryW(clientDll.c_str());
	if (module == nullptr) {
		BOOST_LOG_TRIVIAL(error) << "LoadLibrary failed for " << LogPath(clientDll)
		                         << " (error " << GetLastError() << ")";
		return;
	}

	const auto entryPointCdecl =
		reinterpret_cast<NativeInvokeCdecl>(GetProcAddress(module, "native_invoke_entry_point"));
	const auto entryPointStdcall = entryPointCdecl != nullptr ? nullptr :
		reinterpret_cast<NativeInvokeStdcall>(GetProcAddress(module, "_NativeInjectionEntryPoint@4"));

	if (entryPointCdecl == nullptr && entryPointStdcall == nullptr) {
		BOOST_LOG_TRIVIAL(error) << "Neither native_invoke_entry_point nor "
		                            "_NativeInjectionEntryPoint@4 found in "
		                         << LogPath(clientDll) << " (error " << GetLastError()
		                         << "). Their client may have changed its exports.";
		return;
	}

	const std::string logFolder = ToUtf8(ResolveLogFolder(clientDll));

	// Their entry point accepts nullptr; "" would make it create a directory named "".
	RemoteEntryInfo info = {};
	info.host_pid = GetCurrentProcessId();
	info.user_data = logFolder.empty() ? nullptr : logFolder.c_str();
	info.user_data_size = static_cast<std::uint32_t>(logFolder.length());

	if (logFolder.empty()) {
		BOOST_LOG_TRIVIAL(warning) << "Could not resolve a log folder for the RA3 Battle.net "
		                              "client; it will run without writing its own log.";
	}

	BOOST_LOG_TRIVIAL(info) << "Handing over to the RA3 Battle.net client (logs: "
	                        << (logFolder.empty() ? "<none>" : logFolder) << ")";

	// Their entry point runs the whole RA3BN stack: hostname patching, FESL,
	// relay, master proxy, query master and local HTTP server. It guards against
	// repeat invocation itself.
	if (entryPointCdecl != nullptr) {
		entryPointCdecl(&info);
	}
	else {
		entryPointStdcall(&info);
	}

	BOOST_LOG_TRIVIAL(info) << "RA3 Battle.net client invoked. Connectivity is now theirs; "
	                           "our hostname config and FESL patches are inactive.";
}

bool RA3BNDelegate::Start()
{
	if (!IsSupportedGame()) {
		return false;
	}

	// Cheap pre-flight so a missing client is reported now rather than after the
	// window wait.
	if (ResolveClientDll().empty()) {
		BOOST_LOG_TRIVIAL(error) << "RA3 Battle.net client not found; delegation disabled. "
		                            "Install their client, or set ra3bn.clientDll.";
		return false;
	}

	std::thread(&RA3BNDelegate::Worker).detach();
	return true;
}
