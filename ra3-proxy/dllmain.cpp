/*
Copyright (c) Anthony Beaumont
Modifications by sokie
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

#include "dllmain.h"
#include "memory.h"
#include "util.h"
#include "Config.hpp"
#include "PeerchatCipher.hpp"
#include "EncTypeXCipher.hpp"

#include "GameVersion.h"
#include "patch/RA3/PatchSSL.hpp"
#include "patch/RA3/ProxySSL.h"

#include <map>
#include <mutex>
#include <sstream>
#include <regex>

namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

// Peerchat state tracking
std::map<SOCKET, PeerchatState> peerchatStates;
std::mutex peerchatMutex;

// Master server state tracking
std::map<SOCKET, MasterServerState> masterStates;
std::mutex masterMutex;

// Proxy thread (kept for proper cleanup)
std::thread proxyThread;

connect_t pConnect = nullptr;
send_t pSend = nullptr;
recv_t pRecv = nullptr;

gethostbyname_t pGetHostByName = nullptr;
ShellExecuteW_t pShellExecuteW = nullptr;

#define PORT_PEERCHAT 6667
#define PORT_PEERCHAT_ALT 16667
#define PORT_MASTER_SERVER 28910

HINSTANCE WINAPI detourShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd) {
    BOOST_LOG_TRIVIAL(debug) << "ShellExecuteW()";

    if (lpOperation && wcscmp(lpOperation, L"open") == 0) {
        const auto& config = Config::GetInstance();
        std::wstring file(lpFile);
        if (file == L"IEXPLORE.EXE") {                                                                  //Kane's Wrath
            std::wstring param(lpParameters);
            if (param == L"http://www.ea.com/global/legal/tos.jsp") {
                file = toWString(config.getHostname("tos"));
            }
            else if (param == L"http://www.commandandconquer.com") {
                file = toWString(config.getHostname("website"));
            }
        }
        else if (file == L"http://profile.ea.com/" ||                                                   //RA3
            (file.size() >= 8 && _wcsicmp(file.c_str() + file.size() - 8, L"EREG.EXE") == 0)) {     //Kane's Wrath
            file = toWString(config.getHostname("register"));
        }
        else if (file.find(L"http://www.ea.com/redalert/") == 0) {                                     //RA3
            file = toWString(config.getHostname("website"));
        }

        return pShellExecuteW(hwnd, lpOperation, file.c_str(), NULL, lpDirectory, nShowCmd);
    }

    return pShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

std::atomic<bool> useAltPeerChatPort(false);
int WSAAPI detourConnect(SOCKET s, const sockaddr* name, int namelen) {
    sockaddr_in* addr_in = (sockaddr_in*)name;

    BOOST_LOG_TRIVIAL(debug) << "Connect(): " << addr_in->sin_family << " port: " << addr_in->sin_port;


    if (addr_in->sin_family == AF_INET) { //IPv4
        int port = ntohs(addr_in->sin_port);
        if (port == PORT_PEERCHAT) {
            if (useAltPeerChatPort) {
                BOOST_LOG_TRIVIAL(info) << "Using alt peer chat port";
                addr_in->sin_port = htons(PORT_PEERCHAT_ALT);
            }
            else {
                int result = pConnect(s, name, namelen);
                if (result == SOCKET_ERROR) {
                    BOOST_LOG_TRIVIAL(info) << "Switching to alt peer chat port";
                    useAltPeerChatPort = true;
                    addr_in->sin_port = htons(PORT_PEERCHAT_ALT);
                    result = pConnect(s, name, namelen);
                }
                return result;
            }
        }
    }

    return pConnect(s, name, namelen);
}

void getSocketInfo(SOCKET sock) {
    sockaddr_in localAddr;
    sockaddr_in remoteAddr;
    int addrSize = sizeof(sockaddr_in);

    // Get local address (your end of the socket)
    if (getsockname(sock, (sockaddr*)&localAddr, &addrSize) == 0) {
        char localIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(localAddr.sin_addr), localIP, INET_ADDRSTRLEN);

        BOOST_LOG_TRIVIAL(debug) << "Local IP: " << localIP;
        BOOST_LOG_TRIVIAL(debug) << "Local Port: " << ntohs(localAddr.sin_port);
    }
    else {
        BOOST_LOG_TRIVIAL(debug) << "Failed to get local socket info. Error: " << WSAGetLastError();
    }

    // Get remote address (the other end of the socket)
    if (getpeername(sock, (sockaddr*)&remoteAddr, &addrSize) == 0) {
        char remoteIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(remoteAddr.sin_addr), remoteIP, INET_ADDRSTRLEN);

        BOOST_LOG_TRIVIAL(debug) << "Remote IP: " << remoteIP;
        BOOST_LOG_TRIVIAL(debug) << "Remote Port: " << ntohs(remoteAddr.sin_port);
    }
    else {
        BOOST_LOG_TRIVIAL(debug) << "Failed to get remote socket info. Error: " << WSAGetLastError();
    }
}

u_short get_local_port(SOCKET sock) {
    sockaddr_in localAddr;
    int addrSize = sizeof(sockaddr_in);

    // Get local address (your end of the socket)
    if (getsockname(sock, (sockaddr*)&localAddr, &addrSize) == 0) {
        char localIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(localAddr.sin_addr), localIP, INET_ADDRSTRLEN);
        return ntohs(localAddr.sin_port);
    }
    else {
        BOOST_LOG_TRIVIAL(debug) << "Failed to get local socket info. Error: " << WSAGetLastError();
    }
    return -1;
}

u_short get_remote_port(SOCKET sock) {
    sockaddr_in remoteAddr;
    int addrSize = sizeof(sockaddr_in);

    // Get remote address (the other end of the socket)
    if (getpeername(sock, (sockaddr*)&remoteAddr, &addrSize) == 0) {
        char remoteIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(remoteAddr.sin_addr), remoteIP, INET_ADDRSTRLEN);
        return ntohs(remoteAddr.sin_port);
    }
    else {
        BOOST_LOG_TRIVIAL(debug) << "Failed to get remote socket info. Error: " << WSAGetLastError();
    }
    return -1;
}

// Check if this is a peerchat port
bool isPeerchatPort(u_short port) {
    return port == PORT_PEERCHAT || port == PORT_PEERCHAT_ALT;
}

// Get or create peerchat state for a socket
PeerchatState& getPeerchatState(SOCKET sock) {
    std::lock_guard<std::mutex> lock(peerchatMutex);
    return peerchatStates[sock];
}

// Check if socket has peerchat state
bool hasPeerchatState(SOCKET sock) {
    std::lock_guard<std::mutex> lock(peerchatMutex);
    return peerchatStates.find(sock) != peerchatStates.end();
}

// Remove peerchat state for socket
void removePeerchatState(SOCKET sock) {
    std::lock_guard<std::mutex> lock(peerchatMutex);
    peerchatStates.erase(sock);
}

// Parse 705 response to extract challenges
// Format: :s 705 <nick> <client_challenge> <server_challenge>
bool parse705Response(const std::string& data, std::string& clientChallenge, std::string& serverChallenge) {
    // Look for "705 " in the response
    size_t pos705 = data.find(" 705 ");
    if (pos705 == std::string::npos) {
        return false;
    }

    // Find the parameters after 705
    // Format: 705 <nick> <challenge1> <challenge2>
    size_t paramStart = pos705 + 5; // Skip " 705 "

    // Skip the nickname (first parameter)
    size_t firstSpace = data.find(' ', paramStart);
    if (firstSpace == std::string::npos) return false;

    // Find the two challenges
    size_t secondSpace = data.find(' ', firstSpace + 1);
    if (secondSpace == std::string::npos) return false;

    // Find end of second challenge (newline or end of string)
    size_t endPos = data.find_first_of("\r\n", secondSpace + 1);
    if (endPos == std::string::npos) {
        endPos = data.length();
    }

    clientChallenge = data.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    serverChallenge = data.substr(secondSpace + 1, endPos - secondSpace - 1);

    // Validate challenge lengths (should be 16 chars typically)
    if (clientChallenge.length() < 8 || serverChallenge.length() < 8) {
        return false;
    }

    return true;
}

// Check if this is a master server port
bool isMasterServerPort(u_short port) {
    return port == PORT_MASTER_SERVER;
}

// Get or create master server state for a socket
MasterServerState& getMasterState(SOCKET sock) {
    std::lock_guard<std::mutex> lock(masterMutex);
    return masterStates[sock];
}

// Remove master server state for socket
void removeMasterState(SOCKET sock) {
    std::lock_guard<std::mutex> lock(masterMutex);
    masterStates.erase(sock);
}

// Parse validate string from master server client request
// Format: data starts at offset 9, split by null bytes, take 3rd field, first 8 chars
bool parseMasterValidate(const char* data, size_t len, std::string& validate) {
    if (len <= 9) return false;

    // Start at offset 9
    const char* start = data + 9;
    size_t remaining = len - 9;

    // Find null-separated fields
    int fieldCount = 0;
    const char* fieldStart = start;

    for (size_t i = 0; i < remaining; i++) {
        if (start[i] == '\0') {
            fieldCount++;
            if (fieldCount == 2) {
                // Next field (index 2) starts here
                fieldStart = start + i + 1;
            } else if (fieldCount == 3) {
                // End of field 2
                size_t fieldLen = (start + i) - fieldStart;
                if (fieldLen >= 8) {
                    validate = std::string(fieldStart, 8);
                    return true;
                }
                return false;
            }
        }
    }

    return false;
}

int WSAAPI detourSend(SOCKET s, const char* buf, int len, int flags) {

    BOOST_LOG_NAMED_SCOPE("detourSend");

    std::string str(buf, len);
    u_short remotePort = get_remote_port(s);

    const auto& sendConfig = Config::GetInstance();
    bool isProxyTraffic = (remotePort == ProxySSL::PROXY_PORT || get_local_port(s) == ProxySSL::PROXY_PORT);

    // Handle peerchat traffic (only if decryption logging is enabled)
    if (sendConfig.logDecryption && isPeerchatPort(remotePort)) {
        std::lock_guard<std::mutex> lock(peerchatMutex);
        auto& state = peerchatStates[s];
        state.socket = s;

        if (state.encryptionEnabled) {
            // Decrypt for logging
            std::string decrypted = state.sendCipher.cryptToString(buf, len);
            BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT SEND] " << decrypted;
        } else {
            // Plaintext - check for CRYPT command
            BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT SEND] " << str;

            if (str.find("CRYPT ") != std::string::npos) {
                state.cryptRequested = true;
                BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT] CRYPT command detected, waiting for 705 response";
            }
        }
    }
    // Handle master server traffic (only if decryption logging is enabled)
    else if (sendConfig.logDecryption && isMasterServerPort(remotePort)) {
        std::lock_guard<std::mutex> lock(masterMutex);
        auto& state = masterStates[s];
        state.socket = s;

        // Log the request
        BOOST_LOG_TRIVIAL(debug) << "[MASTER SEND] " << str;

        // Try to capture validate string for decrypting server response
        if (!state.cipherReady) {
            std::string validate;
            if (parseMasterValidate(buf, len, validate)) {
                state.validate = validate;
                state.decoder.init(sendConfig.gameKey, validate);
                state.cipherReady = true;
                BOOST_LOG_TRIVIAL(debug) << "[MASTER] Captured validate: " << validate;
            }
        }
    } else if (!isProxyTraffic) {
        getSocketInfo(s);
        BOOST_LOG_TRIVIAL(debug) << "detourSend(): " << str;
    }

    if (str.find("GET ") == 0 || str.find("HEAD ") == 0) {
        const auto& config = Config::GetInstance();
        std::string updatedStr = str;
        std::string targetHost = "Host: na.llnet.eadownloads.ea.com";
        std::string newHost = "Host: " + config.getHostname("host");

        size_t pos = updatedStr.find(targetHost);
        if (pos != std::string::npos) {
            updatedStr.replace(pos, targetHost.length(), newHost);
        }

        char* updatedBuf = new char[updatedStr.length() + 1];
        strcpy_s(updatedBuf, updatedStr.length() + 1, updatedStr.c_str());

        int result = pSend(s, updatedBuf, static_cast<int>(updatedStr.length()), flags);

        delete[] updatedBuf;

        return result;
    }

    return pSend(s, buf, len, flags);
}

int WSAAPI detourRecv(SOCKET s, char* buf, int len, int flags) {
    // CRITICAL: Call the original recv and IMMEDIATELY capture the error code
    // before any other WinSock calls can overwrite it
    int bytes_recv = pRecv(s, buf, len, flags);
    int lastError = WSAGetLastError();  // Capture IMMEDIATELY after recv!

    // Scope guard to restore error code AFTER all other destructors run
    // Declared FIRST so its destructor runs LAST (reverse order)
    struct ErrorRestorer {
        int error;
        ~ErrorRestorer() { WSASetLastError(error); }
    } restorer{ lastError };

    // Now safe to use BOOST_LOG_NAMED_SCOPE - its destructor will run
    // BEFORE our ErrorRestorer destructor
    BOOST_LOG_NAMED_SCOPE("detourRecv");

    // For non-blocking sockets, WSAEWOULDBLOCK is normal - just pass through quickly
    if (bytes_recv == SOCKET_ERROR && lastError == WSAEWOULDBLOCK) {
        return bytes_recv;  // ErrorRestorer destructor will restore the error
    }

    // Only do logging for non-proxy traffic and only on success
    // Skip expensive operations for the hot path
    if (bytes_recv > 0) {
        // Quick port check without full socket info lookup
        sockaddr_in remoteAddr;
        int addrSize = sizeof(sockaddr_in);
        const auto& recvConfig = Config::GetInstance();
        if (getpeername(s, (sockaddr*)&remoteAddr, &addrSize) == 0) {
            u_short remotePort = ntohs(remoteAddr.sin_port);

            // Handle peerchat traffic (only if decryption logging is enabled)
            if (recvConfig.logDecryption && isPeerchatPort(remotePort)) {
                std::lock_guard<std::mutex> lock(peerchatMutex);
                auto& state = peerchatStates[s];
                state.socket = s;

                if (state.encryptionEnabled) {
                    // Decrypt for logging
                    std::string decrypted = state.recvCipher.cryptToString(buf, bytes_recv);
                    BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT RECV] " << decrypted;
                } else {
                    // Plaintext - check for 705 response
                    std::string data(buf, bytes_recv);
                    BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT RECV] " << data;

                    if (state.cryptRequested) {
                        std::string clientChallenge, serverChallenge;
                        if (parse705Response(data, clientChallenge, serverChallenge)) {
                            // Strip IRC trailing parameter prefix if present
                            if (!serverChallenge.empty() && serverChallenge[0] == ':') {
                                serverChallenge = serverChallenge.substr(1);
                            }
                            // Initialize ciphers with game key from config
                            // Client uses first challenge for sending (server's recv cipher)
                            // Client uses second challenge for receiving (server's send cipher)
                            const std::string& gameKey = recvConfig.gameKey;
                            state.sendCipher.init(clientChallenge, gameKey);
                            state.recvCipher.init(serverChallenge, gameKey);
                            state.encryptionEnabled = true;

                            BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT] Encryption enabled!";
                            BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT] Send challenge: " << clientChallenge;
                            BOOST_LOG_TRIVIAL(debug) << "[PEERCHAT] Recv challenge: " << serverChallenge;
                        }
                    }
                }
            }
            // Handle master server traffic (only if decryption logging is enabled)
            else if (recvConfig.logDecryption && isMasterServerPort(remotePort)) {
                std::lock_guard<std::mutex> lock(masterMutex);
                auto& state = masterStates[s];
                state.socket = s;

                if (state.cipherReady) {
                    // Decrypt server response
                    std::string decrypted = state.decoder.decode(buf, bytes_recv);
                    BOOST_LOG_TRIVIAL(debug) << "[MASTER RECV] " << decrypted;
                    print_hex(decrypted.c_str(), decrypted.size());
                } else {
                    // No validate captured yet, log raw
                    BOOST_LOG_TRIVIAL(debug) << "[MASTER RECV] (encrypted, no validate) " << bytes_recv << " bytes";
                }
            } else if (remotePort != ProxySSL::PROXY_PORT) {
                // Skip logging for proxy traffic
                BOOST_LOG_TRIVIAL(debug) << "detourRecv(): " << bytes_recv
                    << " bytes from port " << remotePort;
                // Optionally log hex dump for debugging (uncomment if needed)
                print_hex(buf, bytes_recv);
            }
        }
    }
    else if (bytes_recv == 0) {
        BOOST_LOG_TRIVIAL(debug) << "detourRecv(): Connection closed on socket " << s;
        // Clean up master server state on connection close
        removeMasterState(s);
        // Clean up peerchat state on connection close
        removePeerchatState(s);
    }
    else {
        // Only log actual errors, not WSAEWOULDBLOCK (handled above)
        BOOST_LOG_TRIVIAL(error) << "detourRecv(): Failed on socket " << s
            << " error: " << lastError;
    }

    return bytes_recv;  // ErrorRestorer destructor will restore the error
}

struct hostent* WSAAPI detourGetHostByName(const char* name) {
    const auto& config = Config::GetInstance();
    std::string host(name);
    BOOST_LOG_TRIVIAL(info) << "Requested GetHostByName(): " << host.c_str();

    if (host == "servserv.generals.ea.com" ||
        host == "na.llnet.eadownloads.ea.com")
    {
        host = config.getHostname("host");
    }
    else if (host == "bfme.fesl.ea.com" ||
        host == "bfme2.fesl.ea.com" ||
        host == "bfme2-ep1-pc.fesl.ea.com" ||
        host == "cnc3-pc.fesl.ea.com" ||
        host == "cnc3-ep1-pc.fesl.ea.com" ||
        host == "cncra3-pc.fesl.ea.com")
    {
        // When proxy is enabled, redirect to localhost so the local proxy can intercept
        // Otherwise, connect directly to the login server
        host = config.proxy_enable ? "localhost" : config.getHostname("login");
    }
    else if (host == "gpcm.gamespy.com")
    {
        host = config.getHostname("gpcm");
    }
    else if (host == "peerchat.gamespy.com")
    {
        host = config.getHostname("peerchat");
    }
    else if (host == "lotrbme.available.gamespy.com" ||
        host == "lotrbme.master.gamespy.com" ||
        host == "lotrbme.ms13.gamespy.com" ||
        host == "lotrbme2r.available.gamespy.com" ||
        host == "lotrbme2r.master.gamespy.com" ||
        host == "lotrbme2r.ms9.gamespy.com" ||
        host == "ccgenerals.ms19.gamespy.com" ||
        host == "ccgenzh.ms6.gamespy.com" ||
        host == "cc3tibwars.available.gamespy.com" ||
        host == "cc3tibwars.master.gamespy.com" ||
        host == "cc3tibwars.ms17.gamespy.com" ||
        host == "cc3xp1.available.gamespy.com" ||
        host == "cc3xp1.master.gamespy.com" ||
        host == "cc3xp1.ms18.gamespy.com" ||
        host == "redalert3pc.available.gamespy.com" ||
        host == "redalert3pc.master.gamespy.com" ||
        host == "redalert3pc.ms1.gamespy.com" ||
        host == "master.gamespy.com")
    {
        host = config.getHostname("master");
    }
    else if (host == "redalert3pc.natneg1.gamespy.com" ||
        host == "redalert3pc.natneg2.gamespy.com" ||
        host == "redalert3pc.natneg3.gamespy.com")
    {
        host = config.getHostname("natneg");
    }
    else if (host == "lotrbme.gamestats.gamespy.com" ||
        host == "lotrbme2r.gamestats.gamespy.com" ||
        host == "gamestats.gamespy.com")
    {
        host = config.getHostname("stats");
    }
    else if (host == "cc3tibwars.auth.pubsvs.gamespy.com" ||
        host == "cc3tibwars.comp.pubsvs.gamespy.com" ||
        host == "cc3tibwars.sake.gamespy.com" ||
        host == "cc3xp1.auth.pubsvs.gamespy.com" ||
        host == "cc3xp1.comp.pubsvs.gamespy.com" ||
        host == "cc3xp1.sake.gamespy.com" ||
        host == "redalert3pc.auth.pubsvs.gamespy.com" ||
        host == "redalert3pc.sake.gamespy.com" ||
        host == "redalert3services.gamespy.com" ||
        host == "psweb.gamespy.com")
    {
        host = config.getHostname("sake");
    }
    else if (host == "lotrbfme.arenasdk.gamespy.com" ||
        host == "arenasdk.gamespy.com" ||
        host == "launch.gamespyarcade.com" ||
        host == "www.gamespy.com" ||
        host == "ingamead.gamespy.com")
    {
        host = config.getHostname("server");
    }



    BOOST_LOG_TRIVIAL(info) << "Patched GetHostByName(): " << host.c_str();

    return pGetHostByName(host.c_str());
}

bool takeDetour(PVOID* ppPointer, PVOID pDetour) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(ppPointer, pDetour);
    return DetourTransactionCommit() == NO_ERROR;
}

bool setDetoursForSocket() {
    HMODULE hMod = LoadLibraryA("ws2_32.dll");
    if (hMod == nullptr) return false;

    pSend = (send_t)GetProcAddress(hMod, "send");
    if (pSend == nullptr) return false;
    if (!takeDetour(&(PVOID&)pSend, detourSend)) return false;

    pRecv = (recv_t)GetProcAddress(hMod, "recv");
    if (pRecv == nullptr) return false;
    if (!takeDetour(&(PVOID&)pRecv, detourRecv)) return false;

    pConnect = (connect_t)GetProcAddress(hMod, "connect");
    if (pConnect == nullptr) return false;
    if (!takeDetour(&(PVOID&)pConnect, detourConnect)) return false;

    pGetHostByName = (gethostbyname_t)GetProcAddress(hMod, "gethostbyname");
    if (pGetHostByName == nullptr) return false;
    if (!takeDetour(&(PVOID&)pGetHostByName, detourGetHostByName)) return false;

    return true;
}

bool setDetoursForShell() {
    HMODULE hMod = LoadLibraryA("shell32.dll");
    if (hMod == nullptr) return false;

    pShellExecuteW = (ShellExecuteW_t)GetProcAddress(hMod, "ShellExecuteW");
    if (pShellExecuteW == nullptr) return false;
    if (!takeDetour(&(PVOID&)pShellExecuteW, detourShellExecuteW)) return false;

    return true;
}

void InitLogging()
{
    using namespace std;
    namespace logging = boost::log;
    namespace expr = logging::expressions;

    const auto config = &Config::GetInstance();

    // Get the configuration settings for logging
    const bool enableConsole = config->showConsole;
    const bool enableLogFile = config->createLog;
    const int consoleLogLevel = config->consoleLogLevel;
    const int fileLogLevel = config->fileLogLevel;

    // Add common attributes for logging
    logging::add_common_attributes();
    logging::core::get()->add_global_attribute("Scope", boost::log::attributes::named_scope());

    // Define the format for the log messages
    const auto logFormat = expr::format("[%1% %2%] %3%: %4%")
        % expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S")
        % expr::format_named_scope("Scope", logging::keywords::format = "%C")
        % logging::trivial::severity
        % expr::smessage;

    if (enableConsole)
    {
        // Create a console for Debug output
        AllocConsole();

        // Redirect standard error, output to console
        // std::cout, std::clog, std::cerr, std::cin
        FILE* fDummy;

        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
        freopen_s(&fDummy, "CONIN$", "r", stdin);

        cout.clear();
        clog.clear();
        cerr.clear();
        cin.clear();

        // Redirect wide standard error, output to console
        // std::wcout, std::wclog, std::wcerr, std::wcin
        const HANDLE hConOut = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        const HANDLE hConIn = CreateFile(_T("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
        SetStdHandle(STD_ERROR_HANDLE, hConOut);
        SetStdHandle(STD_INPUT_HANDLE, hConIn);

        wcout.clear();
        wclog.clear();
        wcerr.clear();
        wcin.clear();

        boost::shared_ptr<sinks::text_ostream_backend> console_backend =
            boost::make_shared<sinks::text_ostream_backend>();
        console_backend->add_stream(boost::shared_ptr<std::ostream>(&std::cout, boost::null_deleter())); // Use std::clog or std::cout
        console_backend->auto_flush(true); // Auto-flush for immediate output

        // Create a frontend (synchronous for simplicity)
        typedef sinks::synchronous_sink<sinks::text_ostream_backend> console_sink_t;
        boost::shared_ptr<console_sink_t> console_sink = boost::make_shared<console_sink_t>(console_backend);

        // Set the filter and format for the console log
        console_sink->set_filter(logging::trivial::severity >= consoleLogLevel);
        console_sink->set_formatter(logFormat);

        // Add the console sink to the core
        logging::core::get()->add_sink(console_sink);
    }

    if (enableLogFile)
    {
        const boost::posix_time::ptime timeLocal = boost::posix_time::second_clock::local_time();
        const auto facet = new boost::posix_time::time_facet("%Y-%m-%d_%H-%M-%S");


        std::ostringstream is;
        is.imbue(std::locale(is.getloc(), facet));
        is << timeLocal;

        boost::shared_ptr<sinks::text_file_backend> file_backend =
            boost::make_shared<sinks::text_file_backend>(
                keywords::file_name = (boost::format("ra3_%1%.log") % is.str()).str(),
                keywords::rotation_size = 10 * 1024 * 1024, // Rotate when file reaches 10 MB
                keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0) // Rotate daily at midnight
            );
        file_backend->auto_flush(true); // Auto-flush for immediate output to file

        // Create a frontend for the file sink
        typedef sinks::synchronous_sink<sinks::text_file_backend> file_sink_t;
        boost::shared_ptr<file_sink_t> file_sink = boost::make_shared<file_sink_t>(file_backend);

        file_sink->set_filter(logging::trivial::severity >= fileLogLevel);
        file_sink->set_formatter(logFormat);

        logging::core::get()->add_sink(file_sink);
    }
}

void InitProxy()
{
    ProxySSL::GetInstance().run();
}

DWORD WINAPI Main(LPVOID lpReserved) {

    InitLogging();
    BOOST_LOG_NAMED_SCOPE("main");

    const auto config = &Config::GetInstance();

    BOOST_LOG_TRIVIAL(info) << "pid: " << GetCurrentProcessId();

    if (setDetoursForSocket() &&
        setDetoursForShell()) {
        BOOST_LOG_TRIVIAL(info) << "Detour function set.";
    }
    else {
        BOOST_LOG_TRIVIAL(error) << "Failed to set detour function.";
    }

    // Identify game version
    GameVersion::GetInstance();

    if (config->patchSSL) {
        const PatchSSL* sslPatch = &PatchSSL::GetInstance();

        if (!sslPatch->Patch()) {
            BOOST_LOG_TRIVIAL(error) << "Failed to patch SSL.";
        }
    }

    if (config->proxy_enable) {
        proxyThread = std::thread(&InitProxy);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {

        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(nullptr, 0, &Main, hModule, 0, nullptr);
        if (hThread) {
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_PROCESS_DETACH: {
        // Stop the proxy server and wait for its thread to finish
        ProxySSL::GetInstance().stop();
        if (proxyThread.joinable()) {
            proxyThread.join();
        }

        break;
    }
    }
    return TRUE;
}