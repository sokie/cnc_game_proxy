/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.

Based on https://github.com/lanyizi/BegoneCrashers
All credits to lanyizi
*/

#include "GameVersion.h"
#include <boost/log/trivial.hpp>

const GameVersion::GameVersionMap GameVersion::VERSIONS = {
    {"1.12", {
        { GameRelease::DIGITAL, 0xC6262C },
        { GameRelease::RETAIL, 0xC5B6C4 }
    }},
    {"1.13", {
        { GameRelease::DIGITAL, 0xC64DBC }
    }}
};

GameVersion& GameVersion::GetInstance() {
    static GameVersion instance;
    return instance;
}

GameVersion::GameVersion() {
    Identify();
}

void GameVersion::Identify() {
    HANDLE hProcess = GetCurrentProcess();
    TCHAR buffer[MAX_PATH] = { 0 };

    if (GetModuleFileNameExW(hProcess, NULL, buffer, sizeof(buffer) / sizeof(TCHAR))) {
        info_.executableName = GetFileName(buffer);

        if (GetFileVersion(buffer, info_.major, info_.minor)) {
            if (info_.executableName == L"ra3_1.12.game" && info_.major == 1 && info_.minor == 12) {
                info_.release = GetReleaseVersion("1.12");
                identified_ = true;

                switch (info_.release) {
                    case GameRelease::DIGITAL:
                        BOOST_LOG_TRIVIAL(info) << "Red Alert 3 (v1.12): Digital Release (EA/Origin, Steam).";
                        break;
                    case GameRelease::RETAIL:
                        BOOST_LOG_TRIVIAL(info) << "Red Alert 3 (v1.12): Retail Release (SecuROM DVD / Steam).";
                        break;
                    default:
                        BOOST_LOG_TRIVIAL(info) << "Red Alert 3 (v1.12): Unknown Release.";
                        break;
                }
            }
            else if (info_.executableName == L"ra3_1.13.game" && info_.major == 1 && info_.minor == 13) {
                info_.release = GetReleaseVersion("1.13");
                identified_ = true;

                switch (info_.release) {
                    case GameRelease::DIGITAL:
                        BOOST_LOG_TRIVIAL(info) << "Red Alert 3 (v1.13): Digital Release (EA/Origin, Steam).";
                        break;
                    default:
                        BOOST_LOG_TRIVIAL(info) << "Red Alert 3 (v1.13): Unknown Release.";
                        break;
                }
            }
            else if (info_.executableName == L"cnc3ep1.dat") {
                identified_ = true;
                BOOST_LOG_TRIVIAL(info) << "Command & Conquer 3: Kane's Wrath (v" << info_.major << "." << info_.minor << ")";
            }
            else if (info_.executableName == L"cnc3game.dat") {
                identified_ = true;
                BOOST_LOG_TRIVIAL(info) << "Command & Conquer 3: Tiberium Wars (v" << info_.major << "." << info_.minor << ")";
            }
        }
    }
    CloseHandle(hProcess);
}

bool GameVersion::GetFileVersion(TCHAR* szPath, int& major, int& minor) {
    DWORD verHandle = 0;
    DWORD verSize = GetFileVersionInfoSizeW(szPath, &verHandle);
    if (verSize == 0 || verHandle != 0) return false;

    LPBYTE verData = new BYTE[verSize];
    if (!GetFileVersionInfoW(szPath, 0, verSize, verData)) {
        delete[] verData;
        return false;
    }

    VS_FIXEDFILEINFO* verInfo = NULL;
    UINT size = 0;

    if (!VerQueryValueW(verData, L"\\", (LPVOID*)&verInfo, &size) || size == 0) {
        delete[] verData;
        return false;
    }

    major = HIWORD(verInfo->dwFileVersionMS);
    minor = LOWORD(verInfo->dwFileVersionMS);

    delete[] verData;
    return true;
}

std::wstring GameVersion::GetFileName(TCHAR* szPath) {
    std::wstring execPath = szPath;
    size_t lastSlash = execPath.find_last_of(L"\\");
    return lastSlash != std::wstring::npos ? execPath.substr(lastSlash + 1) : execPath;
}

GameRelease GameVersion::GetReleaseVersion(const std::string& version) {
    auto it = VERSIONS.find(version);
    if (it == VERSIONS.end()) {
        return GameRelease::UNKNOWN;
    }

    for (const auto& [release, address] : it->second) {
        const char* ptr = reinterpret_cast<const char*>(address);
        if (ptr && std::string(ptr, 8) == "RedAlert") {
            return release;
        }
    }
    return GameRelease::UNKNOWN;
}
