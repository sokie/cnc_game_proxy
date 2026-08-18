// Config.hpp : Defines the configuration settings for the application.
#pragma once

#include <unordered_map>

using boost::property_tree::ptree;

class Config
{
public:
	Config();

	static Config& GetInstance()
	{
		static Config* instance;

		if (instance == nullptr)
			instance = new Config();

		return *instance;
	}

	/* Debug */
	bool showConsole;
	bool createLog;
	bool logDecryption;
	INT consoleLogLevel;
	INT fileLogLevel;

	/* Patches */
	bool patchSSL;
	bool patchAuthKey;

	/* RA3 Battle.net delegation: load the user's installed RA3BN NativeDll.dll
	   and let it drive connectivity, instead of our hostname redirection.
	   Red Alert 3 1.12 only. */
	bool ra3bnDelegate;
	std::string ra3bnClientDll;   // explicit path; empty = autodetect
	std::string ra3bnLogFolder;   // where their DLL writes its log; empty = their client's logs folder
	INT ra3bnWaitSeconds;         // how long to wait for the game window

	/* Proxy */
	bool proxy_enable;
	USHORT proxyListenPort;
	USHORT proxyDestinationPort;
	bool proxySSL;

	/* Gamekey */
	std::string gameKey;

	/* Port peerchat really listens on. 0 keeps the legacy behaviour of trying
	   6667 first and falling back to 16667. RA3BN only serves 16667. */
	USHORT peerchatPort;

	/* Hostnames */
	std::unordered_map<std::string, std::string> hostnames;

	// Helper methods for hostname access
	std::string getHostname(const std::string& key) const;
	std::string getHostname(const std::string& key, const std::string& defaultValue) const;

};
