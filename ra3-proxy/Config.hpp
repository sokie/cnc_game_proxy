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

	/* Proxy */
	bool proxy_enable;
	USHORT proxyListenPort;
	USHORT proxyDestinationPort;
	bool proxySSL;

	/* Gamekey */
	std::string gameKey;

	/* Hostnames */
	std::unordered_map<std::string, std::string> hostnames;

	// Helper methods for hostname access
	std::string getHostname(const std::string& key) const;
	std::string getHostname(const std::string& key, const std::string& defaultValue) const;

};
