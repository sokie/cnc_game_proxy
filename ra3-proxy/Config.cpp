// Config.cpp : Defines the configuration settings for the application.
#include "Framework.h"
#include "boost/property_tree/ini_parser.hpp"

Config::Config()
{
	ptree pt;

	try
	{
		//ini is preferred because you can add comments :D
		if (boost::filesystem::exists("config.ini")) {
			BOOST_LOG_TRIVIAL(info) << "Reading config from ini." << std::endl;
			read_ini("config.ini", pt);
		}
		else if (boost::filesystem::exists("config.json")) {
			BOOST_LOG_TRIVIAL(info) << "Reading config from json." << std::endl;
			read_json("config.json", pt);
		}
		else {
			BOOST_LOG_TRIVIAL(info) << "No config file found, using defaults." << std::endl;
		}
	}
	catch (boost::property_tree::json_parser_error& e)
	{
		auto temp = std::string(e.what());
		BOOST_LOG_TRIVIAL(error) << "Config Parse Error: " << temp << std::endl;
	}

	// Section - Debug
	showConsole = pt.get("debug.showConsole", true);
	createLog = pt.get("debug.createLog", true);
	logDecryption = pt.get("debug.logDecryption", false);
	consoleLogLevel = pt.get("debug.logLevelConsole", static_cast<int>(boost::log::trivial::info));
	fileLogLevel = pt.get("debug.logLevelFile", static_cast<int>(boost::log::trivial::debug));

	// Section - Patches
	patchSSL = pt.get("patches.SSL", true);
	patchAuthKey = pt.get("patches.AuthKey", true);
	patchLoginCert = pt.get("patches.LoginCert", true);

	// Section - Proxy
	proxy_enable = pt.get("proxy.enable", true);
	proxyDestinationPort = pt.get("proxy.destinationPort", 18840);
	proxySSL = pt.get("proxy.secure", false);

	// Game related settings
	gameKey = pt.get("game.gameKey", "");

	// Section - Hostnames
	const auto hostnamesNode = pt.get_child_optional("hostnames");
	if (hostnamesNode) {
		for (const auto& item : *hostnamesNode) {
			hostnames[item.first] = item.second.get_value<std::string>();
		}
		BOOST_LOG_TRIVIAL(info) << "Loaded " << hostnames.size() << " hostnames from config";
	}
	else {
		// Default hostnames (migrated from online.h)
		hostnames = {
			{"host", "http.server.cnc-online.net"},
			{"login", "login.server.cnc-online.net"},
			{"gpcm", "gpcm.server.cnc-online.net"},
			{"peerchat", "peerchat.server.cnc-online.net"},
			{"master", "master.server.cnc-online.net"},
			{"natneg", "natneg.server.cnc-online.net"},
			{"stats", "gamestats.server.cnc-online.net"},
			{"sake", "sake.server.cnc-online.net"},
			{"server", "server.cnc-online.net"},
			{"register", "https://cnc-online.net/en/connect/register/"},
			{"website", "https://cnc-online.net/en/"},
			{"tos", "https://cnc-online.net/en/faq/"}
		};
		BOOST_LOG_TRIVIAL(info) << "Using default hostnames";
	}
}

std::string Config::getHostname(const std::string& key) const {
	auto it = hostnames.find(key);
	if (it != hostnames.end()) {
		return it->second;
	}
	BOOST_LOG_TRIVIAL(warning) << "Hostname not found: " << key;
	return "";
}

std::string Config::getHostname(const std::string& key, const std::string& defaultValue) const {
	auto it = hostnames.find(key);
	return (it != hostnames.end()) ? it->second : defaultValue;
}
