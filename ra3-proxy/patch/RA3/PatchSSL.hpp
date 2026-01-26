// PatchSSL.hpp : Defines the PatchSSL class, which handles the patching of SSL certificate verification.
#pragma once
#include "../../Framework.h"

struct PatternByte {
	std::optional<std::byte> value; // std::byte for actual byte, std::nullopt for '??'
	bool is_wildcard;

	PatternByte(std::byte val) : value(val), is_wildcard(false) {}
	PatternByte() : value(std::nullopt), is_wildcard(true) {}
};


class PatchSSL
{
public:
	PatchSSL();

	static PatchSSL& GetInstance()
	{
		static PatchSSL* instance;

		if (instance == nullptr)
			instance = new PatchSSL();

		return *instance;
	}

	BOOL Patch() const;
	void DumpSSLCheckMemory() const;

private:
	DWORD size_;
	DWORD offset_;
	DWORD entryPoint_;
};
