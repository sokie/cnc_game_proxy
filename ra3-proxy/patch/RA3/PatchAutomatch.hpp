// PatchAutomatch.hpp : Debug hooks for KW automatch staging room flow.
#pragma once
#include "../../Framework.h"
#include "PatchSSL.hpp" // For PatternByte, FindPattern, ParsePattern

class PatchAutomatch
{
public:
	PatchAutomatch();

	static PatchAutomatch& GetInstance()
	{
		static PatchAutomatch* instance;

		if (instance == nullptr)
			instance = new PatchAutomatch();

		return *instance;
	}

	BOOL Patch() const;

private:
	DWORD baseAddress_;
	DWORD size_;
	DWORD offset_;
	DWORD entryPoint_;
};
