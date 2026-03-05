// PatchDesync.hpp : Hooks for CNC3 desync detection and handling functions.
#pragma once
#include "../../Framework.h"
#include "PatchSSL.hpp" // For PatternByte, FindPattern, ParsePattern

class PatchDesync
{
public:
	PatchDesync();

	static PatchDesync& GetInstance()
	{
		static PatchDesync* instance;

		if (instance == nullptr)
			instance = new PatchDesync();

		return *instance;
	}

	BOOL Patch() const;

private:
	DWORD baseAddress_;
	DWORD size_;
	DWORD offset_;
	DWORD entryPoint_;
};
