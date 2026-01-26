// PatchAuthKey.hpp : Defines the PatchAuthKey class, which handles the patching of auth certificate check.
#pragma once
#include "../../Framework.h"

class PatchAuthKey
{
public:
	PatchAuthKey();

	static PatchAuthKey& GetInstance()
	{
		static PatchAuthKey* instance;

		if (instance == nullptr)
			instance = new PatchAuthKey();

		return *instance;
	}

	BOOL Patch() const;
	void DumpAuthCheckMemory() const;

private:
	DWORD baseAddress_;
};
