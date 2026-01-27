// PatchLoginCert.hpp : Hooks wsLoginCertIsValid to bypass GameSpy login certificate verification.
#pragma once
#include "../../Framework.h"

// GameSpy type definitions
typedef int gsi_bool;
#define gsi_true 1
#define gsi_false 0

// Forward declaration of GSLoginCertificate (opaque pointer, we don't need the full struct)
struct GSLoginCertificate;

// Function pointer type for wsLoginCertIsValid
typedef gsi_bool(__cdecl* wsLoginCertIsValid_t)(const GSLoginCertificate* cert);

class PatchLoginCert
{
public:
	PatchLoginCert();

	static PatchLoginCert& GetInstance()
	{
		static PatchLoginCert* instance;

		if (instance == nullptr)
			instance = new PatchLoginCert();

		return *instance;
	}

	BOOL Patch() const;

	// Original function pointer (for calling the original if needed)
	static wsLoginCertIsValid_t pOriginal;

private:
	DWORD baseAddress_;
	DWORD size_;
	DWORD offset_;
	DWORD entryPoint_;
};
