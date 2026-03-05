// FPUGuard.h : RAII guard that saves/restores the x87 FPU control word.
//
// CNC3 uses 53-bit (double) FPU precision for deterministic lockstep.
// Any injected code (Boost, OpenSSL, CRT) can change the FPU control word
// to 64-bit extended precision, causing floating-point results to differ
// between clients and triggering desync.
//
// Usage: Place FPUGuard at the top of any hook function that might
// call FPU-affecting code (logging, crypto, string formatting, etc.)
//
#pragma once

#include <float.h>

class FPUGuard
{
public:
	FPUGuard()
	{
		_controlfp_s(&savedCW_, 0, 0);
	}

	~FPUGuard()
	{
		unsigned int dummy;
		_controlfp_s(&dummy, savedCW_, MCW_PC | MCW_RC | MCW_EM | MCW_IC | MCW_DN);
	}

	FPUGuard(const FPUGuard&) = delete;
	FPUGuard& operator=(const FPUGuard&) = delete;

private:
	unsigned int savedCW_;
};
