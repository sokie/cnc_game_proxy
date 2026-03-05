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

// MCW_DN may not be defined in older MSVC headers
#ifndef MCW_DN
#define MCW_DN 0x03000000
#endif

class FPUGuard
{
public:
	FPUGuard()
	{
		savedCW_ = _controlfp(0, 0);
	}

	~FPUGuard()
	{
		_controlfp(savedCW_, MCW_PC | MCW_RC | MCW_EM | MCW_IC);
	}

	FPUGuard(const FPUGuard&) = delete;
	FPUGuard& operator=(const FPUGuard&) = delete;

private:
	unsigned int savedCW_;
};
