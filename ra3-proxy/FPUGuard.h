// FPUGuard.h : RAII guard that saves/restores the x87 FPU control word and SSE MXCSR.
//
// CNC3 uses 53-bit (double) FPU precision for deterministic lockstep.
// Any injected code (Boost, OpenSSL, CRT) can change the FPU control word
// to 64-bit extended precision, causing floating-point results to differ
// between clients and triggering desync.
//
#pragma once

#include <float.h>
#include <xmmintrin.h>

// MSVC defines these without underscore prefix when <float.h> is included,
// but just in case, fall back to the standard values.
#ifndef MCW_PC
#define MCW_PC  _MCW_PC
#endif
#ifndef MCW_RC
#define MCW_RC  _MCW_RC
#endif
#ifndef MCW_EM
#define MCW_EM  _MCW_EM
#endif
#ifndef MCW_IC
#define MCW_IC  _MCW_IC
#endif

class FPUGuard
{
public:
	FPUGuard() noexcept
	{
		unsigned int cw = 0;
		if (_controlfp_s(&cw, 0, 0) == 0)
			savedCW_ = cw;

		savedMXCSR_ = _mm_getcsr();
		valid_ = (savedCW_ != 0);
	}

	~FPUGuard() noexcept
	{
		if (valid_)
		{
			unsigned int cur;
			_controlfp_s(&cur, savedCW_, MCW_PC | MCW_RC | MCW_EM | MCW_IC);
		}

		_mm_setcsr(savedMXCSR_);
	}

	FPUGuard(const FPUGuard&) = delete;
	FPUGuard& operator=(const FPUGuard&) = delete;

private:
	unsigned int savedCW_{ 0 };
	unsigned int savedMXCSR_{ 0 };
	bool valid_{ false };
};
