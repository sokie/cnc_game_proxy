#pragma once

#include <float.h>
#include <xmmintrin.h>

class FPUGuard
{
public:
    FPUGuard() noexcept
    {
        unsigned int cw = 0;
        if (_controlfp_s(&cw, 0, 0) == 0)
        {
            savedCW_ = cw;
            valid_ = true;
        }

        savedMXCSR_ = _mm_getcsr();
    }

    ~FPUGuard() noexcept
    {
        if (valid_)
        {
            // restore x87 control word state that affects determinism
            (void)_controlfp_s(nullptr, savedCW_, _MCW_PC | _MCW_RC | _MCW_EM | _MCW_IC);
        }

        // restore SSE control/status (rounding + FTZ/DAZ etc.)
        _mm_setcsr(savedMXCSR_);
    }

    FPUGuard(const FPUGuard&) = delete;
    FPUGuard& operator=(const FPUGuard&) = delete;

private:
    unsigned int savedCW_{0};
    unsigned int savedMXCSR_{0};
    bool valid_{false};
};