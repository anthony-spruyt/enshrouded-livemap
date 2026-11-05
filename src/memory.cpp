#include "memory.h"

#include <windows.h>

#include "fault.h"

namespace livemap {

namespace {

// Only a bad read is the probe's to handle; any other code goes on to the fault handler.
constexpr LONG probe_filter(DWORD code) {
    return fault::is_bad_read(code) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

// A bad read in this section is handled on purpose; the fault handler leaves it out (section name in fault_handler.cpp).
#pragma code_seg(push, ".lmprobe")

// No C++ objects with destructors in these functions, so __try/__except is allowed.
__declspec(noinline) bool read_u8(uintptr_t address, uint8_t& out) {
    __try {
        out = *reinterpret_cast<const volatile uint8_t*>(address);
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

__declspec(noinline) bool read_u16(uintptr_t address, uint16_t& out) {
    __try {
        out = *reinterpret_cast<const volatile uint16_t*>(address);
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

__declspec(noinline) bool read_u32(uintptr_t address, uint32_t& out) {
    __try {
        out = *reinterpret_cast<const volatile uint32_t*>(address);
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

__declspec(noinline) bool write_u32(uintptr_t address, uint32_t value) {
    __try {
        *reinterpret_cast<volatile uint32_t*>(address) = value;
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

__declspec(noinline) bool read_ptr(uintptr_t address, uintptr_t& out) {
    __try {
        out = *reinterpret_cast<const volatile uintptr_t*>(address);
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

__declspec(noinline) bool read_u64(uintptr_t address, uint64_t& out) {
    __try {
        out = *reinterpret_cast<const volatile uint64_t*>(address);
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

__declspec(noinline) bool read_bytes(uintptr_t address, std::span<std::byte> out) {
    __try {
        const volatile uint8_t* src = reinterpret_cast<const volatile uint8_t*>(address);
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] = std::byte{src[i]};
        }
        return true;
    } __except (probe_filter(GetExceptionCode())) {
        return false;
    }
}

#pragma code_seg(pop)

}  // namespace livemap
