// The fault line: which exception addresses belong to the map, and the log line written for them.
// Nothing here allocates, locks or calls the CRT, so it can run while the process is crashing.
#pragma once

#include <cstddef>
#include <cstdint>

namespace livemap::fault {

struct Range {
    uintptr_t begin = 0;
    uintptr_t end = 0;  // exclusive
};

constexpr size_t kMaxRegions = 32;

// Memory a hook's stub and trampoline live in, named by the hook site.
struct Region {
    Range range;
    const char* site = nullptr;
};

struct Layout {
    Range module;
    Range probes;
    Region regions[kMaxRegions];
};

enum class Where {
    Outside,
    Module,
    Trampoline,
};

struct Verdict {
    Where where = Where::Outside;
    uint32_t offset = 0;  // from the module base, or from the start of the trampoline region
    const char* site = nullptr;
};

struct Stamp {
    uint16_t year, month, day, hour, minute, second, millisecond;
};

// False for C++ throws, debugger traffic, guard pages and breakpoints: a process survives these.
bool is_fault_code(uint32_t code);

// Only the first `regions` entries of layout.regions are looked at.
Verdict classify(const Layout& layout, size_t regions, uintptr_t address, uint32_t code);

// Writes "<time> [livemap] FAULT code=0x<8 hex> at=<livemap|trampoline>+0x<8 hex> site=<name|none>\r\n", the line ending the CRT gives every other line of the log.
// Returns the length, or 0 when the line does not fit in `capacity`.
size_t format_line(char* out, size_t capacity, const Stamp& at, uint32_t code, Where where, uint32_t offset,
                   const char* site);

}  // namespace livemap::fault
