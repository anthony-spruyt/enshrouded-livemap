// The fault line: which exception addresses belong to the map, and the log line written for them.
// Nothing here allocates, locks or calls the CRT, so it can run while the process is crashing.
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace livemap::fault {

struct Range {
    uintptr_t begin = 0;
    uintptr_t end = 0;  // exclusive
};

constexpr size_t kMaxRegions = 32;
constexpr size_t kNoSlot = SIZE_MAX;

// Memory a hook's stub and trampoline live in, named by the hook site.
struct Region {
    Range range;
    const char* site = nullptr;
};

// Regions that can be published and retired while another thread looks addresses up. A slot is never reused.
class RegionTable {
public:
    size_t publish(const Range& range, const char* site);
    void retire(size_t slot);
    const Region* find(uintptr_t address) const;

private:
    std::array<Region, kMaxRegions> entries_{};
    std::array<std::atomic<const Region*>, kMaxRegions> live_{};
    std::atomic<size_t> used_{0};
};

struct Layout {
    Range module;
    Range probes;
    Range game;
    RegionTable regions;
};

enum class Where {
    Outside,
    Module,
    Trampoline,
    Game,
};

struct Verdict {
    Where where = Where::Outside;
    uint32_t offset = 0;  // from the module or game image base, or from the start of the trampoline region
    const char* site = nullptr;
};

struct Stamp {
    uint16_t year = 0;
    uint16_t month = 0;
    uint16_t day = 0;
    uint16_t hour = 0;
    uint16_t minute = 0;
    uint16_t second = 0;
    uint16_t millisecond = 0;
};

// False for C++ throws, debugger traffic, guard pages and breakpoints: a process survives these.
bool is_fault_code(uint32_t code);

// The codes the probes in memory.cpp catch themselves; classify() leaves them out for addresses in the probes.
constexpr bool is_bad_read(uint32_t code) {
    constexpr uint32_t kAccessViolation = 0xC0000005;
    constexpr uint32_t kInPageError = 0xC0000006;
    constexpr uint32_t kGuardPage = 0x80000001;
    return code == kAccessViolation || code == kInPageError || code == kGuardPage;
}

// `active_site` is the hook whose callback this thread is running, or nullptr. Game code counts only under one.
Verdict classify(const Layout& layout, uintptr_t address, uint32_t code, const char* active_site);

// Writes "<time> [livemap] FAULT code=0x<8 hex> at=<livemap|trampoline|game>+0x<8 hex> site=<name|none>\r\n", the line ending the CRT gives every other line of the log.
// Returns the length, or 0 when the line does not fit in `capacity`.
size_t format_line(char* out, size_t capacity, const Stamp& at, uint32_t code, const Verdict& verdict);

}  // namespace livemap::fault
