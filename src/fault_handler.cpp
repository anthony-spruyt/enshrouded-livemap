#include "fault_handler.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <utility>

#include "fault.h"

namespace livemap::fault {

namespace {

constexpr size_t kNoSlot = SIZE_MAX;
constexpr size_t kAnchorSize = 2;
constexpr size_t kLineCapacity = 192;
constexpr char kProbeSection[] = ".lmprobe";

// The handler reads these while the process crashes: each is set before it is registered or published through g_table.
Range g_module;
Range g_probes;
Region g_entries[kMaxRegions];
std::atomic<const Region*> g_table[kMaxRegions];
std::atomic<size_t> g_used{0};
std::atomic<bool> g_written{false};
std::atomic<void*> g_file{nullptr};
std::atomic<void*> g_handler{nullptr};
thread_local const char* t_site = nullptr;

HMODULE this_module() {
    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&this_module), &module);
    return module;
}

const IMAGE_NT_HEADERS* headers_of(HMODULE module) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    return reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
}

Range image_range(HMODULE module) {
    const auto base = reinterpret_cast<uintptr_t>(module);
    return {base, base + headers_of(module)->OptionalHeader.SizeOfImage};
}

Range probe_range(HMODULE module) {
    const IMAGE_NT_HEADERS* nt = headers_of(module);
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(section[i].Name, kProbeSection, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            const auto begin = reinterpret_cast<uintptr_t>(module) + section[i].VirtualAddress;
            return {begin, begin + section[i].Misc.VirtualSize};
        }
    }
    return {};
}

// The whole allocation a hook's private allocator took, which holds the hook's stub and trampoline.
Range block_of(const void* address) {
    MEMORY_BASIC_INFORMATION inside{};
    MEMORY_BASIC_INFORMATION whole{};
    if (VirtualQuery(address, &inside, sizeof inside) == 0 || VirtualQuery(inside.AllocationBase, &whole, sizeof whole) == 0) {
        return {};
    }
    const auto base = reinterpret_cast<uintptr_t>(inside.AllocationBase);
    return {base, base + whole.RegionSize};
}

size_t publish(const Range& range, const char* site) {
    if (range.begin >= range.end) {
        return kNoSlot;
    }
    const size_t slot = g_used.fetch_add(1);
    if (slot >= kMaxRegions) {
        return kNoSlot;
    }
    g_entries[slot] = {range, site};
    g_table[slot].store(&g_entries[slot], std::memory_order_release);
    return slot;
}

void retire(size_t slot) {
    if (slot < kMaxRegions) {
        g_table[slot].store(nullptr, std::memory_order_release);
    }
}

size_t fill_layout(Layout& layout) {
    layout.module = g_module;
    layout.probes = g_probes;
    size_t regions = 0;
    const size_t used = std::min(g_used.load(std::memory_order_acquire), kMaxRegions);
    for (size_t i = 0; i < used; ++i) {
        if (const Region* entry = g_table[i].load(std::memory_order_acquire)) {
            layout.regions[regions++] = *entry;
        }
    }
    return regions;
}

void write_line(uint32_t code, const Verdict& verdict) {
    SYSTEMTIME now;
    GetSystemTime(&now);
    const Stamp stamp{now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds};
    char line[kLineCapacity];
    const char* site = verdict.site != nullptr ? verdict.site : t_site;
    const size_t length = format_line(line, sizeof line, stamp, code, verdict.where, verdict.offset, site);
    if (length > 0) {
        DWORD written = 0;
        WriteFile(g_file.load(std::memory_order_acquire), line, static_cast<DWORD>(length), &written, nullptr);
    }
}

LONG CALLBACK on_exception(EXCEPTION_POINTERS* info) {
    const auto code = static_cast<uint32_t>(info->ExceptionRecord->ExceptionCode);
    if (!is_fault_code(code) || g_written.load(std::memory_order_relaxed)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    Layout layout;
    const size_t regions = fill_layout(layout);
    const auto address = reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress);
    const Verdict verdict = classify(layout, regions, address, code);
    if (verdict.where != Where::Outside && !g_written.exchange(true)) {
        write_line(code, verdict);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

bool install(void* file) {
    HMODULE self = this_module();
    if (file == nullptr || file == INVALID_HANDLE_VALUE || self == nullptr || g_handler.load() != nullptr) {
        return false;
    }
    SetFilePointerEx(file, LARGE_INTEGER{}, nullptr, FILE_END);
    g_module = image_range(self);
    g_probes = probe_range(self);
    g_file.store(file, std::memory_order_release);
    // Last in line: safetyhook's own handler runs first and takes the faults it causes on purpose.
    void* handler = AddVectoredExceptionHandler(0, on_exception);
    g_handler.store(handler);
    return handler != nullptr;
}

void remove() {
    if (void* handler = g_handler.exchange(nullptr)) {
        RemoveVectoredExceptionHandler(handler);
    }
}

SiteScope::SiteScope(const char* site) : previous_(t_site) {
    t_site = site;
}

SiteScope::~SiteScope() {
    t_site = previous_;
}

Hook::Hook(Hook&& other) noexcept : hook_(std::move(other.hook_)), slot_(std::exchange(other.slot_, kNoSlot)) {}

Hook& Hook::operator=(Hook&& other) noexcept {
    if (this != &other) {
        retire(slot_);
        hook_ = std::move(other.hook_);
        slot_ = std::exchange(other.slot_, kNoSlot);
    }
    return *this;
}

Hook::~Hook() {
    retire(slot_);
}

std::expected<Hook, safetyhook::MidHook::Error> Hook::create(const char* site, void* target,
                                                             safetyhook::MidHookFn callback) {
    const auto allocator = safetyhook::Allocator::create();
    // The first allocation of a private allocator opens the block that the hook's stub and trampoline then share.
    auto anchor = allocator->allocate_near({static_cast<uint8_t*>(target)}, kAnchorSize);
    if (!anchor) {
        return std::unexpected(safetyhook::MidHook::Error::bad_allocation(anchor.error()));
    }
    Hook created;
    created.slot_ = publish(block_of(anchor->data()), site);
    auto hook = safetyhook::MidHook::create(allocator, target, callback);
    if (!hook) {
        return std::unexpected(hook.error());
    }
    created.hook_ = std::move(*hook);
    return created;
}

}  // namespace livemap::fault
