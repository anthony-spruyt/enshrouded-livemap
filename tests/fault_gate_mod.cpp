// The mod side of the fault gate: the real hook wrapper, logger and fault handler in a DLL of their own, so the
// executable that loads it is a separate image to play the game. The mode says where the fault happens.
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

#include "../src/fault_handler.h"
#include "../src/log.h"
#include "../src/memory.h"
#include "fault_gate.h"

namespace {

constexpr const char* kSiteCallback = "gate_callback";
constexpr const char* kSiteTrampoline = "gate_trampoline";
constexpr const char* kSiteGame = "gate_game";
constexpr size_t kPageSize = 4096;
constexpr int kRegionsToWalk = 64;

// sub rsp,0x28 ; nop ; add rsp,0x28 ; ret
constexpr std::array<uint8_t, 10> kQuiet{0x48, 0x83, 0xEC, 0x28, 0x90, 0x48, 0x83, 0xC4, 0x28, 0xC3};
// mov rax,[rcx] ; nop ; nop ; ret. A hook moves the first five bytes into its trampoline.
constexpr std::array<uint8_t, 6> kReader{0x48, 0x8B, 0x01, 0x90, 0x90, 0xC3};
constexpr unsigned kReaderStep = 3;

using GameFault = void (*)(volatile int* target);

struct Gate {
    std::atomic<int> skips{0};
    volatile int* read_only = nullptr;
    GameFault game_fault = nullptr;
};

Gate& gate() {
    static Gate instance;
    return instance;
}

using Standin = void (*)(const int*);

GameFault find_game_fault() {
    return std::bit_cast<GameFault>(GetProcAddress(GetModuleHandleW(nullptr), kGameFaultExport));
}

std::byte* allocate_page(DWORD protection) {
    return static_cast<std::byte*>(VirtualAlloc(nullptr, kPageSize, MEM_COMMIT | MEM_RESERVE, protection));
}

// Near the exe image, like the game's code. Under Wine a page from VirtualAlloc(nullptr) sits at the top of user space,
// where the hook allocator runs into a free-looking gap it cannot map and gives up (#38).
std::byte* allocate_code_page() {
    SYSTEM_INFO machine{};
    GetSystemInfo(&machine);
    const uintptr_t granularity = machine.dwAllocationGranularity;
    auto* region = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    for (int walked = 0; walked < kRegionsToWalk; ++walked) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(region, &info, sizeof info) == 0) {
            break;
        }
        const auto start = reinterpret_cast<uintptr_t>(info.BaseAddress);
        const uintptr_t end = start + info.RegionSize;
        const uintptr_t slot = (start + granularity - 1) / granularity * granularity;
        if (info.State == MEM_FREE && slot + kPageSize <= end) {
            void* page = VirtualAlloc(reinterpret_cast<void*>(slot), kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (page != nullptr) {
                return static_cast<std::byte*>(page);
            }
        }
        region = reinterpret_cast<const std::byte*>(end);
    }
    return allocate_page(PAGE_EXECUTE_READWRITE);
}

uintptr_t standin(std::span<const uint8_t> code) {
    auto* page = allocate_code_page();
    if (page != nullptr) {
        std::ranges::copy(std::as_bytes(code), page);
    }
    return std::bit_cast<uintptr_t>(page);
}

void call(uintptr_t function) {
    std::bit_cast<Standin>(function)(nullptr);
}

void quiet_callback(SafetyHookContext&) {
    livemap::log("gate: the hook ran");
}

void faulting_callback(SafetyHookContext&) {
    const livemap::fault::SiteScope scope(kSiteCallback);
    *gate().read_only = 1;
}

void game_callback(SafetyHookContext&) {
    const livemap::fault::SiteScope scope(kSiteGame);
    if (const GameFault fault = gate().game_fault) {
        fault(gate().read_only);
    }
}

// Registered after the fault handler, so it sees each fault second and can let the process go on.
LONG CALLBACK skip_reader(EXCEPTION_POINTERS* info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || gate().skips.fetch_sub(1) <= 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    info->ContextRecord->Rip += kReaderStep;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool install_hook(livemap::fault::Hook& out, const char* site, uintptr_t target, safetyhook::MidHookFn callback) {
    auto created = livemap::fault::Hook::create(site, target, callback);
    if (created) {
        out = std::move(*created);
        return true;
    }
    const auto& error = created.error();
    const bool allocation = error.type == safetyhook::MidHook::Error::BAD_ALLOCATION;
    const int code = allocation ? static_cast<int>(error.allocator_error) : static_cast<int>(error.inline_hook_error.type);
    livemap::log("gate: could not hook %s: %s error %d", site, allocation ? "allocator" : "inline hook", code);
    return false;
}

int fault_in_callback() {
    livemap::fault::Hook hooked;
    const uintptr_t function = standin(kQuiet);
    if (!install_hook(hooked, kSiteCallback, function, faulting_callback)) {
        return kHookFailed;
    }
    livemap::log("gate: calling the hooked function");
    call(function);
    return kSurvived;
}

int fault_in_trampoline() {
    livemap::fault::Hook hooked;
    const uintptr_t function = standin(kReader);
    if (!install_hook(hooked, kSiteTrampoline, function, quiet_callback)) {
        return kHookFailed;
    }
    livemap::log("gate: calling the hooked function");
    call(function);
    return kSurvived;
}

int fault_twice() {
    livemap::fault::Hook in_trampoline;
    livemap::fault::Hook in_callback;
    const uintptr_t reader = standin(kReader);
    const uintptr_t quiet = standin(kQuiet);
    if (!install_hook(in_trampoline, kSiteTrampoline, reader, quiet_callback) ||
        !install_hook(in_callback, kSiteCallback, quiet, faulting_callback)) {
        return kHookFailed;
    }
    gate().skips = 1;
    AddVectoredExceptionHandler(0, skip_reader);
    livemap::log("gate: calling the first function");
    call(reader);
    livemap::log("gate: the first fault was skipped");
    call(quiet);
    return kSurvived;
}

int fault_in_the_game_from_a_callback() {
    livemap::fault::Hook hooked;
    const uintptr_t function = standin(kQuiet);
    if (!install_hook(hooked, kSiteGame, function, game_callback)) {
        return kHookFailed;
    }
    livemap::log("gate: calling the hooked function");
    call(function);
    return kSurvived;
}

int fault_in_the_game_alone() {
    const GameFault fault = gate().game_fault;
    if (fault == nullptr) {
        return kHookFailed;
    }
    livemap::log("gate: calling the game outside any callback");
    fault(gate().read_only);
    return kSurvived;
}

bool probe_gives_up(uintptr_t address) {
    uint64_t value = 0;
    return !livemap::read_u64(address, value);
}

int handled_probe() {
    if (!probe_gives_up(0)) {
        return kHookFailed;
    }
    livemap::log("gate: the probe handled its own bad read");
    return 0;
}

int handled_probe_on_a_guard_page() {
    if (const auto* page = allocate_page(PAGE_READONLY | PAGE_GUARD); page == nullptr || !probe_gives_up(std::bit_cast<uintptr_t>(page))) {
        return kHookFailed;
    }
    livemap::log("gate: the probe handled a guard page");
    return 0;
}

int handled_probe_then_fault() {
    const int status = handled_probe();
    return status != 0 ? status : fault_in_callback();
}

int run(std::string_view mode) {
    if (mode == "callback") {
        return fault_in_callback();
    }
    if (mode == "trampoline") {
        return fault_in_trampoline();
    }
    if (mode == "twice") {
        return fault_twice();
    }
    if (mode == "game") {
        return fault_in_the_game_from_a_callback();
    }
    if (mode == "unhooked") {
        return fault_in_the_game_alone();
    }
    if (mode == "probe") {
        return handled_probe();
    }
    if (mode == "guard_page") {
        return handled_probe_on_a_guard_page();
    }
    if (mode == "probe_then_fault") {
        return handled_probe_then_fault();
    }
    return kHookFailed;
}

}  // namespace

extern "C" FAULT_GATE_API int gate_run(const char* mode) {
    livemap::log_open(L".", true);
    Gate& current = gate();
    current.game_fault = find_game_fault();
    current.read_only = static_cast<volatile int*>(VirtualAlloc(nullptr, kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY));
    if (current.game_fault == nullptr) {
        livemap::log("gate: the executable does not export %s", kGameFaultExport);
        return kHookFailed;
    }
    if (current.read_only == nullptr || !livemap::fault::install(livemap::log_handle())) {
        return kHookFailed;
    }
    livemap::log("gate: handler installed");
    const int status = run(mode);
    if (status == kSurvived) {
        livemap::log("gate: the fault did not end the process");
    }
    livemap::fault::remove();
    return status;
}
