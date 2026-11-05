// A stand-in for the game with the real hook wrapper, logger and fault handler. tools/test_fault_gate.py runs it
// once per mode and reads livemap.log: the mode says where the fault happens, the log says what the handler saw.
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <utility>

#include "../src/fault_handler.h"
#include "../src/log.h"
#include "../src/memory.h"

namespace {

constexpr int kHookFailed = 98;
constexpr int kSurvived = 99;
constexpr const char* kSiteCallback = "gate_callback";
constexpr const char* kSiteTrampoline = "gate_trampoline";

// sub rsp,0x28 ; nop ; add rsp,0x28 ; ret
constexpr uint8_t kQuiet[] = {0x48, 0x83, 0xEC, 0x28, 0x90, 0x48, 0x83, 0xC4, 0x28, 0xC3};
// mov rax,[rcx] ; nop ; nop ; ret. A hook moves the first five bytes into its trampoline.
constexpr uint8_t kReader[] = {0x48, 0x8B, 0x01, 0x90, 0x90, 0xC3};
constexpr unsigned kReaderStep = 3;

std::atomic<int> g_skips{0};

using Standin = void (*)(const void*);

void* standin(const uint8_t* code, size_t size) {
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (page != nullptr) {
        std::memcpy(page, code, size);
    }
    return page;
}

void call(void* function, const void* argument) {
    reinterpret_cast<Standin>(function)(argument);
}

void quiet_callback(SafetyHookContext&) {}

void faulting_callback(SafetyHookContext&) {
    livemap::fault::SiteScope scope(kSiteCallback);
    volatile uintptr_t address = 0;
    *reinterpret_cast<volatile int*>(address) = 1;
}

// Registered after the fault handler, so it sees each fault second and can let the process go on.
LONG CALLBACK skip_reader(EXCEPTION_POINTERS* info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || g_skips.fetch_sub(1) <= 0) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    info->ContextRecord->Rip += kReaderStep;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool install_hook(livemap::fault::Hook& out, const char* site, void* target, safetyhook::MidHookFn callback) {
    auto created = livemap::fault::Hook::create(site, target, callback);
    if (!created) {
        livemap::log("gate: could not hook %s", site);
        return false;
    }
    out = std::move(*created);
    return true;
}

int fault_in_callback() {
    livemap::fault::Hook hooked;
    void* game = standin(kQuiet, sizeof kQuiet);
    if (!install_hook(hooked, kSiteCallback, game, faulting_callback)) {
        return kHookFailed;
    }
    livemap::log("gate: calling the hooked function");
    call(game, nullptr);
    return kSurvived;
}

int fault_in_trampoline() {
    livemap::fault::Hook hooked;
    void* game = standin(kReader, sizeof kReader);
    if (!install_hook(hooked, kSiteTrampoline, game, quiet_callback)) {
        return kHookFailed;
    }
    livemap::log("gate: calling the hooked function");
    call(game, nullptr);
    return kSurvived;
}

int fault_twice() {
    livemap::fault::Hook in_trampoline;
    livemap::fault::Hook in_callback;
    void* reader = standin(kReader, sizeof kReader);
    void* quiet = standin(kQuiet, sizeof kQuiet);
    if (!install_hook(in_trampoline, kSiteTrampoline, reader, quiet_callback)) {
        return kHookFailed;
    }
    if (!install_hook(in_callback, kSiteCallback, quiet, faulting_callback)) {
        return kHookFailed;
    }
    g_skips = 1;
    AddVectoredExceptionHandler(0, skip_reader);
    livemap::log("gate: calling the first function");
    call(reader, nullptr);
    livemap::log("gate: the first fault was skipped");
    call(quiet, nullptr);
    return kSurvived;
}

int fault_in_the_game() {
    void* game = standin(kReader, sizeof kReader);
    livemap::log("gate: calling a function that is not hooked");
    call(game, nullptr);
    return kSurvived;
}

int handled_probe() {
    uint64_t value = 0;
    if (livemap::read_u64(0, value)) {
        return kHookFailed;
    }
    livemap::log("gate: the probe handled its own bad read");
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
        return fault_in_the_game();
    }
    if (mode == "probe") {
        return handled_probe();
    }
    if (mode == "probe_then_fault") {
        return handled_probe_then_fault();
    }
    return kHookFailed;
}

}  // namespace

int main(int argc, char** argv) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc != 2) {
        return kHookFailed;
    }
    livemap::log_open(L".", true);
    if (!livemap::fault::install(livemap::log_handle())) {
        return kHookFailed;
    }
    livemap::log("gate: handler installed");
    const int status = run(argv[1]);
    if (status == kSurvived) {
        livemap::log("gate: the fault did not end the process");
    }
    livemap::fault::remove();
    return status;
}
