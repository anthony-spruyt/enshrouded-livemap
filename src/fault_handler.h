// The exception handler that writes the FAULT line, and the hook wrapper that tells it where a hook's memory is.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>

#include <safetyhook.hpp>

namespace livemap::fault {

// Registers a vectored handler that only observes: it always lets the search go on, so a fault still
// takes the process down the normal way. `file` is an open handle to livemap.log, positioned at its end.
bool install(void* file);

// Run before the hooks go: a handler left behind would outlive the code it points into.
void remove();

// Names the hook whose callback this thread is running, for the `site=` field. Pass a string literal.
class SiteScope {
public:
    explicit SiteScope(const char* site);
    ~SiteScope();
    SiteScope(const SiteScope&) = delete;
    SiteScope& operator=(const SiteScope&) = delete;

private:
    const char* previous_;
};

// A mid-function hook whose stub and trampoline memory the handler knows. `site` must be a string literal.
class Hook {
public:
    Hook() = default;
    Hook(const Hook&) = delete;
    Hook& operator=(const Hook&) = delete;
    Hook(Hook&& other) noexcept;
    Hook& operator=(Hook&& other) noexcept;
    ~Hook();

    static std::expected<Hook, safetyhook::MidHook::Error> create(const char* site, void* target,
                                                                  safetyhook::MidHookFn callback);

private:
    safetyhook::MidHook hook_;
    size_t slot_ = SIZE_MAX;
};

}  // namespace livemap::fault
