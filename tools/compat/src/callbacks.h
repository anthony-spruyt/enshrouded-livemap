#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include "registers.h"

namespace livemap::compat {

// The second hook of join_line sits on the instruction after the call the first one sits on.
constexpr uint32_t kCallLength = 5;

// A hook callback of src/ and the registers it reads from the context the hook gives it.
struct Callback {
    std::string_view function;
    std::string_view site;  // the pattern of the sigset that places the hook
    uint32_t offset;        // of the hook from the address of the site
    std::string_view layout;  // the mining layout the entry is for; empty for every layout
    Registers reads;
};

std::span<const Callback> callbacks();

}  // namespace livemap::compat
