#pragma once

#include <cstdint>
#include <optional>
#include <span>

#include "disasm.h"

namespace livemap::compat {

// The registers the code from `rva` on reads before it overwrites them, over every chunk of one function in `chain`.
// Flow that leaves the chain counts every register that place could read; nothing when no instruction starts at `rva`.
std::optional<Registers> live_before(std::span<const Code> chain, uint32_t rva);

// `live_before`, plus the registers the instruction just before `rva` reads or overwrites when it leads into it.
std::optional<Registers> in_use_at(std::span<const Code> chain, uint32_t rva);

}  // namespace livemap::compat
