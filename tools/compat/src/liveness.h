#pragma once

#include <cstdint>
#include <expected>
#include <span>

#include "disasm.h"

namespace livemap::compat {

// Why the code from an address cannot be judged.
enum class Fault {
    NoInstruction,  // no instruction of the chain starts there
    Unfollowable,   // code reachable from there goes where the chain cannot be followed
};

// The registers the code from `rva` on reads before it overwrites them, over every chunk of one function in `chain`.
// A jump out of the chain counts as a tail call. A branch or table entry into the middle of an instruction, and code that
// runs off the end of a chunk, cannot be followed: that is a fault.
std::expected<Registers, Fault> live_before(std::span<const Code> chain, uint32_t rva);

// `live_before`, plus the registers the instruction just before `rva` reads or overwrites when it leads into it.
std::expected<Registers, Fault> in_use_at(std::span<const Code> chain, uint32_t rva);

}  // namespace livemap::compat
