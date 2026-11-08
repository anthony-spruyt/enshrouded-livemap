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

// The registers every path from the instruction at `entry` to the one at `rva` overwrites whole. Only the stack pointer is
// set at `entry`, a call leaves the registers it preserves and its result, and where paths meet the registers of all of
// them count. Control that enters from outside the chain, by a branch of `branches` that no jump of the chain explains,
// brings only the stack pointer, and so does each instruction that neither `entry` nor such a branch leads to. A fault when
// `entry` starts no instruction.
std::expected<Registers, Fault> written_before(std::span<const Code> chain, uint32_t entry, uint32_t rva, const BranchMap& branches);

// `live_before`, plus the registers the instruction just before `rva` reads or overwrites when it leads into it, counted
// only where `written_before` gives them.
std::expected<Registers, Fault> in_use_at(std::span<const Code> chain, uint32_t entry, uint32_t rva, const BranchMap& branches);

}  // namespace livemap::compat
