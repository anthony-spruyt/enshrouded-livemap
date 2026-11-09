#pragma once

#include <Zydis/Decoder.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "pe.h"
#include "registers.h"

namespace livemap::compat {

// A hook overwrites a jmp rel32, rounded up to whole instructions.
constexpr uint32_t kHookLength = 5;
constexpr size_t kMaxInstructionLength = 15;

// Bytes at [rva, rva + length) that the code reads as a value of its own and the comparison must not see.
struct Range {
    uint32_t rva = 0;
    uint32_t length = 0;
};

// The disp32 of a [base + index * 4 + disp32] operand: the form a jump table is read through.
struct IndexedLoad {
    uint8_t offset = 0;  // of the displacement within the instruction
    int64_t address = 0;
};

// Stop is a trap: nothing follows it.
enum class Flow { Next,
                  Call,
                  Return,
                  Branch,
                  Jump,
                  Indirect,
                  Stop };

// One instruction with the bytes that depend on where code sits zeroed; a branch or a table load keeps its target as an RVA.
struct Instruction {
    uint32_t rva = 0;
    uint8_t length = 0;
    Flow flow = Flow::Next;
    Registers reads = 0;
    Registers kills = 0;  // only registers it overwrites whole: a partial write keeps the rest live
    bool relative = false;
    bool table_ref = false;
    int64_t target = 0;
    std::optional<int64_t> address;  // the RVA a rip-relative lea forms: where a handler hands control back
    std::optional<IndexedLoad> indexed;
    std::array<std::byte, kMaxInstructionLength> bytes{};
};

class Decoder {
public:
    Decoder();

    // The instruction at the start of `code`, or nothing when the bytes are no instruction.
    std::optional<Instruction> decode(std::span<const std::byte> code, uint32_t rva, std::span<const Range> masks) const;

private:
    ZydisDecoder decoder_;
};

// The bytes a hook at `site` overwrites: whole instructions until kHookLength bytes are covered. Nothing when `site` is
// not the start of an instruction of `stream` or the stream ends first.
std::optional<uint32_t> hook_span(std::span<const Instruction> stream, uint32_t site);

// Addresses of code inside a function that sit in the function itself, as a switch statement leaves them.
struct Table {
    uint32_t rva = 0;
    std::vector<uint32_t> entries;  // RVAs inside the function
    uint32_t ref = 0;               // the first instruction that reads the table
};

// A function or window of code: its range, the instructions in it and the jump tables between them.
struct Code {
    Function range;
    std::vector<Instruction> instructions;
    std::vector<Table> tables;
};

struct Decoded {
    Code code;
    std::optional<uint32_t> stopped;  // where the code could not be followed: bytes that are no instruction, or a bad table
};

// The instructions of the function whose bytes are `bytes`, in a row. An indexed load that reads a table of addresses of
// the function itself marks the table: its bytes are not decoded, and the load and the table are compared by offsets.
Decoded decode_function(const Decoder& decoder, std::span<const std::byte> bytes, Function range, std::span<const Range> masks);

struct Difference {
    std::string kind;  // "bytes", "branch", "length" or "table"
    uint32_t rva = 0;
    uint32_t base_rva = 0;
};

// The first place where `now` differs from `before`. Calls and jumps that leave their code compare equal whatever they
// target; those that stay inside it, and the tables of addresses, have to land at the same offset from the start of the code.
std::optional<Difference> compare_code(const Code& now, const Code& before);

struct Branch {
    uint32_t from = 0;
    int64_t target = 0;
    bool dispatched = false;  // an exception handler hands control back there; `from` is the start of the code it guarded
};

// A function whose decoding stopped early: the bytes from `at` to the end of `range` are not decoded.
struct Stopped {
    Function range;
    uint32_t at = 0;
};

struct BranchMap {
    std::vector<Branch> branches;  // sorted by target
    std::vector<Stopped> stopped;  // sorted by begin
};

// Every call and jump with a relative target in the functions of the exception table, every address they form with a
// rip-relative lea that points into .text, every entry of their jump tables, and every jump target of their scope tables.
// A table is read wherever the load points, and its entries count when they lie in the chain of the function that loads it.
BranchMap collect_branches(const Image& image, const Decoder& decoder);

// Whether a function that stopped is a chunk of the function `site` belongs to, or is one a decoded branch lands inside.
bool stopped_near(const BranchMap& map, const Image& image, const Function& site);

// Whether a function outside the chain of `site` stopped with undecoded bytes within 128 bytes of [low, high).
bool undecoded_near(const BranchMap& map, const Image& image, const Function& site, uint32_t low, uint32_t high);

// The branches that land strictly between `low` and `high`.
std::vector<Branch> landings(const BranchMap& map, uint32_t low, uint32_t high);

}  // namespace livemap::compat
