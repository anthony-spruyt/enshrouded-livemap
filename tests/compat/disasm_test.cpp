// The decoder wrapper on hand-assembled x64: what the normalizer masks, what it keeps, and the hook checks built on it.
#include <algorithm>
#include <array>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <utility>
#include <vector>

#include "disasm.h"
#include "pe_builder.h"
#include "test_support.h"

using compat_test::bytes_of;
using livemap::compat::Branch;
using livemap::compat::Code;
using livemap::compat::Decoded;
using livemap::compat::Decoder;
using livemap::compat::Function;
using livemap::compat::Image;
using livemap::compat::Instruction;

namespace {

constexpr std::byte kCallOpcode{0xe8};

Decoded decode_at(const std::vector<std::byte>& bytes, uint32_t begin = 0x1000, std::span<const livemap::compat::Range> masks = {}) {
    const Decoder decoder;
    return livemap::compat::decode_function(decoder, bytes, Function{begin, begin + static_cast<uint32_t>(bytes.size())}, masks);
}

std::vector<Instruction> decode_all(const std::vector<std::byte>& code, uint32_t rva = 0x1000) {
    return decode_at(code, rva).code.instructions;
}

Code code_of(const std::vector<std::byte>& bytes, uint32_t begin = 0x1000) {
    return decode_at(bytes, begin).code;
}

void append_dword(std::vector<std::byte>& out, uint32_t value) {
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

// A switch: mov eax,[rdx+rcx*4+table]; add rax,rdx; jmp rax; two returns; the table of absolute addresses of those returns.
struct Switch {
    std::vector<uint32_t> cases = {0, 1, 0};  // which of the two returns each entry picks
    size_t loads = 1;                          // instructions that read the table
    size_t early_returns = 0;                  // returns between the jump and the table
    size_t late_returns = 0;                   // returns after the table
    uint32_t skew = 0;                         // added to the address every load after the first reads
};

constexpr uint32_t kLoadLength = 7;

uint32_t table_offset(const Switch& spec) {
    return static_cast<uint32_t>(spec.loads) * kLoadLength + 3 + 2 + 2 + static_cast<uint32_t>(spec.early_returns);
}

std::vector<std::byte> switch_function(uint32_t begin, const Switch& spec) {
    std::vector<std::byte> bytes;
    for (size_t i = 0; i < spec.loads; ++i) {
        const auto load = bytes_of({0x8b, 0x84, 0x8a});
        bytes.insert(bytes.end(), load.begin(), load.end());
        append_dword(bytes, begin + table_offset(spec) + (i == 0 ? 0 : spec.skew));
    }
    const auto jump = bytes_of({0x48, 0x01, 0xd0, 0xff, 0xe0, 0xc3, 0xc3});
    bytes.insert(bytes.end(), jump.begin(), jump.end());
    bytes.insert(bytes.end(), spec.early_returns, std::byte{0xc3});
    for (const uint32_t pick : spec.cases) {
        append_dword(bytes, begin + static_cast<uint32_t>(spec.loads) * kLoadLength + 5 + pick);
    }
    bytes.insert(bytes.end(), spec.late_returns, std::byte{0xc3});
    return bytes;
}

std::vector<std::byte> dwords(std::initializer_list<uint32_t> values) {
    std::vector<std::byte> out;
    for (const uint32_t value : values) {
        append_dword(out, value);
    }
    return out;
}

// mov eax,[rdx+rcx*4+table]; add rax,rdx; jmp rax; ret; ret: 14 bytes, the returns at 12 and 13.
std::vector<std::byte> table_user(uint32_t table) {
    auto code = bytes_of({0x8b, 0x84, 0x8a});
    append_dword(code, table);
    const auto rest = bytes_of({0x48, 0x01, 0xd0, 0xff, 0xe0, 0xc3, 0xc3});
    code.insert(code.end(), rest.begin(), rest.end());
    return code;
}

constexpr uint32_t kTextAt = 0x1000;
constexpr uint32_t kDataAt = 0x4000;

struct Piece {
    compat_test::FunctionSpec function;
    std::vector<std::byte> code;
};

Image image_of(const std::vector<Piece>& pieces, const std::vector<std::byte>& data = {}) {
    compat_test::PeSpec spec;
    std::vector<std::byte> text(0x2000, std::byte{0xcc});
    for (const Piece& piece : pieces) {
        std::ranges::copy(piece.code, text.begin() + (piece.function.begin - kTextAt));
        spec.functions.push_back(piece.function);
    }
    spec.sections.emplace_back(".text", kTextAt, text, 0);
    if (!data.empty()) {
        spec.sections.emplace_back(".rdata", kDataAt, data, 0);
    }
    auto image = livemap::compat::load_image(compat_test::build_pe(spec));
    if (!image) {
        std::cout << "the test image does not load: " << image.error() << "\n";
        std::exit(2);
    }
    return std::move(*image);
}

bool zeroed(const Instruction& insn, size_t from, size_t count) {
    return std::ranges::all_of(std::span(insn.bytes).subspan(from, count), [](std::byte b) { return b == std::byte{0}; });
}

void check_normalizing(compat_test::Suite& t) {
    const auto call = decode_all(bytes_of({0xe8, 0x10, 0x20, 0x30, 0x00}));
    t.check(call.size() == 1 && call[0].length == 5 && call[0].relative, "call rel32 decodes as a relative branch");
    t.check(call.size() == 1 && call[0].target == 0x1000 + 5 + 0x302010, "its target is the next address plus the displacement");
    t.check(call.size() == 1 && call[0].bytes[0] == kCallOpcode && zeroed(call[0], 1, 4), "the opcode stays and the displacement is zeroed");

    const auto back = decode_all(bytes_of({0xeb, 0xfe}));
    t.check(back.size() == 1 && back[0].relative && back[0].target == 0x1000, "jmp rel8 to itself, a negative displacement");
    const auto near_jcc = decode_all(bytes_of({0x0f, 0x84, 0x00, 0x01, 0x00, 0x00}));
    t.check(near_jcc.size() == 1 && near_jcc[0].relative && near_jcc[0].target == 0x1000 + 6 + 0x100 && zeroed(near_jcc[0], 2, 4), "jcc rel32");
    const auto short_jcc = decode_all(bytes_of({0x74, 0x05}));
    t.check(short_jcc.size() == 1 && short_jcc[0].relative && short_jcc[0].target == 0x1007 && zeroed(short_jcc[0], 1, 1), "jcc rel8");

    const auto load = decode_all(bytes_of({0x48, 0x8b, 0x05, 0x44, 0x33, 0x22, 0x11}));
    t.check(load.size() == 1 && !load[0].relative, "a RIP-relative load is no branch");
    t.check(load.size() == 1 && zeroed(load[0], 3, 4) && load[0].bytes[0] == std::byte{0x48}, "its displacement is zeroed and the rest stays");

    const auto compare = decode_all(bytes_of({0x48, 0x81, 0x3d, 0x01, 0x02, 0x03, 0x04, 0x78, 0x56, 0x34, 0x12}));
    t.check(compare.size() == 1 && !compare[0].relative && zeroed(compare[0], 3, 4), "RIP-relative displacement before an immediate is zeroed");
    t.check(compare.size() == 1 && compare[0].bytes[7] == std::byte{0x78} && compare[0].bytes[10] == std::byte{0x12}, "the immediate after it stays");

    const auto add = decode_all(bytes_of({0x48, 0x83, 0xc0, 0x05}));
    t.check(add.size() == 1 && add[0].bytes[3] == std::byte{5}, "an immediate that is no branch target stays");
    const auto indirect = decode_all(bytes_of({0xff, 0x25, 0x01, 0x02, 0x03, 0x04}));
    t.check(indirect.size() == 1 && !indirect[0].relative && zeroed(indirect[0], 2, 4), "an indirect jmp through RIP has no target but a masked slot");
    const auto plain = decode_all(bytes_of({0x8b, 0x88, 0x30, 0x08, 0x00, 0x00}));
    t.check(plain.size() == 1 && plain[0].bytes[2] == std::byte{0x30}, "a displacement from a register stays");
}

void check_operand_masks(compat_test::Suite& t) {
    const std::array<livemap::compat::Range, 1> masks = {{{0x1002, 4}}};
    const auto masked = decode_at(bytes_of({0x8b, 0x88, 0x30, 0x08, 0x00, 0x00, 0xc3}), 0x1000, masks).code.instructions;
    t.check(masked.size() == 2 && zeroed(masked[0], 2, 4) && masked[0].bytes[0] == std::byte{0x8b}, "an operand range is zeroed");
    t.check(masked.size() == 2 && masked[1].bytes[0] == std::byte{0xc3}, "an instruction outside the range is untouched");
}

void check_decode_function(compat_test::Suite& t) {
    const auto good = decode_at(bytes_of({0x90, 0x48, 0x89, 0xc8, 0xc3}), 0x2000);
    const auto& stream = good.code.instructions;
    t.check(!good.stopped && stream.size() == 3 && stream[1].rva == 0x2001 && stream[2].rva == 0x2004, "instructions carry their RVA");
    t.check(good.code.range.begin == 0x2000 && good.code.range.end == 0x2005 && good.code.tables.empty(), "the code keeps its range and holds no table");
    const auto invalid = decode_at(bytes_of({0x90, 0x06, 0xc3}), 0x2000);
    t.check(invalid.stopped == 0x2001U && invalid.code.instructions.size() == 1, "an invalid opcode names the RVA it stops at and keeps what came before");
    const auto cut = decode_at(bytes_of({0x90, 0xe8, 0x01}), 0x2000);
    t.check(cut.stopped == 0x2001U, "an instruction cut by the end of the range is a failure");
}

void check_hook_span(compat_test::Suite& t) {
    const auto code = decode_all(bytes_of({0x4c, 0x8b, 0xd1, 0x48, 0x83, 0xec, 0x28, 0x90, 0x48, 0x89, 0x5c, 0x24, 0x20, 0xc3}));
    t.check(livemap::compat::hook_span(code, 0x1000) == 7U, "3 + 4 bytes: whole instructions until 5 bytes are covered");
    t.check(livemap::compat::hook_span(code, 0x1003) == 5U, "4 + 1 bytes cover 5");
    t.check(livemap::compat::hook_span(code, 0x1008) == 5U, "one 5-byte instruction");
    t.check(!livemap::compat::hook_span(code, 0x1001).has_value(), "a site inside an instruction is not aligned");
    t.check(!livemap::compat::hook_span(code, 0x1d).has_value(), "a site outside the stream");
    t.check(!livemap::compat::hook_span(code, 0x100d).has_value(), "the stream ends before 5 bytes are covered");

    const Switch tail{.late_returns = 5};
    const auto gapped = decode_all(switch_function(0x1000, tail));
    t.check(!livemap::compat::hook_span(gapped, 0x100d).has_value() && !livemap::compat::hook_span(gapped, 0x100c).has_value(), "the bytes of a table between the instructions end the span");
    t.check(livemap::compat::hook_span(gapped, 0x1000 + table_offset(tail) + 12) == 5U, "a span that starts after the table is whole");
}

void check_compare(compat_test::Suite& t) {
    const auto base = bytes_of({0x48, 0x83, 0xec, 0x28, 0xe8, 0x00, 0x01, 0x00, 0x00, 0x74, 0x02, 0x90, 0x90, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xc3});
    const Code before = code_of(base, 0x1000);
    t.check(!livemap::compat::compare_code(before, before).has_value(), "a function equals itself");

    auto moved = base;
    moved[5] = std::byte{0x77};
    moved[16] = std::byte{0x99};
    t.check(!livemap::compat::compare_code(code_of(moved, 0x5000), before).has_value(), "another function address, call target and data reference still compare equal");

    auto immediate = base;
    immediate[3] = std::byte{0x30};
    const auto changed = livemap::compat::compare_code(code_of(immediate, 0x5000), before);
    t.check(changed && changed->kind == "bytes" && changed->rva == 0x5000 && changed->base_rva == 0x1000, "a changed immediate is a difference at that instruction");

    auto jump = base;
    jump[10] = std::byte{0x03};
    const auto retarget = livemap::compat::compare_code(code_of(jump), before);
    t.check(retarget && retarget->kind == "branch" && retarget->rva == 0x1009, "a branch that stays inside the function but lands elsewhere");

    auto outside = base;
    outside[10] = std::byte{0x40};
    const auto leaves = livemap::compat::compare_code(code_of(outside), before);
    t.check(leaves && leaves->kind == "branch", "a branch that now leaves the function");

    auto longer = base;
    longer.push_back(std::byte{0x90});
    const auto grown = livemap::compat::compare_code(code_of(longer), before);
    t.check(grown && grown->kind == "length", "an extra instruction");
    const auto shrunk = livemap::compat::compare_code(before, code_of(longer));
    t.check(shrunk && shrunk->kind == "length", "a missing instruction");
}

void check_branch_map(compat_test::Suite& t) {
    compat_test::PeSpec spec;
    spec.size_of_image = 0x10000;
    auto first = bytes_of({0xe8, 0x1f, 0x00, 0x00, 0x00, 0xc3, 0xcc, 0xcc});
    first.resize(0x20, std::byte{0xcc});
    auto second = bytes_of({0xeb, 0x03, 0x74, 0x00, 0x90, 0xc3});
    auto broken = bytes_of({0x90, 0x06, 0xc3});
    std::vector<std::byte> text = first;
    text.insert(text.end(), second.begin(), second.end());
    text.resize(0x40, std::byte{0xcc});
    text.insert(text.end(), broken.begin(), broken.end());
    spec.sections.emplace_back(".text", 0x1000, text, 0);
    spec.functions = {{0x1000, 0x1008}, {0x1020, 0x1026}, {0x1040, 0x1043}};
    const auto image = livemap::compat::load_image(compat_test::build_pe(spec));
    t.check(image.has_value(), "the synthetic image loads");
    if (!image) {
        return;
    }
    const Decoder decoder;
    const auto map = livemap::compat::collect_branches(*image, decoder);
    t.check(map.stopped.size() == 1 && map.stopped[0].begin == 0x1040 && map.stopped[0].end == 0x1043, "the function that stops decoding is listed");
    t.check(map.branches.size() == 3, "one call and two jumps");
    t.check(std::ranges::is_sorted(map.branches, {}, &Branch::target), "branches are sorted by target");
    const auto inside = livemap::compat::landings(map, 0x1020, 0x1030);
    t.check(inside.size() == 3 && std::ranges::any_of(inside, [](const Branch& b) { return b.from == 0x1000 && b.target == 0x1024; }), "a call from another function lands in the span");
    t.check(livemap::compat::landings(map, 0x1024, 0x1025).empty(), "targets on the span's first or last byte are no landings");
    t.check(livemap::compat::landings(map, 0x1023, 0x1026).size() == 3, "targets one byte inside both ends count");
    t.check(livemap::compat::landings(map, 0x1030, 0x1020).empty(), "an inverted range holds nothing");
}

void check_jump_tables(compat_test::Suite& t) {
    const Switch plain;
    const auto bytes = switch_function(0x1000, plain);
    const auto decoded = decode_at(bytes);
    const auto& stream = decoded.code.instructions;
    t.check(!decoded.stopped, "a function that ends in a jump table decodes");
    t.check(stream.size() == 5 && stream.back().rva == 0x100d, "the table is not decoded as code");
    t.check(decoded.code.tables.size() == 1 && decoded.code.tables[0].rva == 0x100e && decoded.code.tables[0].ref == 0x1000, "the table is found where the load points, with the load that reads it");
    t.check(decoded.code.tables.size() == 1 && decoded.code.tables[0].entries == std::vector<uint32_t>({0x100c, 0x100d, 0x100c}), "its entries are the addresses it holds");
    t.check(!stream.empty() && stream[0].table_ref && stream[0].target == 0x100e && zeroed(stream[0], 3, 4) && stream[0].bytes[0] == std::byte{0x8b}, "the load keeps its opcode and loses the table address");
    t.check(stream.size() > 1 && !stream[1].table_ref, "an instruction that reads no table is no table reference");

    const auto high = decode_at(switch_function(0x01234000, plain), 0x01234000);
    t.check(!high.stopped && high.code.tables.size() == 1 && high.code.tables[0].rva == 0x0123400e && high.code.tables[0].entries == std::vector<uint32_t>({0x0123400c, 0x0123400d, 0x0123400c}),
            "addresses of any size are read whole");
    t.check(!high.code.instructions.empty() && high.code.instructions[0].target == 0x0123400e && zeroed(high.code.instructions[0], 3, 4), "and the whole address is cleared from the load");

    const Switch twice{.loads = 2};
    const auto shared = decode_at(switch_function(0x1000, twice));
    t.check(!shared.stopped && shared.code.tables.size() == 1 && shared.code.tables[0].ref == 0x1000 && shared.code.instructions[1].table_ref, "loads of one table share it");

    const Switch inside{.late_returns = 4};
    const auto middle = decode_at(switch_function(0x1000, inside));
    t.check(!middle.stopped && middle.code.instructions.size() == 9 && middle.code.instructions.back().rva == 0x1000 + table_offset(inside) + 12 + 3, "decoding goes on after a table in the middle of a function");
    t.check(middle.code.tables.size() == 1 && middle.code.tables[0].entries.size() == 3, "and the table ends at the first word that is no address of the function");

    const Switch overlapping{.loads = 2, .skew = 4};
    const auto overlap = decode_at(switch_function(0x1000, overlapping));
    t.check(overlap.stopped == 0x1007U, "a load that reads a table from the middle of another one stops decoding at that load");

    for (const auto& [first, second] : {std::pair{0x10U, 0x18U}, std::pair{0x18U, 0x10U}}) {
        const auto separate = decode_at(bytes_of({0x8b, 0x84, 0x8a, first, 0x10, 0x00, 0x00, 0x8b, 0x84, 0x8a, second, 0x10, 0x00, 0x00, 0xc3, 0xcc, 0x0e, 0x10, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x0e, 0x10, 0x00, 0x00}));
        t.check(!separate.stopped && separate.code.tables.size() == 2 && separate.code.tables[1].rva == 0x1010 + 0x18 - first && separate.code.instructions.size() == 8, "two tables in one function, in either order");
    }

    const auto outside = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x01, 0x90, 0x00, 0x00, 0xc3}));
    t.check(!outside.stopped && outside.code.tables.empty() && outside.code.instructions[0].bytes[4] == std::byte{0x90}, "an indexed load from outside the function reads no table");
    const auto unindexed = decode_at(bytes_of({0x8b, 0x04, 0xa5, 0x08, 0x10, 0x00, 0x00, 0xc3, 0x0b, 0x10, 0x00, 0x00}));
    t.check(!unindexed.stopped && unindexed.code.tables.empty() && !unindexed.code.instructions[0].table_ref, "an absolute address read through a scale without an index reads no table");
    const auto address_only = decode_at(bytes_of({0x8d, 0x84, 0x8a, 0x08, 0x10, 0x00, 0x00, 0xc3, 0x0b, 0x10, 0x00, 0x00}));
    t.check(!address_only.stopped && address_only.code.tables.empty(), "an address computed with lea reads nothing");
    const auto itself = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x03, 0x10, 0x00, 0x00, 0xc3}));
    t.check(!itself.stopped && itself.code.tables.empty() && !itself.code.instructions[0].table_ref, "a load whose address lies at or before its own end reads no table");
    const auto inside_load = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x06, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0xc3}));
    t.check(!inside_load.stopped && inside_load.code.tables.empty(), "a load whose address is its own last byte reads no table");
    const auto empty = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x07, 0x10, 0x00, 0x00, 0xc3}));
    t.check(!empty.stopped && empty.code.tables.empty(), "an address with too few bytes left for an entry reads no table");
    const auto at_end = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x08, 0x10, 0x00, 0x00, 0xc3, 0x0c, 0x10, 0x00, 0x00}));
    t.check(!at_end.stopped && at_end.code.tables.empty(), "the end of the function is no entry");
    const auto before_start = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x08, 0x10, 0x00, 0x00, 0xc3, 0xff, 0x0f, 0x00, 0x00}));
    t.check(!before_start.stopped && before_start.code.tables.empty(), "an address before the function is no entry");
    const auto at_start = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x08, 0x10, 0x00, 0x00, 0xc3, 0x00, 0x10, 0x00, 0x00}));
    t.check(!at_start.stopped && at_start.code.tables.size() == 1 && at_start.code.tables[0].entries == std::vector<uint32_t>({0x1000}), "the first byte of the function is an entry");
    for (const unsigned sib : {0x0aU, 0x4aU, 0xcaU}) {
        const auto scaled = decode_at(bytes_of({0x8b, 0x84, sib, 0x08, 0x10, 0x00, 0x00, 0xc3, 0x0b, 0x10, 0x00, 0x00}));
        t.check(!scaled.stopped && scaled.code.tables.empty() && !scaled.code.instructions[0].table_ref, "only a scale of 4 marks a table");
    }
    const auto straddling = decode_at(bytes_of({0x8b, 0x84, 0x8a, 0x08, 0x10, 0x00, 0x00, 0xb8, 0x0c, 0x10, 0x00, 0x00, 0xc3}));
    t.check(straddling.stopped == 0x1000U, "a table that starts inside another instruction stops decoding at the load");
}

void check_compare_tables(compat_test::Suite& t) {
    const Switch plain;
    const Code before = code_of(switch_function(0x1000, plain));
    t.check(!livemap::compat::compare_code(before, before).has_value(), "a function with a table equals itself");
    t.check(!livemap::compat::compare_code(code_of(switch_function(0x5000, plain), 0x5000), before).has_value(), "the same function elsewhere compares equal, whatever addresses its table holds");

    const Switch swapped{.cases = {1, 0, 0}};
    const auto other_entry = livemap::compat::compare_code(code_of(switch_function(0x1000, swapped)), before);
    t.check(other_entry && other_entry->kind == "table" && other_entry->rva == 0x100e && other_entry->base_rva == 0x100e, "an entry that picks another place is a difference in the table");
    const Switch shorter{.cases = {0, 1}};
    const auto fewer = livemap::compat::compare_code(code_of(switch_function(0x1000, shorter)), before);
    t.check(fewer && fewer->kind == "table", "a table with fewer entries");
    const auto more = livemap::compat::compare_code(before, code_of(switch_function(0x1000, shorter)));
    t.check(more && more->kind == "table", "a table with more entries");

    const Switch late{.late_returns = 1};
    const Switch early{.early_returns = 1};
    const auto moved_table = livemap::compat::compare_code(code_of(switch_function(0x1000, early)), code_of(switch_function(0x1000, late)));
    t.check(moved_table && moved_table->kind == "branch" && moved_table->rva == 0x1000, "the same instructions with the table in another place");

    const Code without = code_of(bytes_of({0x8b, 0x84, 0x8a, 0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0xd0, 0xff, 0xe0, 0xc3, 0xc3}));
    const auto lost = livemap::compat::compare_code(without, before);
    t.check(lost && lost->kind == "bytes" && lost->rva == 0x1000, "a load that reads a table in one build and none in the other");

    Code table_lacking = before;
    table_lacking.tables.clear();
    const auto missing = livemap::compat::compare_code(table_lacking, before);
    t.check(missing && missing->kind == "table", "a table that one of the two lacks");
}

void check_branch_map_tables(compat_test::Suite& t) {
    compat_test::PeSpec spec;
    spec.size_of_image = 0x10000;
    const Switch plain;
    auto text = switch_function(0x1000, plain);
    const auto length = static_cast<uint32_t>(text.size());
    spec.sections.emplace_back(".text", 0x1000, text, 0);
    spec.functions = {{0x1000, 0x1000 + length}};
    const auto image = livemap::compat::load_image(compat_test::build_pe(spec));
    t.check(image.has_value(), "the image with a switch loads");
    if (!image) {
        return;
    }
    const Decoder decoder;
    const auto map = livemap::compat::collect_branches(*image, decoder);
    t.check(map.stopped.empty(), "a function that ends in a table is decodable");
    t.check(map.branches.size() == 3, "each entry of the table is a branch");
    t.check(std::ranges::all_of(map.branches, [](const Branch& b) { return b.from == 0x1000; }), "from the load that reads the table");
    t.check(livemap::compat::landings(map, 0x100b, 0x100d).size() == 2, "the entries count as landings strictly inside a span");
    t.check(livemap::compat::landings(map, 0x100c, 0x100e).size() == 1, "and the ends of the span do not");
}

void check_branch_map_reach(compat_test::Suite& t) {
    const Decoder decoder;
    const Piece user{{0x1000, 0x100e}, table_user(0x1100)};
    const std::vector<uint32_t> returns{0x100c, 0x100d, 0x100c};
    const auto targets = [](const livemap::compat::BranchMap& map) {
        std::vector<int64_t> out;
        std::ranges::transform(map.branches, std::back_inserter(out), &Branch::target);
        return out;
    };

    const auto beside = livemap::compat::collect_branches(image_of({user, Piece{{0x1100, 0x1110}, dwords({0x100c, 0x100d, 0x100c})}}), decoder);
    t.check(beside.stopped.empty() && targets(beside) == std::vector<int64_t>({0x100c, 0x100c, 0x100d}), "a table in another function is read, and that function is decoded around it");
    t.check(std::ranges::all_of(beside.branches, [](const Branch& b) { return b.from == 0x1000; }), "from the load that reads it");

    const auto in_data = livemap::compat::collect_branches(image_of({Piece{{0x1000, 0x100e}, table_user(kDataAt)}}, dwords({0x100c, 0x100d, 0x100c})), decoder);
    t.check(in_data.stopped.empty() && in_data.branches.size() == 3, "a table outside .text is read");

    const std::vector chain{Piece{{0x1000, 0x100e}, table_user(kDataAt)}, Piece{{0x1200, 0x1210, 0x1000}, {}}, Piece{{0x1300, 0x1310}, {}}};
    const auto in_chunk = livemap::compat::collect_branches(image_of(chain, dwords({0x100c, 0x1204, 0x1304, 0x100d})), decoder);
    t.check(targets(in_chunk) == std::vector<int64_t>({0x100c, 0x1204}), "entries may land in a chunk of the function, and the table ends at the first that lands anywhere else");

    auto early = std::vector<std::byte>(0x10, std::byte{0xcc});
    const auto entries = dwords({0x2006, 0x2012, 0x2013});
    early.insert(early.end(), entries.begin(), entries.end());
    const auto reread = livemap::compat::collect_branches(image_of({Piece{{0x1000, 0x1020}, early}, Piece{{0x2006, 0x2014}, table_user(0x1010)}}), decoder);
    t.check(reread.stopped.empty() && reread.branches.size() == 3, "a function decoded before its table was found is decoded again around it");

    const auto reads = [](uint32_t table) {
        auto load = bytes_of({0x8b, 0x84, 0x8a});
        append_dword(load, table);
        return load;
    };
    const auto tail = bytes_of({0x48, 0x01, 0xd0, 0xff, 0xe0, 0xc3, 0xc3});
    for (const auto& [first, second] : {std::pair{kDataAt, kDataAt + 4}, std::pair{kDataAt + 4, kDataAt}}) {
        auto twin = reads(first);
        const auto other = reads(second);
        twin.insert(twin.end(), other.begin(), other.end());
        twin.insert(twin.end(), tail.begin(), tail.end());
        const auto crossed = livemap::compat::collect_branches(image_of({Piece{{0x1000, 0x1015}, twin}}, dwords({0x1013, 0x1014, 0x1013, 0x1014})), decoder);
        t.check(crossed.stopped.size() == 1 && crossed.stopped[0].begin == 0x1000, "a load of a table from the middle of another one stops the function that holds it, whichever is read first");
    }

    const auto nowhere = livemap::compat::collect_branches(image_of({Piece{{0x1000, 0x100e}, table_user(0x7ffffff0)}}), decoder);
    t.check(nowhere.stopped.empty() && nowhere.branches.empty(), "an address outside the image reads no table");

    std::vector<std::byte> cut = bytes_of({0xb8});
    const auto inside_entries = dwords({0x200c, 0x200d, 0x200c});
    cut.insert(cut.end(), inside_entries.begin(), inside_entries.end());
    const auto straddled = livemap::compat::collect_branches(image_of({Piece{{0x1000, 0x1010}, cut}, Piece{{0x2000, 0x200e}, table_user(0x1001)}}), decoder);
    t.check(straddled.stopped.size() == 1 && straddled.stopped[0].begin == 0x1000, "a table that starts inside an instruction stops the function with that instruction");
}

std::vector<std::byte> jump_to(uint32_t from, uint32_t target) {
    auto code = bytes_of({0xe9});
    append_dword(code, target - (from + 5));
    return code;
}

void check_stopped_near(compat_test::Suite& t) {
    const Decoder decoder;
    const auto broken = bytes_of({0x90, 0x06});
    const auto fine = bytes_of({0x90, 0xc3});
    const Function range{0x1000, 0x1010};
    const auto near = [&](const std::vector<std::byte>& site_code, const std::vector<Piece>& more) {
        std::vector pieces{Piece{{0x1000, 0x1010}, site_code}};
        pieces.insert(pieces.end(), more.begin(), more.end());
        const Image image = image_of(pieces);
        return livemap::compat::stopped_near(livemap::compat::collect_branches(image, decoder), image, range);
    };
    t.check(!near(fine, {}), "nothing that stops is nothing near the site");
    t.check(near(broken, {}), "the function of the site itself, when it stops");
    t.check(!near(fine, {Piece{{0x1200, 0x1210}, broken}}), "a function that stops and has no tie to the site");
    t.check(near(fine, {Piece{{0x1200, 0x1210, 0x1000}, broken}}), "a chunk of the site's function that stops");
    t.check(near(fine, {Piece{{0x1200, 0x1210, 0x1000}, fine}, Piece{{0x1300, 0x1310, 0x1200}, broken}}), "also a chunk of a chunk");
    t.check(!near(fine, {Piece{{0x1200, 0x1210, 0x1000}, fine}}), "a chunk that decodes to its end");

    t.check(!near(fine, {Piece{{0x1100, 0x1110}, broken}, Piece{{0x1200, 0x1210}, jump_to(0x1200, 0x1004)}}), "a jump into the site from a function that decodes to its end, past one that stops");
    auto into = jump_to(0x1200, 0x1004);
    into.push_back(std::byte{0x06});
    t.check(near(fine, {Piece{{0x1200, 0x1210}, into}}), "a function that stops after a jump into the site");
    auto to_begin = jump_to(0x1200, 0x1000);
    to_begin.push_back(std::byte{0x06});
    t.check(!near(fine, {Piece{{0x1200, 0x1210}, to_begin}}), "a jump to the first byte of the site is a call of the function, not a tie");
    auto past = jump_to(0x1200, 0x1010);
    past.push_back(std::byte{0x06});
    t.check(!near(fine, {Piece{{0x1200, 0x1210}, past}}), "nor is a jump past its end");
    auto tabled = table_user(kDataAt);
    tabled.push_back(std::byte{0x06});
    const auto by_table = livemap::compat::collect_branches(image_of({Piece{{0x1000, 0x1010}, fine}, Piece{{0x1200, 0x120f}, tabled}}, dwords({0x1004, 0x1004})), decoder);
    t.check(by_table.stopped.size() == 1, "the table of a function that stops is read as far as it goes");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_normalizing(t);
    check_operand_masks(t);
    check_decode_function(t);
    check_jump_tables(t);
    check_hook_span(t);
    check_compare(t);
    check_compare_tables(t);
    check_branch_map(t);
    check_branch_map_tables(t);
    check_branch_map_reach(t);
    check_stopped_near(t);
    return t.result();
}
