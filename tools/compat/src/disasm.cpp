#include "disasm.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <map>
#include <numeric>
#include <set>
#include <utility>
#include <vector>

namespace livemap::compat {

namespace {

void zero_bytes(Instruction& insn, size_t offset, size_t count) {
    for (size_t i = offset; i < offset + count && i < insn.length; ++i) {
        insn.bytes[i] = std::byte{0};
    }
}

void zero_masked(Instruction& insn, std::span<const Range> masks) {
    for (const Range& mask : masks) {
        for (uint64_t rva = std::max<uint64_t>(mask.rva, insn.rva); rva < std::min<uint64_t>(uint64_t{mask.rva} + mask.length, uint64_t{insn.rva} + insn.length); ++rva) {
            insn.bytes[rva - insn.rva] = std::byte{0};
        }
    }
}

constexpr uint32_t kEntryLength = 4;
constexpr uint8_t kTableScale = 4;

uint32_t dword_at(std::span<const std::byte> bytes, size_t offset) {
    uint32_t value = 0;
    for (size_t i = 0; i < kEntryLength; ++i) {
        value |= std::to_integer<uint32_t>(bytes[offset + i]) << (8U * i);
    }
    return value;
}

std::optional<IndexedLoad> indexed_load(const ZydisDecodedInstruction& decoded, std::span<const ZydisDecodedOperand> operands) {
    const auto visible = operands.first(decoded.operand_count_visible);
    const auto scaled = std::ranges::find_if(visible, [](const ZydisDecodedOperand& operand) {
        return operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.type == ZYDIS_MEMOP_TYPE_MEM && operand.mem.scale == kTableScale;
    });
    if (scaled == visible.end()) {
        return std::nullopt;
    }
    return IndexedLoad{decoded.raw.disp.offset, scaled->mem.disp.value};
}

constexpr uint16_t kWholeRegisterBits = 32;

Registers general_register(ZydisRegister reg) {
    const ZydisRegister whole = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
    if (whole < ZYDIS_REGISTER_RAX || whole > ZYDIS_REGISTER_R15) {
        return 0;
    }
    return register_bit(static_cast<size_t>(whole - ZYDIS_REGISTER_RAX));
}

// xor and sub of a register with itself give zero whatever the register held.
bool is_zeroing(const ZydisDecodedInstruction& decoded, std::span<const ZydisDecodedOperand> operands) {
    if (decoded.mnemonic != ZYDIS_MNEMONIC_XOR && decoded.mnemonic != ZYDIS_MNEMONIC_SUB) {
        return false;
    }
    const auto visible = operands.first(decoded.operand_count_visible);
    return visible.size() == 2 && visible[0].type == ZYDIS_OPERAND_TYPE_REGISTER && visible[1].type == ZYDIS_OPERAND_TYPE_REGISTER && visible[0].reg.value == visible[1].reg.value;
}

void note_effects(Instruction& insn, const ZydisDecodedInstruction& decoded, std::span<const ZydisDecodedOperand> operands) {
    const bool zeroing = is_zeroing(decoded, operands);
    for (const ZydisDecodedOperand& operand : operands.first(decoded.operand_count)) {
        if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            insn.reads |= general_register(operand.mem.base) | general_register(operand.mem.index);
        } else if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const Registers bit = general_register(operand.reg.value);
            if ((operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0 && !zeroing) {
                insn.reads |= bit;
            }
            if ((operand.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0 && operand.size >= kWholeRegisterBits) {
                insn.kills |= bit;
            }
        }
    }
}

Flow flow_of(const ZydisDecodedInstruction& decoded, std::span<const ZydisDecodedOperand> operands) {
    using enum Flow;
    switch (decoded.mnemonic) {
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_UD2:
        case ZYDIS_MNEMONIC_HLT:
            return Stop;
        default:
            break;
    }
    switch (decoded.meta.category) {
        case ZYDIS_CATEGORY_CALL:
            return Call;
        case ZYDIS_CATEGORY_RET:
            return Return;
        case ZYDIS_CATEGORY_COND_BR:
            return Branch;
        case ZYDIS_CATEGORY_UNCOND_BR:
            return operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ? Jump : Indirect;
        default:
            return Next;
    }
}

bool same_encoding(const Instruction& a, const Instruction& b) {
    return a.length == b.length && a.relative == b.relative && a.table_ref == b.table_ref && a.bytes == b.bytes;
}

bool inside(const Function& range, int64_t target) {
    return target >= range.begin && target < range.end;
}

// Whether two branches of the same encoding do the same: both leave their code, or both land at the same offset into it.
bool same_branch(const Instruction& now, const Function& now_range, const Instruction& before, const Function& before_range) {
    const bool stays = inside(now_range, now.target);
    if (stays != inside(before_range, before.target)) {
        return false;
    }
    return !stays || now.target - now_range.begin == before.target - before_range.begin;
}

// The table that `load` reads, when its address lies ahead of the load and holds addresses of the function.
std::optional<Table> read_table(std::span<const std::byte> bytes, const Function& range, const Instruction& load) {
    const int64_t address = load.indexed->address;
    if (address < int64_t{load.rva} + load.length) {
        return std::nullopt;
    }
    Table table;
    table.rva = static_cast<uint32_t>(address);
    table.ref = load.rva;
    for (size_t offset = table.rva - range.begin; offset + kEntryLength <= bytes.size(); offset += kEntryLength) {
        const uint32_t entry = dword_at(bytes, offset);
        if (!inside(range, entry)) {
            break;
        }
        table.entries.push_back(entry);
    }
    if (table.entries.empty()) {
        return std::nullopt;
    }
    return table;
}

bool collide(const Table& a, const Table& b) {
    return a.rva != b.rva && a.rva < b.rva + b.entries.size() * kEntryLength && b.rva < a.rva + a.entries.size() * kEntryLength;
}

// Marks `load` as a reference to the table it reads and records the table. False when the table overlaps another one.
bool note_table(std::vector<Table>& tables, std::span<const std::byte> bytes, const Function& range, Instruction& load) {
    if (!load.indexed) {
        return true;
    }
    auto table = read_table(bytes, range, load);
    if (!table) {
        return true;
    }
    if (const auto collides = [&](const Table& other) {
            return collide(other, *table);
        };
        std::ranges::any_of(tables, collides)) {
        return false;
    }
    if (std::ranges::find(tables, table->rva, &Table::rva) == tables.end()) {
        tables.push_back(*table);
    }
    load.table_ref = true;
    load.target = table->rva;
    zero_bytes(load, load.indexed->offset, kEntryLength);
    return true;
}

bool crosses(const Table& table, const Instruction& insn) {
    return table.rva > insn.rva && table.rva < insn.rva + insn.length;
}

// Decodes the instruction at `rva` into `out` and returns the address after it. Sets out.stopped when the code cannot be followed.
uint32_t step(const Decoder& decoder, std::span<const std::byte> bytes, std::span<const Range> masks, Decoded& out, uint32_t rva) {
    const Function& range = out.code.range;
    auto insn = decoder.decode(bytes.subspan(rva - range.begin), rva, masks);
    if (!insn) {
        out.stopped = rva;
        return rva;
    }
    const auto crossing = [&](const Table& table) { return crosses(table, *insn); };
    if (const auto crossed = std::ranges::find_if(out.code.tables, crossing); crossed != out.code.tables.end()) {
        out.stopped = crossed->ref;
        return rva;
    }
    if (!note_table(out.code.tables, bytes, range, *insn)) {
        out.stopped = rva;
        return rva;
    }
    out.code.instructions.push_back(*insn);
    return rva + insn->length;
}

bool same_table(const Table& now, const Function& now_range, const Table& before, const Function& before_range) {
    return std::ranges::equal(now.entries, before.entries, {}, [&](uint32_t entry) { return entry - now_range.begin; }, [&](uint32_t entry) { return entry - before_range.begin; });
}

std::optional<Difference> compare_tables(const Code& now, const Code& before) {
    if (now.tables.size() != before.tables.size()) {
        return Difference{"table", now.range.end, before.range.end};
    }
    for (size_t i = 0; i < now.tables.size(); ++i) {
        if (!same_table(now.tables[i], now.range, before.tables[i], before.range)) {
            return Difference{"table", now.tables[i].rva, before.tables[i].rva};
        }
    }
    return std::nullopt;
}

using TableMap = std::map<uint32_t, Table>;

uint64_t table_end(const Table& table) {
    return uint64_t{table.rva} + table.entries.size() * kEntryLength;
}

const Table* table_covering(const TableMap& tables, uint32_t rva) {
    const auto next = tables.upper_bound(rva);
    if (next == tables.begin()) {
        return nullptr;
    }
    const Table& candidate = std::prev(next)->second;
    return rva < table_end(candidate) ? &candidate : nullptr;
}

bool starts_inside(const TableMap& tables, const Instruction& insn) {
    const auto next = tables.upper_bound(insn.rva);
    return next != tables.end() && next->first < uint64_t{insn.rva} + insn.length;
}

struct Scan {
    std::vector<Instruction> instructions;
    bool stopped = false;
};

// The instructions of a function around the tables found so far.
Scan scan_function(const Decoder& decoder, std::span<const std::byte> bytes, const Function& range, const TableMap& tables) {
    Scan scan;
    uint32_t rva = range.begin;
    while (rva < range.end && !scan.stopped) {
        if (const Table* table = table_covering(tables, rva); table != nullptr) {
            rva = static_cast<uint32_t>(table_end(*table));
            continue;
        }
        const auto insn = decoder.decode(bytes.subspan(rva - range.begin), rva, {});
        scan.stopped = !insn || starts_inside(tables, *insn);
        if (!scan.stopped) {
            scan.instructions.push_back(*insn);
            rva += insn->length;
        }
    }
    return scan;
}

// The table `load` reads: the words from its address on that are addresses in the chain `root` heads.
std::optional<Table> read_chain_table(const Image& image, uint32_t root, const Instruction& load) {
    const int64_t address = load.indexed->address;
    if (address <= 0) {
        return std::nullopt;
    }
    Table table;
    table.rva = static_cast<uint32_t>(address);
    table.ref = load.rva;
    for (uint64_t at = table.rva; !image.at(at, kEntryLength).empty(); at += kEntryLength) {
        const uint32_t entry = dword_at(image.at(at, kEntryLength), 0);
        if (image.chain_root(entry) != root) {
            break;
        }
        table.entries.push_back(entry);
    }
    if (table.entries.empty()) {
        return std::nullopt;
    }
    return table;
}

bool overlaps_known(const TableMap& tables, const Table& table) {
    const auto next = tables.upper_bound(table.rva);
    const bool over_next = next != tables.end() && next->first < table_end(table);
    const bool over_previous = next != tables.begin() && table_end(std::prev(next)->second) > table.rva;
    return over_next || over_previous;
}

// The indexes of the functions that hold any of the bytes [low, high).
std::set<size_t> functions_touching(const std::vector<Function>& functions, uint64_t low, uint64_t high) {
    std::set<size_t> touched;
    auto at = static_cast<size_t>(std::ranges::upper_bound(functions, low, {}, &Function::begin) - functions.begin());
    if (at > 0 && functions[at - 1].end > low) {
        --at;
    }
    for (; at < functions.size() && functions[at].begin < high; ++at) {
        touched.insert(at);
    }
    return touched;
}

bool within(const std::vector<Function>& sorted, uint32_t rva) {
    const auto next = std::ranges::upper_bound(sorted, rva, {}, &Function::begin);
    return next != sorted.begin() && rva < std::prev(next)->end;
}

struct Discovery {
    TableMap tables;
    std::vector<Scan> scans;
    std::vector<bool> conflicted;
};

// Adds the tables that the indexed loads of one function read; returns the functions that hold bytes of a new table.
std::set<size_t> add_tables(const Image& image, size_t index, Discovery& found) {
    const uint32_t begin = image.functions()[index].begin;
    const uint32_t root = image.chain_root(begin).value_or(begin);
    std::set<size_t> touched;
    for (const Instruction& insn : found.scans[index].instructions) {
        if (!insn.indexed) {
            continue;
        }
        const auto table = read_chain_table(image, root, insn);
        if (!table || found.tables.contains(table->rva)) {
            continue;
        }
        if (overlaps_known(found.tables, *table)) {
            found.conflicted[index] = true;
            continue;
        }
        touched.merge(functions_touching(image.functions(), table->rva, table_end(*table)));
        found.tables.try_emplace(table->rva, *table);
    }
    return touched;
}

// Decodes every function without the tables found so far and decodes again the functions that hold a new table, until no table is new.
Discovery discover_tables(const Image& image, const Decoder& decoder) {
    const std::vector<Function>& functions = image.functions();
    Discovery found{{}, std::vector<Scan>(functions.size()), std::vector<bool>(functions.size(), false)};
    std::set<size_t> dirty;
    for (size_t i = 0; i < functions.size(); ++i) {
        dirty.insert(i);
    }
    while (!dirty.empty()) {
        std::set<size_t> next;
        for (const size_t index : dirty) {
            const Function& f = functions[index];
            found.scans[index] = scan_function(decoder, image.at(f.begin, f.end - f.begin), f, found.tables);
            next.merge(add_tables(image, index, found));
        }
        dirty = std::move(next);
    }
    return found;
}

}  // namespace

Decoder::Decoder() : decoder_{} {
    ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

std::optional<Instruction> Decoder::decode(std::span<const std::byte> code, uint32_t rva, std::span<const Range> masks) const {
    ZydisDecodedInstruction decoded{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, code.data(), code.size(), &decoded, operands.data()))) {
        return std::nullopt;
    }
    Instruction insn;
    insn.rva = rva;
    insn.length = decoded.length;
    insn.indexed = indexed_load(decoded, operands);
    insn.flow = flow_of(decoded, operands);
    note_effects(insn, decoded, operands);
    std::copy_n(code.begin(), decoded.length, insn.bytes.begin());
    if (const auto& imm = decoded.raw.imm[0]; imm.is_relative) {
        insn.relative = true;
        insn.target = int64_t{rva} + decoded.length + imm.value.s;
        zero_bytes(insn, imm.offset, imm.size / 8U);
    }
    if ((decoded.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0 && decoded.raw.disp.size != 0) {
        zero_bytes(insn, decoded.raw.disp.offset, decoded.raw.disp.size / 8U);
    }
    zero_masked(insn, masks);
    return insn;
}

Decoded decode_function(const Decoder& decoder, std::span<const std::byte> bytes, Function range, std::span<const Range> masks) {
    Decoded out;
    out.code.range = range;
    uint32_t rva = range.begin;
    while (rva < range.end && !out.stopped.has_value()) {
        const auto table = std::ranges::find(out.code.tables, rva, &Table::rva);
        rva = table != out.code.tables.end() ? rva + static_cast<uint32_t>(table->entries.size()) * kEntryLength : step(decoder, bytes, masks, out, rva);
    }
    return out;
}

std::optional<uint32_t> hook_span(std::span<const Instruction> stream, uint32_t site) {
    const auto first = std::ranges::lower_bound(stream, site, {}, &Instruction::rva);
    if (first == stream.end() || first->rva != site) {
        return std::nullopt;
    }
    uint32_t covered = 0;
    for (auto it = first; it != stream.end(); ++it) {
        if (it->rva != site + covered) {
            return std::nullopt;
        }
        covered += it->length;
        if (covered >= kHookLength) {
            return covered;
        }
    }
    return std::nullopt;
}

std::optional<Difference> compare_code(const Code& now, const Code& before) {
    const size_t common = std::min(now.instructions.size(), before.instructions.size());
    for (size_t i = 0; i < common; ++i) {
        const Instruction& a = now.instructions[i];
        const Instruction& b = before.instructions[i];
        if (!same_encoding(a, b)) {
            return Difference{"bytes", a.rva, b.rva};
        }
        if ((a.relative || a.table_ref) && !same_branch(a, now.range, b, before.range)) {
            return Difference{"branch", a.rva, b.rva};
        }
    }
    if (now.instructions.size() != before.instructions.size()) {
        return Difference{"length", now.range.end, before.range.end};
    }
    return compare_tables(now, before);
}

BranchMap collect_branches(const Image& image, const Decoder& decoder) {
    const Discovery found = discover_tables(image, decoder);
    const std::vector<Function>& functions = image.functions();
    BranchMap map;
    for (size_t i = 0; i < functions.size(); ++i) {
        for (const Instruction& insn : found.scans[i].instructions) {
            if (insn.relative) {
                map.branches.emplace_back(insn.rva, insn.target);
            }
        }
        if (found.scans[i].stopped || found.conflicted[i]) {
            map.stopped.push_back(functions[i]);
        }
    }
    for (const auto& [rva, table] : found.tables) {
        std::ranges::transform(table.entries, std::back_inserter(map.branches), [&](uint32_t entry) { return Branch{table.ref, entry}; });
    }
    std::ranges::sort(map.branches, {}, &Branch::target);
    return map;
}

bool stopped_near(const BranchMap& map, const Image& image, const Function& site) {
    const std::optional<uint32_t> root = image.chain_root(site.begin);
    if (const auto in_chain = [&](const Function& f) {
            return image.chain_root(f.begin) == root;
        };
        std::ranges::any_of(map.stopped, in_chain)) {
        return true;
    }
    const auto first = std::ranges::upper_bound(map.branches, int64_t{site.begin}, {}, &Branch::target);
    const auto last = std::ranges::lower_bound(map.branches, int64_t{site.end}, {}, &Branch::target);
    return first < last && std::any_of(first, last, [&](const Branch& b) { return within(map.stopped, b.from); });
}

std::vector<Branch> landings(const BranchMap& map, uint32_t low, uint32_t high) {
    const auto first = std::ranges::upper_bound(map.branches, int64_t{low}, {}, &Branch::target);
    const auto last = std::ranges::lower_bound(map.branches, int64_t{high}, {}, &Branch::target);
    return first < last ? std::vector<Branch>(first, last) : std::vector<Branch>{};
}

}  // namespace livemap::compat
