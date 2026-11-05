// Plain assert-based tests for the fault line: its text and which exception addresses count (no framework).
#include <array>
#include <cstdint>
#include <cstring>
#include <print>
#include <source_location>
#include <string>

#include "../src/fault.h"

using livemap::fault::classify;
using livemap::fault::format_line;
using livemap::fault::kMaxRegions;
using livemap::fault::kNoSlot;
using livemap::fault::Layout;
using livemap::fault::Stamp;
using livemap::fault::Verdict;
using livemap::fault::Where;

namespace {

int& failures() {
    static int count = 0;
    return count;
}

void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures();
    }
}

constexpr uint32_t kAccessViolation = 0xC0000005;
constexpr uint32_t kInPageError = 0xC0000006;
constexpr uint32_t kStackOverflow = 0xC00000FD;
constexpr uint32_t kCppException = 0xE06D7363;
constexpr uint32_t kGuardPage = 0x80000001;
constexpr uint32_t kBreakpoint = 0x80000003;
constexpr uint32_t kDebugPrint = 0x40010006;
constexpr uint32_t kThreadName = 0x406D1388;

constexpr uintptr_t kModule = 0x10000000;
constexpr uintptr_t kModuleEnd = 0x10080000;
constexpr uintptr_t kProbes = 0x10001000;
constexpr uintptr_t kProbesEnd = 0x10001200;
constexpr uintptr_t kGame = 0x140000000;
constexpr uintptr_t kGameEnd = 0x145000000;
constexpr uintptr_t kRegionA = 0x70000000;
constexpr uintptr_t kRegionB = 0x7ff00000;
constexpr uintptr_t kRegionSize = 0x10000;
constexpr const char* kActive = "chest";

void fill_layout(Layout& layout) {
    layout.module = {kModule, kModuleEnd};
    layout.probes = {kProbes, kProbesEnd};
    layout.game = {kGame, kGameEnd};
    layout.regions.publish({kRegionA, kRegionA + kRegionSize}, "movement");
    layout.regions.publish({kRegionB, kRegionB + kRegionSize}, "chest");
}

std::string line(const Stamp& at, uint32_t code, const Verdict& verdict) {
    std::array<char, 160> buf{};
    const size_t n = format_line(buf.data(), buf.size(), at, code, verdict);
    return std::string(buf.data(), n);
}

void test_format() {
    const Stamp at{2026, 11, 5, 7, 8, 9, 42};
    check(line(at, kAccessViolation, {Where::Module, 0x1a2b3, "movement"}) ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=livemap+0x0001A2B3 site=movement\r\n");
    check(line(at, kStackOverflow, {Where::Trampoline, 0x40, "chest"}) ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC00000FD at=trampoline+0x00000040 site=chest\r\n");
    check(line(at, kAccessViolation, {Where::Game, 0x1f2e3d, "chest"}) ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=game+0x001F2E3D site=chest\r\n");
    check(line(at, kAccessViolation, {Where::Module, 0, nullptr}) ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=livemap+0x00000000 site=none\r\n");
    check(line(at, kAccessViolation, {Where::Module, 0, ""}) ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=livemap+0x00000000 site=none\r\n");
}

void test_format_bounds() {
    const Stamp at{2026, 11, 5, 7, 8, 9, 42};
    const Verdict verdict{Where::Module, 1, "movement"};
    std::array<char, 160> buf{};
    const size_t full = format_line(buf.data(), buf.size(), at, kAccessViolation, verdict);
    check(full > 0);
    check(format_line(buf.data(), full - 1, at, kAccessViolation, verdict) == 0);
    check(format_line(buf.data(), full, at, kAccessViolation, verdict) == full);
    const std::string longest(200, 'x');
    const std::string cut = line(at, kAccessViolation, {Where::Module, 1, longest.c_str()});
    check(!cut.empty() && cut.size() < buf.size());
    check(cut.ends_with("x\r\n"));
}

void test_fault_codes() {
    using livemap::fault::is_fault_code;
    check(is_fault_code(kAccessViolation));
    check(is_fault_code(kInPageError));
    check(is_fault_code(kStackOverflow));
    check(is_fault_code(0xC000001D));
    check(is_fault_code(0x80000002));
    check(!is_fault_code(kCppException));
    check(!is_fault_code(kGuardPage));
    check(!is_fault_code(kBreakpoint));
    check(!is_fault_code(kDebugPrint));
    check(!is_fault_code(kThreadName));
}

void test_bad_read_codes() {
    using livemap::fault::is_bad_read;
    check(is_bad_read(kAccessViolation));
    check(is_bad_read(kInPageError));
    check(!is_bad_read(kStackOverflow));
    check(!is_bad_read(kGuardPage));
    check(!is_bad_read(kCppException));
    check(!is_bad_read(0xC000001D));
    check(!is_bad_read(0));
}

void test_classify_module() {
    Layout layout;
    fill_layout(layout);
    Verdict v = classify(layout, kModule + 0x2345, kAccessViolation, nullptr);
    check(v.where == Where::Module && v.offset == 0x2345 && v.site == nullptr);
    v = classify(layout, kModule + 0x2345, kAccessViolation, kActive);
    check(v.where == Where::Module && std::strcmp(v.site, "chest") == 0);
    v = classify(layout, kModule, kAccessViolation, nullptr);
    check(v.where == Where::Module && v.offset == 0);
    v = classify(layout, kModuleEnd - 1, kAccessViolation, nullptr);
    check(v.where == Where::Module);
    check(classify(layout, kModuleEnd, kAccessViolation, nullptr).where == Where::Outside);
    check(classify(layout, kModule - 1, kAccessViolation, nullptr).where == Where::Outside);
}

void test_classify_trampoline() {
    Layout layout;
    fill_layout(layout);
    Verdict v = classify(layout, kRegionA + 0x30, kAccessViolation, nullptr);
    check(v.where == Where::Trampoline && v.offset == 0x30 && std::strcmp(v.site, "movement") == 0);
    v = classify(layout, kRegionB + kRegionSize - 1, kAccessViolation, kActive);
    check(v.where == Where::Trampoline && std::strcmp(v.site, "chest") == 0);
    check(classify(layout, kRegionB + kRegionSize, kAccessViolation, nullptr).where == Where::Outside);
    check(classify(layout, kRegionA - 1, kAccessViolation, nullptr).where == Where::Outside);
}

void test_classify_game() {
    Layout layout;
    fill_layout(layout);
    Verdict v = classify(layout, kGame + 0x2345, kAccessViolation, kActive);
    check(v.where == Where::Game && v.offset == 0x2345 && std::strcmp(v.site, "chest") == 0);
    v = classify(layout, kGame, kAccessViolation, kActive);
    check(v.where == Where::Game && v.offset == 0);
    check(classify(layout, kGameEnd - 1, kAccessViolation, kActive).where == Where::Game);
    check(classify(layout, kGameEnd, kAccessViolation, kActive).where == Where::Outside);
    check(classify(layout, kGame - 1, kAccessViolation, kActive).where == Where::Outside);
    check(classify(layout, kGame + 0x2345, kAccessViolation, nullptr).where == Where::Outside);
    check(classify(layout, kGame + 0x2345, kCppException, kActive).where == Where::Outside);
    check(classify(layout, kGame + 0x2345, kBreakpoint, kActive).where == Where::Outside);
    Layout unknown;
    fill_layout(unknown);
    unknown.game = {};
    check(classify(unknown, kGame + 0x2345, kAccessViolation, kActive).where == Where::Outside);
}

void test_classify_ignores() {
    Layout layout;
    fill_layout(layout);
    check(classify(layout, 0x7ff600001000, kAccessViolation, nullptr).where == Where::Outside);
    check(classify(layout, 0x7ff600001000, kAccessViolation, kActive).where == Where::Outside);
    check(classify(layout, kModule + 0x2345, kCppException, nullptr).where == Where::Outside);
    check(classify(layout, kRegionA + 4, kGuardPage, nullptr).where == Where::Outside);
    check(classify(layout, kModule + 0x2345, kBreakpoint, nullptr).where == Where::Outside);
}

void test_classify_probes() {
    Layout layout;
    fill_layout(layout);
    check(classify(layout, kProbes, kAccessViolation, nullptr).where == Where::Outside);
    check(classify(layout, kProbesEnd - 1, kInPageError, kActive).where == Where::Outside);
    check(classify(layout, kProbes - 1, kAccessViolation, nullptr).where == Where::Module);
    check(classify(layout, kProbesEnd, kAccessViolation, nullptr).where == Where::Module);
    check(classify(layout, kProbes + 4, kStackOverflow, nullptr).where == Where::Module);
    Layout none;
    fill_layout(none);
    none.probes = {};
    check(classify(none, kProbes, kAccessViolation, nullptr).where == Where::Module);
}

void test_region_table() {
    livemap::fault::RegionTable table;
    check(table.find(kRegionA) == nullptr);
    const size_t first = table.publish({kRegionA, kRegionA + kRegionSize}, "movement");
    const size_t second = table.publish({kRegionB, kRegionB + kRegionSize}, "chest");
    check(first != kNoSlot && second != kNoSlot && first != second);
    check(table.find(kRegionA + 8) != nullptr && std::strcmp(table.find(kRegionA + 8)->site, "movement") == 0);
    check(table.find(kRegionB + kRegionSize - 1) != nullptr);
    check(table.find(kRegionB + kRegionSize) == nullptr);
    table.retire(first);
    check(table.find(kRegionA + 8) == nullptr);
    check(table.find(kRegionB + 8) != nullptr);
    table.retire(first);
    table.retire(kNoSlot);
    check(table.find(kRegionB + 8) != nullptr);
    const size_t again = table.publish({kRegionA, kRegionA + kRegionSize}, "bases");
    check(again != first && table.find(kRegionA + 8) != nullptr && std::strcmp(table.find(kRegionA + 8)->site, "bases") == 0);
}

void test_region_table_capacity() {
    livemap::fault::RegionTable table;
    check(table.publish({0x1000, 0x1000}, "empty") == kNoSlot);
    check(table.publish({0x2000, 0x1000}, "reversed") == kNoSlot);
    for (size_t i = 0; i < kMaxRegions; ++i) {
        check(table.publish({0x10000 * (i + 1), 0x10000 * (i + 1) + 0x100}, "hook") != kNoSlot);
    }
    check(table.publish({0x900000, 0x900100}, "late") == kNoSlot);
    check(table.find(0x900010) == nullptr);
    check(table.find(0x10000 * kMaxRegions + 0x10) != nullptr);
}

}  // namespace

int main() {
    test_format();
    test_format_bounds();
    test_fault_codes();
    test_bad_read_codes();
    test_classify_module();
    test_classify_trampoline();
    test_classify_game();
    test_classify_ignores();
    test_classify_probes();
    test_region_table();
    test_region_table_capacity();
    if (failures() != 0) {
        std::print("{} failure(s)\n", failures());
    } else {
        std::print("all fault tests passed\n");
    }
    return failures() != 0 ? 1 : 0;
}
