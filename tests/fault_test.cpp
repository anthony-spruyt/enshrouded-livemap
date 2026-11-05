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
using livemap::fault::Layout;
using livemap::fault::Stamp;
using livemap::fault::Verdict;
using livemap::fault::Where;

namespace {

int failures = 0;

void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
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
constexpr uintptr_t kRegionA = 0x70000000;
constexpr uintptr_t kRegionB = 0x7ff00000;
constexpr uintptr_t kRegionSize = 0x10000;

Layout make_layout() {
    Layout layout;
    layout.module = {kModule, kModuleEnd};
    layout.probes = {kProbes, kProbesEnd};
    layout.regions[0] = {{kRegionA, kRegionA + kRegionSize}, "movement"};
    layout.regions[1] = {{kRegionB, kRegionB + kRegionSize}, "chest"};
    return layout;
}

std::string line(const Stamp& at, uint32_t code, Where where, uint32_t offset, const char* site) {
    std::array<char, 160> buf{};
    const size_t n = format_line(buf.data(), buf.size(), at, code, where, offset, site);
    return std::string(buf.data(), n);
}

void test_format() {
    const Stamp at{2026, 11, 5, 7, 8, 9, 42};
    check(line(at, kAccessViolation, Where::Module, 0x1a2b3, "movement") ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=livemap+0x0001A2B3 site=movement\r\n");
    check(line(at, kStackOverflow, Where::Trampoline, 0x40, "chest") ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC00000FD at=trampoline+0x00000040 site=chest\r\n");
    check(line(at, kAccessViolation, Where::Module, 0, nullptr) ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=livemap+0x00000000 site=none\r\n");
    check(line(at, kAccessViolation, Where::Module, 0, "") ==
          "2026-11-05 07:08:09.042 [livemap] FAULT code=0xC0000005 at=livemap+0x00000000 site=none\r\n");
}

void test_format_bounds() {
    const Stamp at{2026, 11, 5, 7, 8, 9, 42};
    std::array<char, 160> buf{};
    const size_t full = format_line(buf.data(), buf.size(), at, kAccessViolation, Where::Module, 1, "movement");
    check(full > 0);
    check(format_line(buf.data(), full - 1, at, kAccessViolation, Where::Module, 1, "movement") == 0);
    check(format_line(buf.data(), full, at, kAccessViolation, Where::Module, 1, "movement") == full);
    const std::string longest(200, 'x');
    const std::string cut = line(at, kAccessViolation, Where::Module, 1, longest.c_str());
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

void test_classify_module() {
    const Layout layout = make_layout();
    Verdict v = classify(layout, 2, kModule + 0x2345, kAccessViolation);
    check(v.where == Where::Module && v.offset == 0x2345 && v.site == nullptr);
    v = classify(layout, 2, kModule, kAccessViolation);
    check(v.where == Where::Module && v.offset == 0);
    v = classify(layout, 2, kModuleEnd - 1, kAccessViolation);
    check(v.where == Where::Module);
    check(classify(layout, 2, kModuleEnd, kAccessViolation).where == Where::Outside);
    check(classify(layout, 2, kModule - 1, kAccessViolation).where == Where::Outside);
}

void test_classify_trampoline() {
    const Layout layout = make_layout();
    Verdict v = classify(layout, 2, kRegionA + 0x30, kAccessViolation);
    check(v.where == Where::Trampoline && v.offset == 0x30 && std::strcmp(v.site, "movement") == 0);
    v = classify(layout, 2, kRegionB + kRegionSize - 1, kAccessViolation);
    check(v.where == Where::Trampoline && std::strcmp(v.site, "chest") == 0);
    check(classify(layout, 2, kRegionB + kRegionSize, kAccessViolation).where == Where::Outside);
    check(classify(layout, 1, kRegionB + 4, kAccessViolation).where == Where::Outside);
    check(classify(layout, 0, kRegionA + 4, kAccessViolation).where == Where::Outside);
}

void test_classify_ignores() {
    const Layout layout = make_layout();
    check(classify(layout, 2, 0x140001000, kAccessViolation).where == Where::Outside);
    check(classify(layout, 2, kModule + 0x2345, kCppException).where == Where::Outside);
    check(classify(layout, 2, kRegionA + 4, kGuardPage).where == Where::Outside);
    check(classify(layout, 2, kModule + 0x2345, kBreakpoint).where == Where::Outside);
}

void test_classify_probes() {
    const Layout layout = make_layout();
    check(classify(layout, 2, kProbes, kAccessViolation).where == Where::Outside);
    check(classify(layout, 2, kProbesEnd - 1, kInPageError).where == Where::Outside);
    check(classify(layout, 2, kProbes - 1, kAccessViolation).where == Where::Module);
    check(classify(layout, 2, kProbesEnd, kAccessViolation).where == Where::Module);
    check(classify(layout, 2, kProbes + 4, kStackOverflow).where == Where::Module);
    Layout none = make_layout();
    none.probes = {};
    check(classify(none, 2, kProbes, kAccessViolation).where == Where::Module);
}

}  // namespace

int main() {
    test_format();
    test_format_bounds();
    test_fault_codes();
    test_classify_module();
    test_classify_trampoline();
    test_classify_ignores();
    test_classify_probes();
    if (failures) {
        std::print("{} failure(s)\n", failures);
    } else {
        std::print("all fault tests passed\n");
    }
    return failures ? 1 : 0;
}
