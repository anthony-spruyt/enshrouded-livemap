// The PE reader on synthetic files: where .text and the exception table land, and which files it refuses.
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "pe.h"
#include "pe_builder.h"
#include "test_support.h"

using compat_test::build_pe;
using compat_test::bytes_of;
using compat_test::PeSpec;
using compat_test::put;
using livemap::compat::load_image;

namespace {

PeSpec basic() {
    PeSpec spec;
    spec.time_date_stamp = 0x65432100;
    spec.size_of_image = 0x10000;
    spec.sections.emplace_back(".text", 0x1000, bytes_of({0x90, 0xc3, 0xcc, 0xcc}), 0x2000);
    spec.sections.emplace_back(".rdata", 0x4000, bytes_of({1, 2, 3, 4}), 0);
    spec.functions = {{0x1100, 0x1180}, {0x1000, 0x1010}, {0x1200, 0x1300}};
    return spec;
}

void check_layout(compat_test::Suite& t) {
    const auto file = build_pe(basic());
    const auto image = load_image(file);
    t.check(image.has_value(), "a valid file loads");
    if (!image) {
        return;
    }
    t.check(image->time_date_stamp() == 0x65432100 && image->size_of_image() == 0x10000, "fingerprint fields");
    t.check(image->text_rva() == 0x1000 && image->text().size() == 0x2000, ".text range is its virtual size");
    t.check(image->text()[1] == std::byte{0xc3}, "section bytes sit at their RVA");
    t.check(image->text()[0x100] == std::byte{0}, "bytes past the raw data are zero");
    t.check(image->at(0x4000, 4)[3] == std::byte{4}, "another section's bytes");
    t.check(image->at(0x10000 - 2, 2).size() == 2 && image->at(0x10000 - 2, 3).empty(), "at() ends with the image");
    t.check(image->in_text(0x1000, 1) && image->in_text(0x2fff, 1), "first and last byte of .text");
    t.check(!image->in_text(0x3000, 1) && !image->in_text(0xfff, 1) && !image->in_text(0x2fff, 2), "just outside .text");
    t.check(!image->in_text(0x1000, 0x2001) && !image->in_text(0xffffffffULL, 5), "lengths and RVAs are bounds-checked without overflow");

    t.check(image->functions().size() == 3 && image->functions()[0].begin == 0x1000 && image->functions()[2].begin == 0x1200, "functions are sorted");
    const auto* first = image->function_at(0x1000);
    const auto* inside = image->function_at(0x100f);
    t.check(first != nullptr && first->end == 0x1010 && inside == first, "a function holds its first and last byte");
    t.check(image->function_at(0x1010) == nullptr && image->function_at(0x10ff) == nullptr, "the end is exclusive and gaps hold nothing");
    t.check(image->function_at(0x12ff) != nullptr && image->function_at(0x1300) == nullptr && image->function_at(0xfff) == nullptr, "outer edges");
}

void check_text_selection(compat_test::Suite& t) {
    PeSpec spec = basic();
    spec.sections.emplace_back(".text", 0x6000, bytes_of({0xaa}), 0x100);
    const auto image = load_image(build_pe(spec));
    t.check(image && image->text_rva() == 0x6000 && image->text().size() == 0x100, "the last .text section wins, as in the DLL");

    PeSpec prefixed = basic();
    prefixed.sections[0].name = ".text$mn";
    t.check(load_image(build_pe(prefixed)).has_value(), "the name is matched by its first five characters, as in the DLL");

    PeSpec none = basic();
    none.sections[0].name = ".code";
    t.check(!load_image(build_pe(none)).has_value(), "a file without .text is refused");
}

void check_refusals(compat_test::Suite& t) {
    const auto good = build_pe(basic());
    t.check(!load_image({}).has_value(), "empty input");
    t.check(!load_image(std::span(good).first(0x30)).has_value(), "shorter than the DOS header");
    t.check(!load_image(std::span(good).first(compat_test::kSectionTableOffset + 10)).has_value(), "cut inside the section table");
    t.check(!load_image(std::span(good).first(good.size() - 0x200)).has_value(), "cut inside section data");

    const auto broken = [&](auto&& edit) {
        auto file = good;
        edit(file);
        return load_image(file).has_value();
    };
    t.check(!broken([](auto& f) { put(f, 0, 0x5a5a, 2); }), "no MZ");
    t.check(!broken([](auto& f) { put(f, 0x3c, 0x7fffffff, 4); }), "e_lfanew outside the file");
    t.check(!broken([](auto& f) { put(f, compat_test::kPeHeaderOffset, 0x4551, 4); }), "no PE signature");
    t.check(!broken([](auto& f) { put(f, compat_test::kCoffOffset, 0x14c, 2); }), "not x64");
    t.check(!broken([](auto& f) { put(f, compat_test::kOptionalOffset, 0x10b, 2); }), "not PE32+");
    t.check(!broken([](auto& f) { put(f, compat_test::kOptionalOffset + 56, 0, 4); }), "no image size");
    t.check(!broken([](auto& f) { put(f, compat_test::kOptionalOffset + 56, 0xf0000000, 4); }), "absurd image size");
    t.check(!broken([](auto& f) { put(f, compat_test::kSectionTableOffset + 12, 0xffff0000, 4); }), "section beyond the image");
    t.check(!broken([](auto& f) { put(f, compat_test::kSectionTableOffset + 20, 0xfffff000, 4); }), "raw data beyond the file");
    t.check(!broken([](auto& f) { put(f, compat_test::kExceptionDirectoryOffset + 4, 13, 4); }), "exception table size not a multiple of 12");
    t.check(!broken([](auto& f) { put(f, compat_test::kExceptionDirectoryOffset, 0xfffff000, 4); }), "exception table beyond the image");

    PeSpec empty_function = basic();
    empty_function.functions = {{0x1100, 0x1100}};
    t.check(!load_image(build_pe(empty_function)).has_value(), "an exception entry with no bytes");
    PeSpec outside = basic();
    outside.functions = {{0x1100, 0x20000}};
    t.check(!load_image(build_pe(outside)).has_value(), "an exception entry past the image");
    PeSpec no_table = basic();
    no_table.functions.clear();
    const auto plain = load_image(build_pe(no_table));
    t.check(plain && plain->functions().empty(), "a file without an exception table loads with no functions");
}

void check_chains(compat_test::Suite& t) {
    PeSpec spec = basic();
    spec.functions = {{0x1000, 0x1100},
                      {0x1200, 0x1240, 0x1000},
                      {0x1300, 0x1340, 0x1200},
                      {0x1400, 0x1440},
                      {0x1500, 0x1540, 0x1900},
                      {.begin = 0x1600, .end = 0x1640, .chained_to = 0x1000, .unwind_codes = 3},
                      {.begin = 0x1700, .end = 0x1740, .chained_to = 0x1000, .unwind_codes = 4},
                      {.begin = 0x1800, .end = 0x1840, .chained_to = 0x1000, .unwind_version = 3},
                      {.begin = 0x1a00, .end = 0x1a40, .chained_to = 0x1000, .unwind_version = 2},
                      {0x1b00, 0x1b40, 0x1b00},
                      {0x1c00, 0x1c40, 0x10}};
    const auto image = load_image(build_pe(spec));
    t.check(image.has_value(), "a file with chained unwind info loads");
    if (!image) {
        return;
    }
    t.check(image->chain_root(0x1000) == 0x1000U && image->chain_root(0x10ff) == 0x1000U, "a function that chains to nothing is its own root");
    t.check(image->chain_root(0x1210) == 0x1000U, "a chunk belongs to the function it chains to");
    t.check(image->chain_root(0x1310) == 0x1000U, "and a chunk of a chunk to the root of the chain");
    t.check(image->chain_root(0x1410) == 0x1400U, "an unrelated function keeps its own");
    t.check(image->chain_root(0x1510) == 0x1500U, "a chunk whose parent is no function stays its own root");
    t.check(image->chain_root(0x1610) == 0x1000U && image->chain_root(0x1710) == 0x1000U, "the codes before the link are skipped, whether their count is odd or even");
    t.check(image->chain_root(0x1810) == 0x1800U && image->chain_root(0x1a10) == 0x1000U, "unwind info of a version the format does not define is not followed");
    t.check(image->chain_root(0x1b10) == 0x1b00U && image->chain_root(0x1c10) == 0x1c00U, "a chunk that names itself, or a parent below every function, is its own root");
    t.check(!image->chain_root(0x1150).has_value() && !image->chain_root(0xfff).has_value(), "code outside every function has no root");

    PeSpec loop = basic();
    loop.functions = {{0x1000, 0x1100, 0x1200}, {0x1200, 0x1240, 0x1000}};
    const auto looping = load_image(build_pe(loop));
    t.check(!looping && looping.error().contains("unwind"), "unwind info that chains in a circle is refused");
    PeSpec lost = basic();
    lost.functions = {{0x1000, 0x1100, 0, 0xffffff00}};
    const auto beyond = load_image(build_pe(lost));
    t.check(!beyond && beyond.error().contains("unwind"), "unwind info outside the image is refused");
}

using compat_test::ScopeRecord;
using Jumps = std::vector<std::pair<uint32_t, uint32_t>>;

Jumps jumps_of(const livemap::compat::Image& image) {
    Jumps out;
    for (const auto& jump : image.scope_jumps()) {
        out.emplace_back(jump.begin, jump.target);
    }
    return out;
}

bool none_in(const Jumps& jumps, uint32_t low, uint32_t high) {
    const auto inside = [&](uint32_t rva) { return rva >= low && rva < high; };
    return std::ranges::none_of(jumps, [&](const auto& jump) { return inside(jump.first) || inside(jump.second); });
}

void check_scopes(compat_test::Suite& t) {
    constexpr uint32_t kInfo = 0x4000;
    constexpr uint32_t kStep = 0x100;
    constexpr unsigned kHandler = compat_test::kExceptionHandlerFlag;
    constexpr unsigned kFinally = compat_test::kTerminationHandlerFlag;
    constexpr unsigned kChained = compat_test::kChainFlag;
    const std::vector<ScopeRecord> guarded{{0x1004, 0x1010, 1, 0x1020}, {0x1010, 0x1018, 0x1180, 0}, {0x1020, 0x1030, 1, 0x1210}, {0x10f0, 0x1100, 1, 0x1050}};
    const std::vector<std::vector<std::byte>> infos{
        compat_test::scope_info(kHandler, 0, guarded, 4),
        compat_test::scope_info(kFinally, 3, {{0x1300, 0x1310, 0x1180, 0x1320}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1400, 0x1410, 1, 0x1420}}, 0x10000000),
        compat_test::scope_info(kHandler, 0, {{0x1500, 0x1510, 1, 0x1520}, {0x1520, 0x1520, 1, 0}}, 2),
        compat_test::scope_info(kHandler, 0, {{0x1600, 0x1610, 1, 0x1520}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1004, 0x1010, 1, 0x1720}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1800, 0x1810, 1, 0x1820}}, 1, 3),
        compat_test::scope_info(0, 0, {{0x1900, 0x1910, 1, 0x1920}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1a30, 0x1a50, 1, 0x1a20}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1b00, 0x1b10, 1, 0x1b20}, {0x1b10, 0x1b20, 1, 0x1b30}}, 2),
        compat_test::scope_info(kHandler, 0, {{0x1c00, 0x1c10, 0x7770, 0x1c20}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1cf0, 0x1d10, 1, 0x1d20}}, 1),
        compat_test::scope_info(kHandler | kChained, 0, {{0x1e00, 0x1e10, 1, 0x1e20}}, 1),
        compat_test::scope_info(kHandler, 0, {{0x1f00, 0x1f10, 0, 0x1f20}}, 1),
    };
    PeSpec spec = basic();
    spec.functions = {{.begin = 0x1000, .end = 0x1100, .unwind = kInfo},
                      {.begin = 0x1180, .end = 0x11c0},
                      {.begin = 0x1200, .end = 0x1240, .chained_to = 0x1000},
                      {.begin = 0x1300, .end = 0x1340, .unwind = kInfo + kStep},
                      {.begin = 0x1400, .end = 0x1440, .unwind = kInfo + 2 * kStep},
                      {.begin = 0x1500, .end = 0x1540, .unwind = kInfo + 3 * kStep},
                      {.begin = 0x1600, .end = 0x1640, .unwind = kInfo + 4 * kStep},
                      {.begin = 0x1700, .end = 0x1740, .unwind = kInfo + 5 * kStep},
                      {.begin = 0x1800, .end = 0x1840, .unwind = kInfo + 6 * kStep},
                      {.begin = 0x1900, .end = 0x1940, .unwind = kInfo + 7 * kStep},
                      {.begin = 0x1a00, .end = 0x1a40, .unwind = kInfo + 8 * kStep},
                      {.begin = 0x1b00, .end = 0x1b40, .unwind = 0xffd8},
                      {.begin = 0x1c00, .end = 0x1c40, .unwind = kInfo + 10 * kStep},
                      {.begin = 0x1d00, .end = 0x1d40, .unwind = kInfo + 11 * kStep},
                      {.begin = 0x1e00, .end = 0x1e40, .unwind = kInfo + 12 * kStep},
                      {.begin = 0x1f00, .end = 0x1f40, .unwind = kInfo + 13 * kStep}};
    std::vector<std::byte> data(infos.size() * kStep);
    for (size_t i = 0; i < infos.size(); ++i) {
        std::ranges::copy(infos[i], data.begin() + i * kStep);
    }
    spec.sections[1] = {".rdata", kInfo, data, 0};
    spec.sections.emplace_back(".rdata2", 0xffd8, std::vector<std::byte>(infos[9].begin(), infos[9].begin() + 0x28), 0);
    const auto image = load_image(build_pe(spec));
    t.check(image.has_value(), "a file with scope tables loads");
    if (!image) {
        return;
    }
    const Jumps jumps = jumps_of(*image);
    t.check(jumps == Jumps({{0x1004, 0x1020}, {0x1020, 0x1210}, {0x10f0, 0x1050}, {0x1300, 0x1320}}),
            "the jump targets of the scope tables, in code of the chain; a record with no jump target adds none");
    t.check(std::ranges::contains(jumps, std::pair<uint32_t, uint32_t>{0x1300, 0x1320}), "a termination handler has a scope table too, after codes of an odd count");
    t.check(none_in(jumps, 0x1400, 0x1440), "a table that claims more records than the file holds");
    t.check(none_in(jumps, 0x1500, 0x1540), "a record that guards nothing");
    t.check(none_in(jumps, 0x1600, 0x1640), "a jump target in another function");
    t.check(none_in(jumps, 0x1700, 0x1740), "a guarded range outside the function");
    t.check(none_in(jumps, 0x1800, 0x1840), "unwind info of a version the format does not define");
    t.check(none_in(jumps, 0x1900, 0x1940), "unwind info with no handler");
    t.check(none_in(jumps, 0x1a00, 0x1a40), "a guarded range that runs past the function");
    t.check(none_in(jumps, 0x1b00, 0x1b40), "a last record that runs off the end of the image");
    t.check(none_in(jumps, 0x1c00, 0x1c40) && none_in(jumps, 0x1f00, 0x1f40), "a record whose handler is in no function, or is zero");
    t.check(none_in(jumps, 0x1d00, 0x1d40), "a guarded range that starts before the function");
    t.check(none_in(jumps, 0x1e00, 0x1e40), "unwind info that chains and has a handler");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_layout(t);
    check_text_selection(t);
    check_chains(t);
    check_scopes(t);
    check_refusals(t);
    return t.result();
}
