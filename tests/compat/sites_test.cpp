// Sites: where each pattern of a sigset matches in an image, the way src/scan.cpp finds its hook sites and operands.
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pe.h"
#include "pe_builder.h"
#include "signature.h"
#include "sites.h"
#include "test_support.h"

using compat_test::bytes_of;
using livemap::compat::NamedValue;
using livemap::compat::PatternDef;
using livemap::compat::scan_sigset;
using livemap::compat::SigsetDef;

namespace {

constexpr uint32_t kTextRva = 0x1000;

PatternDef pattern(std::string_view site, std::string_view bytes, uint32_t offset, std::vector<NamedValue> operands = {}) {
    PatternDef p;
    p.site = std::string(site);
    p.bytes = std::string(bytes);
    p.signature = *livemap::compat::parse_signature(bytes);
    p.offset = offset;
    p.mandatory = true;
    p.operands = std::move(operands);
    return p;
}

// A neighbour right behind .text holds bytes that a read past its end would pick up.
livemap::compat::Image image_of(std::vector<std::byte> text, bool neighbour = false) {
    compat_test::PeSpec spec;
    const auto end = static_cast<uint32_t>(kTextRva + text.size());
    spec.sections.emplace_back(".text", kTextRva, std::move(text), 0);
    if (neighbour) {
        spec.sections.emplace_back(".rdata", end, std::vector<std::byte>(0x20, std::byte{0xff}), 0);
    }
    return *livemap::compat::load_image(compat_test::build_pe(spec));
}

std::vector<std::byte> filler(size_t size) {
    return std::vector<std::byte>(size, std::byte{0x90});
}

void put_at(std::vector<std::byte>& text, size_t at, std::initializer_list<unsigned> values) {
    for (const unsigned v : values) {
        text.at(at++) = static_cast<std::byte>(v);
    }
}

}  // namespace

int main() {
    compat_test::Suite t;
    auto text = filler(0x100);
    put_at(text, 0x10, {0xaa, 0xbb, 0x78, 0x56, 0x34, 0x12, 0xcc});
    put_at(text, 0x40, {0xdd, 0xee});
    put_at(text, 0x60, {0xdd, 0xee});
    const auto image = image_of(text);

    SigsetDef set{"s", {}};
    set.patterns.push_back(pattern("once", "aa bb ?? ?? ?? ?? cc", 2, {{"value", 2}}));
    set.patterns.push_back(pattern("twice", "dd ee", 0));
    set.patterns.push_back(pattern("never", "11 22 33", 0));
    const auto hits = scan_sigset(image, set);

    t.check(hits.size() == 3 && hits[0].pattern == &set.patterns[0], "one hit for each pattern, in the order of the sigset");
    t.check(hits[0].matches == 1 && hits[0].match_rva == kTextRva + 0x10 && hits[0].rva == kTextRva + 0x12, "a unique match: its start, and the hook offset after it");
    t.check(hits[0].operands.size() == 1 && hits[0].operands[0].name == "value" && hits[0].operands[0].value == 0x12345678U, "the operand is read little endian from the match");
    t.check(hits[0].fits_in_text, "a hook and operand inside .text");
    t.check(hits[1].matches == 2 && hits[2].matches == 0, "a pattern that matches twice or never reports how often");
    t.check(hits[1].operands.empty() && hits[2].operands.empty() && !hits[1].fits_in_text && !hits[2].fits_in_text, "and has no site");

    SigsetDef edge{"e", {}};
    edge.patterns.push_back(pattern("hook_runs_out", "aa bb", 0));
    edge.patterns.push_back(pattern("operand_runs_out", "aa bb", 0, {{"v", 2}}));
    auto tail = filler(0x20);
    put_at(tail, 0x1b, {0xaa, 0xbb, 0x01, 0x02, 0x03});
    const auto edge_hits = scan_sigset(image_of(tail, true), edge);
    t.check(edge_hits[0].matches == 1 && edge_hits[0].fits_in_text, "a hook of five bytes that ends on the last byte of .text fits");
    t.check(edge_hits[1].matches == 1 && !edge_hits[1].fits_in_text && edge_hits[1].operands[0].value == 0, "an operand that runs past the end does not, and is not read");
    auto short_tail = filler(0x20);
    put_at(short_tail, 0x1c, {0xaa, 0xbb});
    t.check(!scan_sigset(image_of(short_tail), edge)[0].fits_in_text, "a hook of five bytes that would pass the end does not");
    return t.result();
}
