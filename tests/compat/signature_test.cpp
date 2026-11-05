// Signatures: the hex-with-wildcards text of data/builds.json and the search that must report every match.
#include <array>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "signature.h"
#include "test_support.h"

using compat_test::bytes_of;
using livemap::compat::find_all;
using livemap::compat::parse_signature;

int main() {
    compat_test::Suite t;

    const auto sig = parse_signature("48 8b ?? 05");
    t.check(sig.has_value() && sig->size() == 4, "four bytes with one wildcard");
    t.check(parse_signature("00 ff").has_value() && parse_signature("??").has_value(), "extremes parse");

    t.check(parse_signature("48").has_value(), "a single byte parses");
    constexpr auto bad = std::to_array<std::string_view>({"", " ", "48  8b", "48 8b ", " 48 8b", "4", "484", "48 8", "48 8g", "48 8B", "?", "???", "48 ? 8b", "0x48"});
    for (const std::string_view text : bad) {
        t.check(!parse_signature(text).has_value(), std::format("refuses: '{}'", text));
    }

    const auto haystack = bytes_of({0x48, 0x8b, 0x01, 0x05, 0x00, 0x48, 0x8b, 0xff, 0x05, 0x48, 0x8b, 0x05});
    const auto hits = find_all(*sig, haystack);
    t.check(hits.size() == 2 && hits[0] == 0 && hits[1] == 5, "both matches are found, wildcard bytes are free");
    t.check(find_all(*parse_signature("48 8b 05"), haystack) == std::vector<size_t>{9}, "a match that ends on the last byte");
    t.check(find_all(*parse_signature("05"), haystack).size() == 3, "single-byte signature");
    t.check(find_all(*parse_signature("aa bb"), haystack).empty(), "no match");
    t.check(find_all(*parse_signature("48 8b 01 05 00 48 8b ff 05 48 8b 05 00"), haystack).empty(), "a signature longer than the data");
    t.check(find_all(*parse_signature("?? ?? ??"), haystack).empty(), "a signature of wildcards only matches nothing");
    t.check(find_all(*parse_signature("?? 8b"), haystack).size() == 3, "leading wildcard");
    t.check(find_all(*parse_signature("8b ??"), haystack).size() == 3, "trailing wildcard");

    const auto overlapping = bytes_of({1, 1, 1, 1});
    t.check(find_all(*parse_signature("01 01"), overlapping).size() == 3, "overlapping matches all count");
    return t.result();
}
