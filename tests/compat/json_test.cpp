// The JSON reader and writer: the data file has to come back byte for byte, and malformed input has to be refused.
#include <array>
#include <format>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <string>
#include <string_view>

#include "json.h"
#include "test_support.h"

using livemap::compat::Json;
using livemap::compat::parse_json;
using livemap::compat::write_json;

namespace {

constexpr std::string_view kCanonical = R"({
  "name": "value",
  "numbers": [
    0,
    -12,
    1793700549,
    2.5e3
  ],
  "flags": {
    "yes": true,
    "no": false,
    "nothing": null
  },
  "empty_array": [],
  "empty_object": {},
  "escapes": "quote \" slash \\ tab \t newline \n bell \u0007"
}
)";

std::string read_text(const char* path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void check_round_trips(compat_test::Suite& t) {
    const auto doc = parse_json(kCanonical);
    t.check(doc.has_value(), "canonical document parses");
    if (doc) {
        t.check(write_json(*doc) == kCanonical, "canonical document is written back byte for byte");
    }
    const std::string data = read_text(LIVEMAP_BUILDS_JSON);
    const auto builds = parse_json(data);
    t.check(!data.empty() && builds.has_value(), "data/builds.json parses");
    if (builds) {
        t.check(write_json(*builds) == data, "data/builds.json is written back byte for byte");
    }
}

void check_accessors(compat_test::Suite& t) {
    auto doc = parse_json(R"({"a": 1, "b": ["x", true], "c": "text"})");
    t.check(doc.has_value(), "small document parses");
    if (!doc) {
        return;
    }
    t.check(doc->kind() == Json::Kind::Object && doc->keys().size() == 3, "object with three members");
    const Json* a = doc->find("a");
    t.check(a != nullptr && a->as_uint() == 1U, "number reads as unsigned");
    const Json* b = doc->find("b");
    t.check(b != nullptr && b->kind() == Json::Kind::Array && b->items().size() == 2, "array with two items");
    t.check(doc->find("missing") == nullptr, "a missing key is null");
    t.check(doc->find("c")->text() == "text", "string text");

    doc->set("a", Json::string("replaced"));
    doc->set("d", Json::boolean(true));
    t.check(doc->keys().size() == 4 && doc->keys()[0] == "a" && doc->keys()[3] == "d", "set replaces in place and appends new keys last");
    t.check(doc->find("a")->text() == "replaced", "replaced value");

    Json* list = doc->find("b");
    t.check(list->at(1) != nullptr && list->at(2) == nullptr && doc->find("c")->at(0) == nullptr, "a mutable element exists for each position of a container and no other value");
    *list->at(0) = Json::number(5);
    t.check(list->items()[0].as_uint() == 5U && list->items().size() == 2 && doc->find("d")->as_bool(), "an element is replaced where it is");
    t.check(Json::number(18446744073709551615ULL).as_uint() == 18446744073709551615ULL, "largest unsigned number");
    t.check(!parse_json("-3")->as_uint().has_value(), "a negative number is no unsigned");
    t.check(!parse_json("1.5")->as_uint().has_value(), "a fraction is no unsigned");
    t.check(!parse_json("99999999999999999999")->as_uint().has_value(), "an overflowing number is no unsigned");
}

std::string string_of(std::initializer_list<unsigned> bytes) {
    std::string out;
    for (const unsigned b : bytes) {
        out.push_back(static_cast<char>(b));
    }
    return out;
}

void check_unicode(compat_test::Suite& t) {
    const auto accent = parse_json(R"("caf\u00e9")");
    t.check(accent && accent->text() == string_of({'c', 'a', 'f', 0xc3, 0xa9}), "BMP escape becomes UTF-8");
    const auto pair = parse_json(R"("\ud83d\ude00")");
    t.check(pair && pair->text() == string_of({0xf0, 0x9f, 0x98, 0x80}), "surrogate pair becomes one code point");
    t.check(!parse_json(R"("\ud83d")"), "a lone high surrogate is refused");
    t.check(!parse_json(R"("\ude00")"), "a lone low surrogate is refused");
}

void check_refusals(compat_test::Suite& t) {
    constexpr auto bad = std::to_array<std::string_view>({
        "",
        "   ",
        "{",
        "[1,]",
        R"({"a": 1,})",
        R"({"a": 1 "b": 2})",
        R"({"a" 1})",
        "{a: 1}",
        R"("unterminated)",
        R"("bad \x escape")",
        R"("raw)"
        "\t"
        R"(tab")",
        "01",
        "1.",
        "-",
        "+1",
        "tru",
        "nulls",
        "[] []",
        R"({"a": 1, "a": 2})",
        R"("\u12")",
    });
    for (const std::string_view text : bad) {
        t.check(!parse_json(text).has_value(), std::format("refuses: {}", text));
    }
    t.check(parse_json("{").error().contains("offset"), "an error names the offset");
    t.check(parse_json(std::string(200, '[')).error().contains("deep"), "nesting past the limit is refused");
    t.check(parse_json(std::string(40, '[') + std::string(40, ']')).has_value(), "moderate nesting is accepted");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_round_trips(t);
    check_accessors(t);
    check_unicode(t);
    check_refusals(t);
    return t.result();
}
