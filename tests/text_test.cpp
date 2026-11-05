// Plain assert-based tests for cleaning names from game memory (no framework).
#include <print>
#include <source_location>
#include <string>

#include "../src/text.h"

using livemap::text::clean_utf8;

static int failures = 0;

static void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
    }
}

int main() {
    const std::string fffd = "\xEF\xBF\xBD";
    check(clean_utf8("OG Vanilla K") == "OG Vanilla K");
    // Valid UTF-8 stays: Turkish, Kurdish, German letters, CJK, an emoji (4 bytes).
    check(clean_utf8("\xC3\x96zg\xC3\xBC\x72") == "\xC3\x96zg\xC3\xBCr");                // Özgür
    check(clean_utf8("\xC5\x9E\x65\x76\xC3\xAA") == "\xC5\x9E\x65v\xC3\xAA");             // Şevê
    check(clean_utf8("\xE6\x9D\xB1\xE4\xBA\xAC") == "\xE6\x9D\xB1\xE4\xBA\xAC");          // 東京
    check(clean_utf8("a\xF0\x9F\x94\xA5"
                     "b") ==
          "a\xF0\x9F\x94\xA5"
          "b");                 // a🔥b
    // The bytes of a pointer read as text: each invalid byte -> U+FFFD.
    check(clean_utf8("\xE0\xF0\x84G\xB5u") == fffd + fffd + fffd + "G" + fffd + "u");
    // Cut-off sequence, overlong form, UTF-16 surrogate, beyond U+10FFFF.
    check(clean_utf8("x\xC3") == "x" + fffd);
    check(clean_utf8("\xC0\xAF") == fffd + fffd);
    check(clean_utf8("\xED\xA0\x80") == fffd + fffd + fffd);
    check(clean_utf8("\xF4\x90\x80\x80") == fffd + fffd + fffd + fffd);
    // Control characters become spaces, quotes stay (JSON escaping happens later).
    check(clean_utf8("a\tb\x7F"
                     "c\"") == "a b c\"");
    check(clean_utf8("") == "");

    if (failures) {
        std::print("{} failure(s)\n", failures);
    } else {
        std::print("all text tests passed\n");
    }
    return failures ? 1 : 0;
}
