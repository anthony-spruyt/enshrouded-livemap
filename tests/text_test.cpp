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
    const std::string fffd = "\x{EF}\x{BF}\x{BD}";
    check(clean_utf8("OG Vanilla K") == "OG Vanilla K");
    // Valid UTF-8 stays: Turkish, Kurdish, German letters, CJK, an emoji (4 bytes).
    check(clean_utf8("\x{C3}\x{96}zg\x{C3}\x{BC}r") == "\x{C3}\x{96}zg\x{C3}\x{BC}r");                    // Özgür
    check(clean_utf8("\x{C5}\x{9E}ev\x{C3}\x{AA}") == "\x{C5}\x{9E}ev\x{C3}\x{AA}");                      // Şevê
    check(clean_utf8("\x{E6}\x{9D}\x{B1}\x{E4}\x{BA}\x{AC}") == "\x{E6}\x{9D}\x{B1}\x{E4}\x{BA}\x{AC}");  // 東京
    check(clean_utf8("a\x{F0}\x{9F}\x{94}\x{A5}b") == "a\x{F0}\x{9F}\x{94}\x{A5}b");                      // a🔥b
    // The bytes of a pointer read as text: each invalid byte -> U+FFFD.
    check(clean_utf8("\x{E0}\x{F0}\x{84}G\x{B5}u") == fffd + fffd + fffd + "G" + fffd + "u");
    // Cut-off sequence, overlong form, UTF-16 surrogate, beyond U+10FFFF.
    check(clean_utf8("x\x{C3}") == "x" + fffd);
    check(clean_utf8("\x{C0}\x{AF}") == fffd + fffd);
    check(clean_utf8("\x{ED}\x{A0}\x{80}") == fffd + fffd + fffd);
    check(clean_utf8("\x{F4}\x{90}\x{80}\x{80}") == fffd + fffd + fffd + fffd);
    // Control characters become spaces, quotes stay (JSON escaping happens later).
    check(clean_utf8("a\tb\x{7F}c\"") == "a b c\"");
    check(clean_utf8("") == "");

    if (failures) {
        std::print("{} failure(s)\n", failures);
    } else {
        std::print("all text tests passed\n");
    }
    return failures ? 1 : 0;
}
