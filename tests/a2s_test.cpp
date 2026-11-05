// Plain assert-based tests for reading the Flame level from the server's A2S_INFO reply.
#include <print>
#include <source_location>
#include <string>

#include "../src/a2s.h"

using namespace livemap::a2s;

static int failures = 0;

static void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
    }
}

int main() {
    // The live server's reply of 23 Oct 2026 (world at Flame level 3), byte for byte.
    static const unsigned char kLive[] = {
        0xff, 0xff, 0xff, 0xff, 0x49, 0x11, 0x59, 0x61, 0x68, 0x75, 0x64, 0x73, 0x65, 0x6e, 0x54,
        0x6f, 0x77, 0x6e, 0x20, 0x33, 0x33, 0x65, 0x72, 0x00, 0x00, 0x45, 0x6e, 0x73, 0x68, 0x72,
        0x6f, 0x75, 0x64, 0x65, 0x64, 0x00, 0x45, 0x6e, 0x73, 0x68, 0x72, 0x6f, 0x75, 0x64, 0x65,
        0x64, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x64, 0x77, 0x01, 0x00, 0x30, 0x2e, 0x30, 0x2e,
        0x31, 0x35, 0x2e, 0x30, 0x00, 0xb1, 0x15, 0x3d, 0x18, 0x30, 0x06, 0xb6, 0x52, 0xcb, 0x40,
        0x01, 0x33, 0x3b, 0x31, 0x32, 0x37, 0x33, 0x30, 0x34, 0x33, 0x3b, 0x31, 0x3b, 0x30, 0x3b,
        0x31, 0x3b, 0x31, 0x3b, 0x31, 0x3b, 0x30, 0x3b, 0x30, 0x00, 0xa4, 0x5d, 0x12, 0x00, 0x00,
        0x00, 0x00, 0x00};
    const std::string live(reinterpret_cast<const char*>(kLive), sizeof kLive);
    check(keywords_of(live) == "3;1273043;1;0;1;1;1;0;0");
    check(flame_level(keywords_of(live)) == 3);
    check(flame_level("10;1273043") == 10);
    check(flame_level("") == -1);
    check(flame_level("x;1") == -1);
    check(flame_level("123;1") == -1);
    // Cut short anywhere: no keywords, no crash.
    for (size_t n = 0; n < live.size(); ++n) {
        check(keywords_of(live.substr(0, n)).size() <= 23);
    }
    check(keywords_of(live.substr(0, 90)).empty());
    // Challenge round trip.
    const std::string challenge_reply("\x{ff}\x{ff}\x{ff}\x{ff}A\x{01}\x{02}\x{03}\x{04}", 9);
    check(challenge_of(challenge_reply) == std::string("\x{01}\x{02}\x{03}\x{04}", 4));
    check(challenge_of(live).empty());
    check(info_request(std::string("\x{01}\x{02}\x{03}\x{04}", 4)).size() == 4 + 1 + 19 + 1 + 4);
    if (failures == 0) {
        std::print("a2s: all passed\n");
    }
    return failures == 0 ? 0 : 1;
}
