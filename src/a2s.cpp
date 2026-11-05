#include "a2s.h"

#include <cstddef>
#include <string>

namespace livemap::a2s {

namespace {

constexpr char kHeader[] = "\x{FF}\x{FF}\x{FF}\x{FF}";

// Reads a zero-terminated string at `at`; false when the reply ends first.
bool skip_string(const std::string& r, size_t& at) {
    size_t end = r.find('\0', at);
    if (end == std::string::npos) {
        return false;
    }
    at = end + 1;
    return true;
}

}  // namespace

std::string info_request(const std::string& challenge) {
    return std::string(kHeader) + "TSource Engine Query" + std::string(1, '\0') + challenge;
}

std::string challenge_of(const std::string& reply) {
    if (reply.size() >= 9 && reply.compare(0, 4, kHeader) == 0 && reply[4] == 'A') {
        return reply.substr(5, 4);
    }
    return {};
}

std::string keywords_of(const std::string& r) {
    // Layout (Valve's A2S_INFO): header, 'I', protocol, name, map, folder, game, id (2), players,
    // max players, bots, server type, environment, visibility, VAC (7 bytes), version, then the
    // extra data flag and the fields it announces: 0x80 port (2), 0x10 SteamID (8), 0x40 SourceTV
    // port (2) + name, 0x20 keywords, 0x01 game id (8).
    if (r.size() < 6 || r.compare(0, 4, kHeader) != 0 || r[4] != 'I') {
        return {};
    }
    size_t at = 6;
    for (int i = 0; i < 4; ++i) {
        if (!skip_string(r, at)) {
            return {};
        }
    }
    at += 2 + 7;
    if (at > r.size() || !skip_string(r, at) || at >= r.size()) {
        return {};
    }
    const auto flags = static_cast<std::byte>(r[at++]);
    auto has = [flags](std::byte bit) { return (flags & bit) != std::byte{}; };
    if (has(std::byte{0x80})) {
        at += 2;
    }
    if (has(std::byte{0x10})) {
        at += 8;
    }
    if (has(std::byte{0x40})) {
        at += 2;
        if (at > r.size() || !skip_string(r, at)) {
            return {};
        }
    }
    if (!has(std::byte{0x20}) || at >= r.size()) {
        return {};
    }
    size_t end = r.find('\0', at);
    return end == std::string::npos ? std::string() : r.substr(at, end - at);
}

int flame_level(const std::string& keywords) {
    int value = 0;
    size_t i = 0;
    for (; i < keywords.size() && i < 3 && keywords[i] >= '0' && keywords[i] <= '9'; ++i) {
        value = value * 10 + (keywords[i] - '0');
    }
    if (i == 0 || i > 2 || (i < keywords.size() && keywords[i] != ';')) {
        return -1;
    }
    return value;
}

}  // namespace livemap::a2s
