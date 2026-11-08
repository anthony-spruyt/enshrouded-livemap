#include "signature.h"

#include <algorithm>
#include <format>
#include <string>
#include <vector>

namespace livemap::compat {

namespace {

constexpr std::string_view kDigits = "0123456789abcdef";

std::expected<int, std::string> parse_token(std::string_view token) {
    if (token == "??") {
        return -1;
    }
    const size_t high = token.size() == 2 ? kDigits.find(token[0]) : std::string_view::npos;
    const size_t low = token.size() == 2 ? kDigits.find(token[1]) : std::string_view::npos;
    if (high == std::string_view::npos || low == std::string_view::npos) {
        return std::unexpected(std::format("'{}' is no byte", token));
    }
    return static_cast<int>(high * 16 + low);
}

bool matches_at(const Signature& signature, std::span<const std::byte> data) {
    return std::ranges::equal(signature, data.first(signature.size()), [](int want, std::byte got) { return want < 0 || want == std::to_integer<int>(got); });
}

}  // namespace

std::expected<Signature, std::string> parse_signature(std::string_view text) {
    Signature signature;
    size_t start = 0;
    while (true) {
        const size_t end = text.find(' ', start);
        const auto byte = parse_token(text.substr(start, end == std::string_view::npos ? end : end - start));
        if (!byte.has_value()) {
            return std::unexpected(byte.error());
        }
        signature.push_back(*byte);
        if (end == std::string_view::npos) {
            return signature;
        }
        start = end + 1;
    }
}

std::vector<size_t> find_all(const Signature& signature, std::span<const std::byte> data) {
    std::vector<size_t> hits;
    const auto lead = std::ranges::find_if(signature, [](int b) { return b >= 0; });
    if (lead == signature.end()) {
        return hits;
    }
    const auto lead_at = static_cast<size_t>(lead - signature.begin());
    for (size_t i = 0; i + signature.size() <= data.size(); ++i) {
        if (std::to_integer<int>(data[i + lead_at]) == *lead && matches_at(signature, data.subspan(i))) {
            hits.push_back(i);
        }
    }
    return hits;
}

}  // namespace livemap::compat
