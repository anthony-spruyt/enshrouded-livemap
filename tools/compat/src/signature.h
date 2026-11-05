#pragma once

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace livemap::compat {

// Bytes to match; -1 matches any byte.
using Signature = std::vector<int>;

// Lower-case hex bytes separated by single spaces, ?? for any byte: the form data/builds.json holds.
std::expected<Signature, std::string> parse_signature(std::string_view text);

// The offset of every match, overlapping ones included. A signature of wildcards only matches nothing.
std::vector<size_t> find_all(const Signature& signature, std::span<const std::byte> data);

}  // namespace livemap::compat
