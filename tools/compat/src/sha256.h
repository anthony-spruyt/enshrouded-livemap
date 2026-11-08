#pragma once

#include <cstddef>
#include <span>
#include <string>

namespace livemap::compat {

// Lower-case hex SHA-256 of `data`.
std::string sha256_hex(std::span<const std::byte> data);

}  // namespace livemap::compat
