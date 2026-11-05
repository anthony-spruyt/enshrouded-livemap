#pragma once

#include <cstddef>
#include <format>
#include <initializer_list>
#include <iostream>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace compat_test {

class Suite {
public:
    void check(bool ok, std::string_view detail, std::source_location where = std::source_location::current()) {
        ++checks_;
        if (!ok) {
            ++failures_;
            std::cout << std::format("FAIL {}:{}  {}\n", where.file_name(), where.line(), detail);
        }
    }

    int result() const {
        std::cout << std::format("{} checks, {} failed\n", checks_, failures_);
        return failures_ == 0 ? 0 : 1;
    }

private:
    int checks_ = 0;
    int failures_ = 0;
};

inline std::vector<std::byte> bytes_of(std::initializer_list<unsigned> values) {
    std::vector<std::byte> out;
    for (const unsigned v : values) {
        out.push_back(static_cast<std::byte>(v));
    }
    return out;
}

inline std::span<const std::byte> as_bytes(std::string_view text) {
    return std::as_bytes(std::span(text));
}

}  // namespace compat_test
