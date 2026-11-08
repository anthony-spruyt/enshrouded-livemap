#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace livemap::compat {

// A set of the 16 general-purpose registers, one bit each in the order of their numbers: rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8 to r15.
using Registers = uint16_t;

constexpr std::array<std::string_view, 16> kRegisterNames{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                                          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

constexpr Registers register_bit(size_t number) {
    return static_cast<Registers>(1U << number);
}

constexpr std::optional<Registers> register_named(std::string_view name) {
    for (size_t number = 0; number < kRegisterNames.size(); ++number) {
        if (kRegisterNames[number] == name) {
            return register_bit(number);
        }
    }
    return std::nullopt;
}

constexpr Registers register_set(std::initializer_list<std::string_view> names) {
    Registers all = 0;
    for (const std::string_view name : names) {
        all |= register_named(name).value_or(0);
    }
    return all;
}

inline std::string register_list(Registers set) {
    std::string text;
    for (size_t number = 0; number < kRegisterNames.size(); ++number) {
        if ((set & register_bit(number)) != 0) {
            text += text.empty() ? "" : ", ";
            text += kRegisterNames[number];
        }
    }
    return text;
}

}  // namespace livemap::compat
