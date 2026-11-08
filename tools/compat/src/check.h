#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>

#include "builds.h"
#include "hooks.h"
#include "pe.h"

namespace livemap::compat {

struct CheckResult {
    std::string label;
    std::string sigset;
    size_t hooks = 0;
    Problems problems;
};

// Checks the sigset of the row that describes `image` against the exe: the sites are where the row lists them, every hook
// starts on a whole instruction, no branch lands in the bytes a hook overwrites, and each register a callback reads from the
// context is in use at its hook. An error when no single row describes the exe.
std::expected<CheckResult, std::string> check_exe(const Catalog& catalog, const Image& image, std::string_view sha256);

}  // namespace livemap::compat
