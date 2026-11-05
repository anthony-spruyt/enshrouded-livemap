#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "builds.h"
#include "pe.h"

namespace livemap::compat {

// Operands are 4-byte values.
constexpr uint32_t kOperandWidth = 4;

struct SiteHit {
    const PatternDef* pattern = nullptr;
    size_t matches = 0;
    // Set when the pattern matches exactly once: the start of the match, the hook site, and the operands read from the match.
    uint32_t match_rva = 0;
    uint32_t rva = 0;
    std::vector<NamedValue> operands;
    // The hook overwrites kHookLength bytes and every operand is 4 bytes; they all have to lie inside .text, as src/scan.cpp requires.
    bool fits_in_text = false;
};

// One hit for each pattern, in the order of the sigset.
std::vector<SiteHit> scan_sigset(const Image& image, const SigsetDef& sigset);

}  // namespace livemap::compat
