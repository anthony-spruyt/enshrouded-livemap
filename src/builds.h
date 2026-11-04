#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "mining.h"

namespace livemap {

// A number the data file attaches to a name: an operand offset, an expected RVA or an expected operand.
struct Named {
    const char* name;
    uint32_t value;
};

// One hook site: `bytes` is hex with ?? for any byte; the site is the match start + `offset`.
// `operands` are offsets, from the match start, of values the code reads out of the match.
struct Pattern {
    const char* site;
    const char* bytes;
    uint32_t offset;
    bool mandatory;
    std::span<const Named> operands;
};

struct Sigset {
    const char* name;
    std::span<const Pattern> patterns;
};

// A server build recognised by its PE fingerprint; `expected` is what the selftest checks.
struct Build {
    const char* label;
    uint32_t time_date_stamp;
    uint32_t size_of_image;
    const Sigset* sigset;
    MiningLayout mining_layout;
    std::span<const Named> expected;
    std::span<const Named> expected_operands;
};

}  // namespace livemap
