#pragma once

#include "analyze.h"
#include "json.h"

namespace livemap::compat {

// Holds RVAs, counts and kinds, never game bytes or disassembly.
Json report_json(const Analysis& analysis);

}  // namespace livemap::compat
