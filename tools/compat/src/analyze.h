#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "builds.h"
#include "disasm.h"
#include "hooks.h"
#include "pe.h"

namespace livemap::compat {

enum class Verdict { Known,
                     Easy,
                     Hard };

std::string_view verdict_name(Verdict verdict);

// Everything the report says about one pattern of the sigset: positions and counts, never bytes.
struct SiteReport {
    std::string site;
    bool mandatory = false;
    size_t matches = 0;
    std::optional<uint32_t> rva;
    std::optional<uint32_t> base_rva;
    std::optional<Region> region;
    std::optional<Region> base_region;
    std::optional<bool> hook_aligned;
    std::vector<Branch> into_hook;
    std::optional<Difference> difference;
};

struct ExeInfo {
    uint32_t time_date_stamp = 0;
    uint32_t size_of_image = 0;
    std::string sha256;
};

struct Edit {
    enum class Kind { None,
                      Alias,
                      Append };
    Kind kind = Kind::None;
    size_t row = 0;
    NewRow added;
};

struct Analysis {
    Verdict verdict = Verdict::Hard;
    std::string build_id;
    std::string manifest;
    ExeInfo exe;
    std::string base_label;
    std::string base_sigset;
    std::optional<std::string> matched_label;
    std::vector<std::string> reasons;
    std::vector<SiteReport> sites;
    std::vector<NamedValue> operands;
    std::optional<size_t> undecodable_functions;  // set when a map of the branches of the exe was built
    Edit edit;
};

// `previous` is the last supported build: its row says which sigset and which RVAs are the reference.
struct Request {
    const Image* previous = nullptr;
    std::string previous_sha256;
    const Image* current = nullptr;
    std::string current_sha256;
    std::string build_id;
    std::string manifest;
    std::optional<std::string> depot;
};

// A verdict for the build, or the reason the inputs cannot be judged: the previous exe is not the build its row describes.
std::expected<Analysis, std::string> analyze(const Catalog& catalog, const Request& request);

std::expected<void, std::string> apply_edit(Catalog& catalog, const Edit& edit);

}  // namespace livemap::compat
