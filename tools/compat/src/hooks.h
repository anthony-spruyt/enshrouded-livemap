#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "builds.h"
#include "disasm.h"
#include "pe.h"
#include "sites.h"

namespace livemap::compat {

constexpr std::string_view kJoinSite = "join_line";

using Problems = std::vector<std::string>;

// Its function in the exception table, or the bytes of its pattern for code with no entry there.
struct Region {
    bool window = false;
    uint32_t begin = 0;
    uint32_t end = 0;
};

std::string hex(uint32_t value);

const SiteHit* hit_named(std::span<const SiteHit> hits, std::string_view site);
std::optional<uint32_t> operand_of(std::span<const SiteHit> hits, std::string_view name);
bool lists(std::span<const NamedValue> values, std::string_view name);

// What differs between the row and the sites an exe has: nothing when the exe is the build the row describes.
Problems scan_problems(const BuildRow& row, std::span<const SiteHit> hits);

struct Loaded {
    Region region;
    Code code;
};

// The function that holds the site, or for code the exception table does not list, the bytes of the pattern.
std::expected<Loaded, std::string> load_code(const Image& image, const Decoder& decoder, const SiteHit& hit);

// The addresses where the DLL places a hook for the site: the site itself, and the places the callbacks add to it.
std::vector<uint32_t> hook_points(const SiteHit& hit);

struct HookInspection {
    bool aligned = true;
    std::vector<Branch> into_hook;
    Problems problems;
};

// Whether each hook of the site starts on an instruction, whether any branch lands in the bytes it overwrites, and whether
// the code around it could be followed, including the bytes of other functions within 128 bytes of each hook.
HookInspection inspect_hooks(const Image& image, const BranchMap& branches, const SiteHit& hit, const Loaded& loaded);

}  // namespace livemap::compat
