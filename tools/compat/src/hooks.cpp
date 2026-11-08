#include "hooks.h"

#include <algorithm>
#include <format>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "callbacks.h"

namespace livemap::compat {

std::string hex(uint32_t value) {
    return std::format("0x{:x}", value);
}

const SiteHit* hit_named(std::span<const SiteHit> hits, std::string_view site) {
    const auto found = std::ranges::find(hits, site, [](const SiteHit& hit) -> std::string_view { return hit.pattern->site; });
    return found == hits.end() ? nullptr : std::to_address(found);
}

std::optional<uint32_t> operand_of(std::span<const SiteHit> hits, std::string_view name) {
    for (const SiteHit& hit : hits) {
        for (const NamedValue& operand : hit.operands) {
            if (operand.name == name) {
                return operand.value;
            }
        }
    }
    return std::nullopt;
}

bool lists(std::span<const NamedValue> values, std::string_view name) {
    return std::ranges::any_of(values, [&](const NamedValue& value) { return value.name == name; });
}

Problems scan_problems(const BuildRow& row, std::span<const SiteHit> hits) {
    Problems problems;
    for (const NamedValue& expected : row.expected) {
        const SiteHit* hit = hit_named(hits, expected.name);
        if (const size_t matches = hit == nullptr ? 0 : hit->matches; matches != 1) {
            problems.push_back(std::format("{}: {} matches, the row lists {}", expected.name, matches, hex(expected.value)));
        } else if (hit->rva != expected.value) {
            problems.push_back(std::format("{}: found at {}, the row lists {}", expected.name, hex(hit->rva), hex(expected.value)));
        }
    }
    for (const SiteHit& hit : hits) {
        if (hit.matches == 1 && hit.pattern->site != kJoinSite && !lists(row.expected, hit.pattern->site)) {
            problems.push_back(std::format("{}: found at {}, the row does not list it", hit.pattern->site, hex(hit.rva)));
        }
    }
    for (const NamedValue& expected : row.expected_operands) {
        if (const std::optional<uint32_t> value = operand_of(hits, expected.name); !value.has_value()) {
            problems.push_back(std::format("{}: no site reads it, the row lists {}", expected.name, hex(expected.value)));
        } else if (*value != expected.value) {
            problems.push_back(std::format("{}: reads {}, the row lists {}", expected.name, hex(*value), hex(expected.value)));
        }
    }
    return problems;
}

std::expected<Loaded, std::string> load_code(const Image& image, const Decoder& decoder, const SiteHit& hit) {
    const Function* function = image.function_at(hit.rva);
    const Region region = function != nullptr ? Region{false, function->begin, function->end}
                                              : Region{true, hit.match_rva, hit.match_rva + static_cast<uint32_t>(hit.pattern->signature.size())};
    const std::span<const std::byte> bytes = image.at(region.begin, region.end - region.begin);
    std::vector<Range> masks;
    for (const NamedValue& operand : hit.pattern->operands) {
        masks.emplace_back(hit.match_rva + operand.value, kOperandWidth);
    }
    auto decoded = decode_function(decoder, bytes, Function{region.begin, region.end}, masks);
    if (decoded.stopped.has_value()) {
        return std::unexpected(std::format("the code at {} cannot be decoded past {}", hex(region.begin), hex(*decoded.stopped)));
    }
    return Loaded{region, std::move(decoded.code)};
}

std::vector<uint32_t> hook_points(const SiteHit& hit) {
    std::vector points{hit.rva};
    for (const Callback& callback : callbacks()) {
        if (callback.site == hit.pattern->site && callback.offset != 0 && std::ranges::find(points, hit.rva + callback.offset) == points.end()) {
            points.push_back(hit.rva + callback.offset);
        }
    }
    return points;
}

HookInspection inspect_hooks(const Image& image, const BranchMap& branches, const SiteHit& hit, const Loaded& loaded) {
    const std::string& site = hit.pattern->site;
    HookInspection found;
    for (const uint32_t point : hook_points(hit)) {
        const std::optional<uint32_t> span = hook_span(loaded.code.instructions, point);
        if (!span.has_value()) {
            found.aligned = false;
            found.problems.push_back(std::format("{}: the hook at {} does not start on an instruction", site, hex(point)));
            continue;
        }
        std::ranges::copy(landings(branches, point, point + *span), std::back_inserter(found.into_hook));
        if (!loaded.region.window && undecoded_near(branches, image, Function{loaded.region.begin, loaded.region.end}, point, point + *span)) {
            found.problems.push_back(std::format("{}: code near the hook at {} could not be decoded", site, hex(point)));
        }
    }
    if (!found.into_hook.empty()) {
        found.problems.push_back(std::format("{}: {} branches land inside the bytes the hook overwrites", site, found.into_hook.size()));
    }
    if (loaded.region.window) {
        found.problems.push_back(std::format("{}: the exception table does not list the code around the hook", site));
    } else if (stopped_near(branches, image, Function{loaded.region.begin, loaded.region.end})) {
        found.problems.push_back(std::format("{}: code tied to the function around the hook could not be decoded", site));
    }
    return found;
}

}  // namespace livemap::compat
