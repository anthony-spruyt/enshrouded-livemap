#include "check.h"

#include <algorithm>
#include <format>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "callbacks.h"
#include "liveness.h"
#include "registers.h"
#include "sites.h"

namespace livemap::compat {

namespace {

struct Context {
    const Image& image;
    const Decoder& decoder;
    const BranchMap& branches;
    const BuildRow& row;
};

bool is_hooked(std::string_view site) {
    return std::ranges::any_of(callbacks(), [&](const Callback& callback) { return callback.site == site; });
}

bool applies(const Callback& callback, std::string_view layout) {
    return callback.layout.empty() || callback.layout == layout;
}

// A site whose callbacks depend on the mining layout needs a row that names one of them.
bool layout_known(std::string_view site, std::string_view layout) {
    const auto of_site = [&](const Callback& callback) { return callback.site == site && !callback.layout.empty(); };
    const auto matches = [&](const Callback& callback) { return of_site(callback) && callback.layout == layout; };
    return !std::ranges::any_of(callbacks(), of_site) || std::ranges::any_of(callbacks(), matches);
}

void append(Problems& to, Problems&& more) {
    std::ranges::move(more, std::back_inserter(to));
}

// Every chunk of the function that holds the site, decoded; the first is the one that holds it.
std::vector<Code> chain_of(const Context& c, const Loaded& loaded) {
    std::vector<Code> chain{loaded.code};
    const std::optional<uint32_t> root = c.image.chain_root(loaded.region.begin);
    for (const Function& function : c.image.functions()) {
        if (function.begin == loaded.region.begin || c.image.chain_root(function.begin) != root) {
            continue;
        }
        Decoded decoded = decode_function(c.decoder, c.image.at(function.begin, function.end - function.begin), function, {});
        if (!decoded.stopped.has_value()) {
            chain.push_back(std::move(decoded.code));
        }
    }
    return chain;
}

// The registers each callback reads at one hook.
std::map<std::string_view, Registers> reads_at(const SiteHit& hit, uint32_t point, std::string_view layout) {
    std::map<std::string_view, Registers> reads;
    for (const Callback& callback : callbacks()) {
        if (callback.site == hit.pattern->site && hit.rva + callback.offset == point && applies(callback, layout)) {
            reads[callback.function] |= callback.reads;
        }
    }
    return reads;
}

Problems unused_registers(const Context& c, const SiteHit& hit, std::span<const Code> chain) {
    Problems problems;
    for (const uint32_t point : hook_points(hit)) {
        const std::optional<Registers> used = in_use_at(chain, point);
        if (!used.has_value()) {
            continue;
        }
        for (const auto& [function, reads] : reads_at(hit, point, c.row.mining_layout)) {
            if (const auto unused = static_cast<Registers>(reads & ~*used); unused != 0) {
                problems.push_back(std::format("{}: {} reads {} of the context at {}, which the code there does not use", hit.pattern->site,
                                               function, register_list(unused), hex(point)));
            }
        }
    }
    return problems;
}

void check_site(const Context& c, const SiteHit& hit, CheckResult& result) {
    const std::string& site = hit.pattern->site;
    result.hooks += hook_points(hit).size();
    if (!hit.fits_in_text) {
        result.problems.push_back(std::format("{}: the hook or an operand lies outside .text", site));
        return;
    }
    if (!layout_known(site, c.row.mining_layout)) {
        result.problems.push_back(std::format("{}: the mining layout {} is not one the callbacks know", site, c.row.mining_layout));
    }
    const auto loaded = load_code(c.image, c.decoder, hit);
    if (!loaded) {
        result.problems.push_back(std::format("{}: {}", site, loaded.error()));
        return;
    }
    append(result.problems, inspect_hooks(c.image, c.branches, hit, *loaded).problems);
    if (!loaded->region.window) {
        append(result.problems, unused_registers(c, hit, chain_of(c, *loaded)));
    }
}

}  // namespace

std::expected<CheckResult, std::string> check_exe(const Catalog& catalog, const Image& image, std::string_view sha256) {
    const std::vector<size_t> rows = catalog.rows_with_fingerprint(image.time_date_stamp(), image.size_of_image());
    if (rows.empty()) {
        return std::unexpected("no row describes this exe: its fingerprint is not in the builds");
    }
    if (rows.size() > 1) {
        return std::unexpected("several rows describe this exe: its fingerprint is not unique");
    }
    const BuildRow& row = catalog.rows()[rows[0]];
    const SigsetDef* sigset = catalog.sigset(row.sigset);
    if (sigset == nullptr) {
        return std::unexpected(std::format("the sigset {} of row {} does not exist", row.sigset, row.label));
    }
    const std::vector<SiteHit> hits = scan_sigset(image, *sigset);
    CheckResult result{row.label, row.sigset, 0, {}};
    if (row.exe_sha256 && *row.exe_sha256 != sha256) {
        result.problems.push_back(std::format("checksum: the exe is not the one the row {} lists", row.label));
    }
    append(result.problems, scan_problems(row, hits));
    const Decoder decoder;
    const BranchMap branches = collect_branches(image, decoder);
    const Context context{image, decoder, branches, row};
    for (const SiteHit& hit : hits) {
        if (hit.matches == 1 && is_hooked(hit.pattern->site)) {
            check_site(context, hit, result);
        }
    }
    return result;
}

}  // namespace livemap::compat
