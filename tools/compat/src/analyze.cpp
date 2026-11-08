#include "analyze.h"

#include <algorithm>
#include <format>
#include <iterator>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "disasm.h"
#include "sites.h"

namespace livemap::compat {

namespace {

constexpr std::string_view kJoinSite = "join_line";
constexpr std::string_view kChatSite = "chat_post";
constexpr std::string_view kAccessorOperand = "entity_table";
constexpr uint32_t kCallLength = 5;
constexpr std::byte kCallOpcode{0xe8};

using Problems = std::vector<std::string>;

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

// What differs between the row and the sites an exe has: nothing when the exe is the build the row describes.
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

std::string joined(const Problems& problems) {
    std::string text;
    for (const std::string& problem : problems) {
        if (!text.empty()) {
            text += "; ";
        }
        text += problem;
    }
    return text;
}

std::expected<size_t, std::string> find_base(const Catalog& catalog, const Request& request) {
    const std::vector<size_t> rows = catalog.rows_with_fingerprint(request.previous->time_date_stamp(), request.previous->size_of_image());
    if (rows.empty()) {
        return std::unexpected("no row describes the previous exe: its fingerprint is not in the builds");
    }
    if (rows.size() > 1) {
        return std::unexpected("several rows describe the previous exe: its fingerprint is not unique");
    }
    if (const BuildRow& row = catalog.rows()[rows[0]]; row.exe_sha256 && *row.exe_sha256 != request.previous_sha256) {
        return std::unexpected(std::format("the previous exe is not the build of row {}: its checksum is not the one the row lists", row.label));
    }
    return rows[0];
}

std::vector<SiteReport> basic_reports(std::span<const SiteHit> now, std::span<const SiteHit> before) {
    std::vector<SiteReport> reports;
    for (const SiteHit& hit : now) {
        SiteReport report;
        report.site = hit.pattern->site;
        report.mandatory = hit.pattern->mandatory;
        report.matches = hit.matches;
        if (hit.matches == 1) {
            report.rva = hit.rva;
        }
        if (const SiteHit* old = hit_named(before, report.site); old != nullptr && old->matches == 1) {
            report.base_rva = old->rva;
        }
        reports.push_back(std::move(report));
    }
    return reports;
}

struct Context {
    const Image& previous;
    const Image& current;
    std::span<const SiteHit> before;
    std::span<const SiteHit> now;
    const Decoder& decoder;
    const BranchMap& branches;
};

struct Loaded {
    Region region;
    Code code;
};

// The function that holds the site, or for code the exception table does not list, the bytes of the pattern.
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

bool follows_join_call(std::byte next) {
    return next == std::byte{0x44} || next == std::byte{0xe9};
}

// The hook for the join line sits on a call to chat_post, and a second one on the instruction after it.
void check_join(const Context& c, const SiteHit& join, const Code& code, Problems& problems) {
    const SiteHit* chat = hit_named(c.now, kChatSite);
    if (chat == nullptr || chat->matches != 1) {
        problems.push_back(std::format("{}: {} is not found once, so the call cannot be checked", kJoinSite, kChatSite));
        return;
    }
    if (const auto is_chat_call = [&](const Instruction& i) {
            return i.rva == join.rva && i.bytes[0] == kCallOpcode && i.target == chat->rva;
        };
        !std::ranges::any_of(code.instructions, is_chat_call)) {
        problems.push_back(std::format("{}: the instruction at {} is not a call to {}", kJoinSite, hex(join.rva), kChatSite));
    }
    if (!std::ranges::any_of(c.current.at(join.rva + kCallLength, 1), follows_join_call)) {
        problems.push_back(std::format("{}: the call at {} is not followed by the bytes the second hook needs", kJoinSite, hex(join.rva)));
    }
}

void check_hooks(const Context& c, const SiteHit& now, const Code& code, SiteReport& report, Problems& problems) {
    std::vector points{now.rva};
    if (report.site == kJoinSite) {
        points.push_back(now.rva + kCallLength);
    }
    report.hook_aligned = true;
    for (const uint32_t point : points) {
        const std::optional<uint32_t> span = hook_span(code.instructions, point);
        if (!span.has_value()) {
            report.hook_aligned = false;
            problems.push_back(std::format("{}: the hook at {} does not start on an instruction", report.site, hex(point)));
            continue;
        }
        std::ranges::copy(landings(c.branches, point, point + *span), std::back_inserter(report.into_hook));
    }
    if (!report.into_hook.empty()) {
        problems.push_back(std::format("{}: {} branches land inside the bytes the hook overwrites", report.site, report.into_hook.size()));
    }
    if (report.region->window) {
        problems.push_back(std::format("{}: the exception table does not list the code around the hook", report.site));
    } else if (stopped_near(c.branches, c.current, Function{report.region->begin, report.region->end})) {
        problems.push_back(std::format("{}: code tied to the function around the hook could not be decoded", report.site));
    }
}

bool is_accessor(const PatternDef& pattern) {
    return lists(pattern.operands, kAccessorOperand);
}

void compare_site(const Context& c, const SiteHit& now, const SiteHit& before, SiteReport& report, Problems& problems) {
    const auto current = load_code(c.current, c.decoder, now);
    const auto previous = load_code(c.previous, c.decoder, before);
    if (!current || !previous) {
        problems.push_back(std::format("{}: {}", report.site, current ? previous.error() : current.error()));
        return;
    }
    report.region = current->region;
    report.base_region = previous->region;
    report.difference = compare_code(current->code, previous->code);
    if (report.difference) {
        problems.push_back(std::format("{}: differs from the previous build at {} ({})", report.site, hex(report.difference->rva), report.difference->kind));
    }
    if (!is_accessor(*now.pattern)) {
        check_hooks(c, now, current->code, report, problems);
    }
    if (report.site == kJoinSite) {
        check_join(c, now, current->code, problems);
    }
}

void inspect_site(const Context& c, size_t index, SiteReport& report, Problems& problems) {
    const SiteHit& now = c.now[index];
    const SiteHit& before = c.before[index];
    if (now.matches != 1) {
        problems.push_back(std::format("{}: {} matches, exactly one is needed", report.site, now.matches));
    } else if (!now.fits_in_text) {
        problems.push_back(std::format("{}: the hook or an operand lies outside .text", report.site));
    } else if (before.matches != 1) {
        problems.push_back(std::format("{}: the previous exe has no single match to compare with", report.site));
    } else {
        compare_site(c, now, before, report, problems);
    }
}

Problems collisions(const Catalog& catalog, std::string_view id, std::optional<size_t> own) {
    Problems problems;
    if (const std::optional<size_t> listed = catalog.row_with_build_id(id); listed.has_value() && listed != own) {
        problems.push_back(std::format("the build id {} is already listed by the row {}", id, catalog.rows()[*listed].label));
    }
    if (const std::optional<size_t> labeled = catalog.row_with_label(id); labeled.has_value() && labeled != own) {
        problems.push_back(std::format("the build id {} is the label of another row", id));
    }
    return problems;
}

ExeInfo exe_info(const Image& image, std::string_view sha256) {
    return ExeInfo{image.time_date_stamp(), image.size_of_image(), std::string(sha256)};
}

void append(Problems& to, Problems&& more) {
    std::ranges::move(more, std::back_inserter(to));
}

void judge_known(const Catalog& catalog, const Request& request, const std::vector<size_t>& rows, std::span<const SiteHit> before, Analysis& out) {
    if (rows.size() > 1) {
        Problems labels;
        for (const size_t row : rows) {
            labels.push_back(catalog.rows()[row].label);
        }
        out.reasons.push_back(std::format("{} rows have the fingerprint of this exe: {}", rows.size(), joined(labels)));
        return;
    }
    const BuildRow& row = catalog.rows()[rows[0]];
    const SigsetDef* sigset = catalog.sigset(row.sigset);
    const std::vector<SiteHit> found = scan_sigset(*request.current, *sigset);
    out.sites = basic_reports(found, before);
    Problems problems;
    if (row.exe_sha256 && *row.exe_sha256 != request.current_sha256) {
        problems.push_back(std::format("checksum: the exe is not the one the row {} lists", row.label));
    }
    append(problems, scan_problems(row, found));
    append(problems, collisions(catalog, request.build_id, rows[0]));
    out.reasons = problems;
    if (!problems.empty()) {
        return;
    }
    out.verdict = Verdict::Known;
    out.matched_label = row.label;
    if (!catalog.row_with_build_id(request.build_id).has_value()) {
        out.edit.kind = Edit::Kind::Alias;
        out.edit.row = rows[0];
        out.edit.added.build_id = request.build_id;
    }
}

uint32_t rva_of(std::span<const SiteHit> hits, std::string_view site) {
    const SiteHit* hit = hit_named(hits, site);
    return hit == nullptr ? 0 : hit->rva;
}

NewRow new_row(const BuildRow& base, const Request& request, std::span<const SiteHit> now, const std::vector<NamedValue>& operands) {
    NewRow row;
    row.build_id = request.build_id;
    row.time_date_stamp = request.current->time_date_stamp();
    row.size_of_image = request.current->size_of_image();
    row.depot = request.depot;
    row.manifest = request.manifest;
    row.exe_sha256 = request.current_sha256;
    for (const NamedValue& expected : base.expected) {
        row.expected.push_back(rva_of(now, expected.name));
    }
    for (const NamedValue& operand : operands) {
        row.expected_operands.push_back(operand.value);
    }
    return row;
}

// The operands the row of the base lists, read from the new exe. The accessor's has to be one of them: it is what the DLL reads by signature.
Problems read_operands(const BuildRow& base, std::span<const SiteHit> now, std::vector<NamedValue>& operands) {
    Problems problems;
    if (!lists(base.expected_operands, kAccessorOperand)) {
        problems.push_back(std::format("{}: the row of the previous build does not list the operand the accessor reads", kAccessorOperand));
    }
    for (const NamedValue& listed : base.expected_operands) {
        if (const std::optional<uint32_t> value = operand_of(now, listed.name)) {
            operands.emplace_back(listed.name, *value);
        } else {
            problems.push_back(std::format("{}: no site reads it in this exe", listed.name));
        }
    }
    return problems;
}

void judge_new(const Catalog& catalog, const Request& request, size_t base_index, std::span<const SiteHit> before, std::span<const SiteHit> now, Analysis& out) {
    const BuildRow& base = catalog.rows()[base_index];
    const Decoder decoder;
    const BranchMap branches = collect_branches(*request.current, decoder);
    out.undecodable_functions = branches.stopped.size();
    const Context context{*request.previous, *request.current, before, now, decoder, branches};
    Problems problems;
    for (size_t i = 0; i < out.sites.size(); ++i) {
        inspect_site(context, i, out.sites[i], problems);
    }
    append(problems, read_operands(base, now, out.operands));
    append(problems, collisions(catalog, request.build_id, std::nullopt));
    out.reasons = problems;
    if (!problems.empty()) {
        return;
    }
    out.verdict = Verdict::Easy;
    out.edit.kind = Edit::Kind::Append;
    out.edit.row = base_index;
    out.edit.added = new_row(base, request, now, out.operands);
}

}  // namespace

std::expected<Analysis, std::string> analyze(const Catalog& catalog, const Request& request) {
    if (request.previous == nullptr || request.current == nullptr) {
        return std::unexpected("both exes are needed");
    }
    const auto base_index = find_base(catalog, request);
    if (!base_index.has_value()) {
        return std::unexpected(base_index.error());
    }
    const BuildRow& base = catalog.rows()[*base_index];
    const SigsetDef* sigset = catalog.sigset(base.sigset);
    if (sigset == nullptr) {
        return std::unexpected(std::format("the sigset {} of row {} does not exist", base.sigset, base.label));
    }
    const std::vector<SiteHit> before = scan_sigset(*request.previous, *sigset);
    if (const Problems problems = scan_problems(base, before); !problems.empty()) {
        return std::unexpected(std::format("the previous exe is not the build of row {}: {}", base.label, joined(problems)));
    }
    const std::vector<SiteHit> now = scan_sigset(*request.current, *sigset);

    Analysis out;
    out.build_id = request.build_id;
    out.manifest = request.manifest;
    out.exe = exe_info(*request.current, request.current_sha256);
    out.base_label = base.label;
    out.base_sigset = base.sigset;
    out.sites = basic_reports(now, before);
    if (const std::vector<size_t> same = catalog.rows_with_fingerprint(out.exe.time_date_stamp, out.exe.size_of_image); same.empty()) {
        judge_new(catalog, request, *base_index, before, now, out);
    } else {
        judge_known(catalog, request, same, before, out);
    }
    return out;
}

std::expected<void, std::string> apply_edit(Catalog& catalog, const Edit& edit) {
    using enum Edit::Kind;
    switch (edit.kind) {
        case Alias:
            return catalog.add_alias(edit.row, edit.added.build_id);
        case Append:
            return catalog.append_row_like(edit.row, edit.added);
        case None:
            break;
    }
    return {};
}

}  // namespace livemap::compat
