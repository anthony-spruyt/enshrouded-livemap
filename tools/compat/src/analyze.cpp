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

#include "callbacks.h"
#include "disasm.h"
#include "hooks.h"
#include "sites.h"

namespace livemap::compat {

namespace {

constexpr std::string_view kChatSite = "chat_post";
constexpr std::string_view kAccessorOperand = "entity_table";
constexpr std::byte kCallOpcode{0xe8};

void append(Problems& to, Problems&& more) {
    std::ranges::move(more, std::back_inserter(to));
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

void check_hooks(const Context& c, const SiteHit& now, const Loaded& loaded, SiteReport& report, Problems& problems) {
    HookInspection found = inspect_hooks(c.current, c.branches, now, loaded);
    report.hook_aligned = found.aligned;
    report.into_hook = std::move(found.into_hook);
    append(problems, std::move(found.problems));
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
        check_hooks(c, now, *current, report, problems);
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
