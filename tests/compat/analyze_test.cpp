// The verdicts: known, easy and hard, judged on synthetic exes that move and change the way a game patch does.
#include <cstdlib>
#include <format>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "analyze.h"
#include "builds.h"
#include "exe_fixture.h"
#include "json.h"
#include "pe.h"
#include "sha256.h"
#include "test_support.h"

using compat_test::ExeLayout;
using compat_test::ExeSites;
using compat_test::Extra;
using compat_test::sites_of;
using livemap::compat::Analysis;
using livemap::compat::Catalog;
using livemap::compat::Edit;
using livemap::compat::Request;
using livemap::compat::SiteReport;
using livemap::compat::Verdict;

namespace {

struct Exe {
    ExeLayout layout;
    std::vector<std::byte> file;
    livemap::compat::Image image;
    std::string sha;
};

Exe exe_of(const ExeLayout& layout) {
    auto file = compat_test::build_exe(layout);
    auto sha = livemap::compat::sha256_hex(file);
    auto image = livemap::compat::load_image(file);
    if (!image) {
        std::cout << "the test exe is not a PE: " << image.error() << "\n";
        std::exit(2);
    }
    return Exe{layout, std::move(file), std::move(*image), std::move(sha)};
}

// The same code under a fingerprint no row has.
ExeLayout bumped() {
    ExeLayout l;
    l.time_date_stamp = 101;
    return l;
}

// What a patch that moves everything does.
ExeLayout shifted() {
    ExeLayout l = bumped();
    l.size_of_image = 0x11000;
    l.lead = 0x40;
    l.entity_table = 0x838;
    l.outside = 0x100;
    return l;
}

// A replacement that finds nothing would leave a test checking the wrong thing, so it stops the run.
std::string replaced(std::string text, std::string_view from, std::string_view to) {
    const auto at = text.find(from);
    if (at == std::string::npos) {
        std::cout << "the test text has no '" << from << "'\n";
        std::exit(2);
    }
    text.replace(at, from.size(), to);
    return text;
}

std::string hex(uint32_t v) {
    return std::format("0x{:x}", v);
}

std::string entry(std::string_view name, uint32_t value) {
    return std::format(R"("{}": "{}")", name, hex(value));
}

constexpr std::string_view kTemplate = R"({
  "sigsets": {"s": [
    {"site": "alpha", "bytes": "b8 11 11 11 11 48 89 d9", "offset": "0x0", "mandatory": true},
    {"site": "beta", "bytes": "b8 22 22 22 22 48 89 d9", "offset": "0x0", "mandatory": true},
    {"site": "param_entity", "bytes": "4c 8b d9 48 8b 81 ?? ?? ?? ?? 8b 04 ?? c3", "offset": "0x0", "mandatory": true, "operands": {"entity_table": "0x6"}},
    {"site": "chat_post", "bytes": "b8 33 33 33 33 48 89 d9", "offset": "0x0", "mandatory": false},
    {"site": "join_line", "bytes": "b8 44 44 44 44 ba ?? ?? ?? ??", "offset": "0xa", "mandatory": false, "operands": {"join_tag": "0x6"}}
  ], "t": [
    {"site": "alpha", "bytes": "b8 11 11 11 11 48 89 d9", "offset": "0x0", "mandatory": true}
  ]},
  "builds": [
    {"label": "100", "buildids": ["100"], "time_date_stamp": @TDS@, "size_of_image": "@SIZE@", "sigset": "s", "mining_layout": "m",
     "steam": {"depot": "7", "manifest": "8", "exe_sha256": @SHA@},
     "expected": {"alpha": "@ALPHA@", "beta": "@BETA@", "param_entity": "@LEAF@", "chat_post": "@CHAT@"},
     "expected_operands": {"entity_table": "@ET@"}},
    {"label": "900", "buildids": ["900", "901"], "time_date_stamp": 5, "size_of_image": "0x2000", "sigset": "s", "mining_layout": "m",
     "steam": {"depot": null, "manifest": null, "exe_sha256": null}, "expected": {}},
    {"label": "legacy", "buildids": ["950"], "time_date_stamp": 6, "size_of_image": "0x3000", "sigset": "s", "mining_layout": "m",
     "steam": {"depot": null, "manifest": null, "exe_sha256": null}, "expected": {}}
  ]
})";

std::string catalog_text(const Exe& base, bool with_sha = true) {
    const ExeSites s = sites_of(base.layout);
    std::string text(kTemplate);
    for (const auto& [key, value] : std::vector<std::pair<std::string, std::string>>{{"@TDS@", std::to_string(base.layout.time_date_stamp)},
                                                                                     {"@SIZE@", hex(base.layout.size_of_image)},
                                                                                     {"@SHA@", with_sha ? R"(")" + base.sha + R"(")" : "null"},
                                                                                     {"@ALPHA@", hex(s.alpha)},
                                                                                     {"@BETA@", hex(s.beta)},
                                                                                     {"@LEAF@", hex(s.leaf)},
                                                                                     {"@CHAT@", hex(s.chat)},
                                                                                     {"@ET@", hex(base.layout.entity_table)}}) {
        text = replaced(text, key, value);
    }
    return text;
}

Catalog load(std::string_view text) {
    auto parsed = livemap::compat::parse_json(text);
    if (!parsed) {
        std::cout << "the test catalog is not JSON: " << parsed.error() << "\n";
        std::exit(2);
    }
    auto catalog = Catalog::from_json(std::move(*parsed));
    if (!catalog) {
        std::cout << "the test catalog is invalid: " << catalog.error() << "\n";
        std::exit(2);
    }
    return std::move(*catalog);
}

Request request(const Exe& previous, const Exe& current, std::string build_id = "200") {
    Request r;
    r.previous = &previous.image;
    r.previous_sha256 = previous.sha;
    r.current = &current.image;
    r.current_sha256 = current.sha;
    r.build_id = std::move(build_id);
    r.manifest = "5555";
    return r;
}

bool mentions(const Analysis& a, std::string_view fragment) {
    return std::ranges::any_of(a.reasons, [&](std::string_view reason) { return reason.contains(fragment); });
}

const SiteReport& site(const Analysis& a, std::string_view name) {
    static const SiteReport kNone;
    for (const SiteReport& s : a.sites) {
        if (s.site == name) {
            return s;
        }
    }
    return kNone;
}

struct Options {
    std::string build_id = "200";
    bool with_sha = true;
    std::optional<std::string> depot;
    std::string catalog;  // used instead of the generated one when set
};

// An analysis that fails to run is a failed check, never a quiet hard verdict.
Analysis run(compat_test::Suite& t, const Exe& base, const Exe& current, const Options& options = {}) {
    const Catalog catalog = load(options.catalog.empty() ? catalog_text(base, options.with_sha) : options.catalog);
    Request r = request(base, current, options.build_id);
    r.depot = options.depot;
    auto result = livemap::compat::analyze(catalog, r);
    t.check(result.has_value(), result ? "the analysis ran" : result.error());
    return result ? std::move(*result) : Analysis{};
}

Options with_id(std::string id) {
    Options o;
    o.build_id = std::move(id);
    return o;
}

Options without_sha() {
    Options o;
    o.with_sha = false;
    return o;
}

void check_inputs(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});
    const ExeSites s = sites_of(base.layout);
    const std::string good = catalog_text(base);
    const auto fails = [&](const std::string& catalog, const Exe& previous, std::string_view fragment, std::string_view why) {
        const auto result = livemap::compat::analyze(load(catalog), request(previous, base));
        t.check(!result.has_value() && result.error().contains(fragment), why);
    };
    t.check(livemap::compat::analyze(load(good), request(base, base)).has_value(), "the previous exe that is its row is accepted");
    t.check(livemap::compat::analyze(load(catalog_text(base, false)), request(base, base)).has_value(), "a row without a checksum is accepted");
    ExeLayout other;
    other.time_date_stamp = 77;
    fails(good, exe_of(other), "no row", "a previous exe no row describes");
    fails(replaced(replaced(good, R"("time_date_stamp": 6)", R"("time_date_stamp": 100)"), R"("0x3000")", R"("0x10000")"), base, "several rows", "a previous exe two rows describe");
    fails(replaced(good, base.sha, std::string(64, '0')), base, "checksum", "a previous exe whose checksum is not its row's");
    fails(replaced(good, entry("alpha", s.alpha), entry("alpha", s.alpha + 1)), base, "alpha", "an expected RVA that is not where the previous exe has the site");
    fails(replaced(good, ", " + entry("chat_post", s.chat), ""), base, "chat_post", "a site the previous exe has that the row does not list");
    fails(replaced(good, entry("entity_table", 0x830), entry("entity_table", 0x831)), base, "entity_table", "an operand that is not what the previous exe holds");
    fails(replaced(replaced(good, entry("alpha", s.alpha), entry("alpha", s.alpha + 1)), entry("entity_table", 0x830), entry("entity_table", 0x831)), base, "; entity_table", "every difference is listed");
    fails(replaced(good, R"(, "operands": {"entity_table": "0x6"})", ""), base, "entity_table", "an operand that no site reads");
}

void check_known(compat_test::Suite& t) {
    using enum Verdict;
    const Exe base = exe_of(ExeLayout{});
    const ExeSites s = sites_of(base.layout);
    const Analysis same = run(t, base, base);
    t.check(same.verdict == Known && same.matched_label == "100" && same.reasons.empty(), "the same exe under a new build id is known");
    t.check(same.edit.kind == Edit::Kind::Alias && same.edit.row == 0 && same.edit.added.build_id == "200", "and asks for an alias in the row it matched");
    t.check(same.edit.added.manifest == "5555", "with the manifest of the new build, the one Steam serves now");
    t.check(same.build_id == "200" && same.manifest == "5555" && same.exe.sha256 == base.sha && same.exe.time_date_stamp == 100 && same.exe.size_of_image == 0x10000,
            "the report names the build and the exe");
    t.check(same.base_label == "100" && same.base_sigset == "s" && same.sites.size() == 5, "the base and a site for each pattern");
    const SiteReport& alpha = site(same, "alpha");
    t.check(alpha.matches == 1 && alpha.rva == s.alpha && alpha.base_rva == s.alpha, "a site reports where it was found and where the base has it");
    t.check(alpha.mandatory && !site(same, "chat_post").mandatory, "and whether the sigset needs it");

    const Analysis listed = run(t, base, base, with_id("100"));
    t.check(listed.verdict == Known && listed.edit.kind == Edit::Kind::None, "a build id the row lists already changes nothing");
    t.check(run(t, base, base, without_sha()).verdict == Known, "a row without a checksum goes by the fingerprint");

    ExeLayout other_bytes_layout;
    other_bytes_layout.outside = 0x40;
    const Exe other_bytes = exe_of(other_bytes_layout);
    const Analysis changed = run(t, base, other_bytes);
    t.check(changed.verdict == Hard && mentions(changed, "checksum") && changed.edit.kind == Edit::Kind::None, "other bytes under the fingerprint of a row are hard");
    t.check(run(t, base, other_bytes, without_sha()).verdict == Known, "unless the row has no checksum to tell");

    ExeLayout moved_layout;
    moved_layout.lead = 0x20;
    const Analysis elsewhere = run(t, base, exe_of(moved_layout), without_sha());
    t.check(elsewhere.verdict == Hard && mentions(elsewhere, "alpha"), "the sites of a row found elsewhere are hard");

    const Analysis taken = run(t, base, base, with_id("900"));
    t.check(taken.verdict == Hard && mentions(taken, "already listed") && taken.edit.kind == Edit::Kind::None, "a build id that belongs to another row");

    ExeLayout twice_layout;
    twice_layout.duplicate_beta = true;
    const Analysis doubled = run(t, base, exe_of(twice_layout), without_sha());
    t.check(doubled.verdict == Hard && mentions(doubled, "beta: 2 matches"), "a site that matches twice under the fingerprint of a row is hard");
    ExeLayout bare_layout;
    bare_layout.lose_gamma = true;
    const Exe bare = exe_of(bare_layout);
    Options bare_options;
    bare_options.catalog = replaced(catalog_text(bare), ", " + entry("chat_post", s.chat), "");
    t.check(run(t, bare, bare, bare_options).verdict == Known, "a site that the exe lacks and the row does not list is no difference");

    Options other_sigset;
    other_sigset.catalog = replaced(replaced(replaced(catalog_text(base), R"("time_date_stamp": 6)", R"("time_date_stamp": 101)"), R"("0x3000", "sigset": "s")", R"("0x10000", "sigset": "t")"),
                                    R"("expected": {}})"
                                    "\n"
                                    R"(  ])",
                                    std::format(R"("expected": {{{}}}}})"
                                                "\n"
                                                R"(  ])",
                                                entry("alpha", s.alpha)));
    const Analysis reverted = run(t, base, exe_of(bumped()), other_sigset);
    t.check(reverted.verdict == Known && reverted.matched_label == "legacy" && reverted.sites.size() == 1, "a row with a sigset of its own is judged by that one");
    t.check(reverted.edit.kind == Edit::Kind::Alias && reverted.edit.row == 2, "and gets the alias");

    const std::string claimed = replaced(replaced(catalog_text(base), R"("time_date_stamp": 5)", R"("time_date_stamp": 101)"), R"("0x2000")", R"("0x10000")");
    const Exe fresh = exe_of(bumped());
    Options claimed_options;
    claimed_options.catalog = claimed;
    const Analysis lone = run(t, base, fresh, claimed_options);
    t.check(lone.verdict == Hard && mentions(lone, "alpha"), "a row that lists no sites for its fingerprint is hard");
    Options crowded_options;
    crowded_options.catalog = replaced(replaced(claimed, R"("time_date_stamp": 6)", R"("time_date_stamp": 101)"), R"("0x3000")", R"("0x10000")");
    const Analysis crowd = run(t, base, fresh, crowded_options);
    t.check(crowd.verdict == Hard && mentions(crowd, "900") && mentions(crowd, "legacy"), "a fingerprint two rows have is hard");
}

void check_easy(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});
    const ExeSites old_sites = sites_of(base.layout);
    const Exe next = exe_of(shifted());
    const ExeSites s = sites_of(next.layout);
    const Analysis a = run(t, base, next);
    t.check(a.verdict == Verdict::Easy && a.reasons.empty() && !a.matched_label.has_value(), "everything moved and nothing changed is easy");
    t.check(a.base_label == "100" && a.base_sigset == "s", "against the row of the previous exe");
    t.check(a.edit.kind == Edit::Kind::Append && a.edit.row == 0, "asks for a row like the base");
    const livemap::compat::NewRow& row = a.edit.added;
    t.check(row.build_id == "200" && row.manifest == "5555" && row.exe_sha256 == next.sha && row.time_date_stamp == 101 && row.size_of_image == 0x11000, "the new row names the build and the exe");
    t.check(!row.depot.has_value(), "and keeps the depot of the base unless one is given");
    t.check(row.expected == std::vector<uint32_t>{s.alpha, s.beta, s.leaf, s.chat}, "the sites in the order of the row it follows");
    t.check(row.expected_operands == std::vector<uint32_t>{0x838}, "the accessor operand read from the exe");
    t.check(a.operands.size() == 1 && a.operands[0].name == "entity_table" && a.operands[0].value == 0x838, "the report lists the operand");

    const SiteReport& alpha = site(a, "alpha");
    t.check(alpha.matches == 1 && alpha.rva == s.alpha && alpha.base_rva == old_sites.alpha, "a site with where it moved from");
    t.check(alpha.region && !alpha.region->window && alpha.region->begin == s.alpha && alpha.region->end == s.alpha + compat_test::kFunctionSize, "compared over its function");
    t.check(alpha.base_region && alpha.base_region->begin == old_sites.alpha, "against the function of the base");
    t.check(alpha.hook_aligned == true && alpha.into_hook.empty() && !alpha.difference.has_value(), "a hook that lands on instructions, that nothing jumps into");
    const SiteReport& accessor = site(a, "param_entity");
    t.check(accessor.region && accessor.region->window && accessor.region->begin == s.leaf && accessor.region->end == s.leaf + 14, "code without an entry is compared over its pattern");
    t.check(!accessor.hook_aligned.has_value() && !accessor.difference.has_value(), "the accessor is read, not hooked");
    const SiteReport& join = site(a, "join_line");
    t.check(join.rva == s.join + 10 && join.base_rva == old_sites.join + 10 && join.hook_aligned == true, "the join hook is at the call");
    t.check(join.region && !join.region->window && join.region->begin == s.join, "compared over the function that holds it");

    Options with_depot;
    with_depot.depot = "9";
    t.check(run(t, base, next, with_depot).edit.added.depot == "9", "a depot that is given goes to the new row");

    const Analysis plain = run(t, base, exe_of(bumped()));
    t.check(plain.verdict == Verdict::Easy && plain.edit.added.expected == std::vector<uint32_t>{old_sites.alpha, old_sites.beta, old_sites.leaf, old_sites.chat}, "a new fingerprint over the same code");

    ExeLayout tagged = bumped();
    tagged.join.tag = 0x5678;
    t.check(run(t, base, exe_of(tagged)).verdict == Verdict::Easy, "a value the code reads as its own is not a difference");

    ExeLayout edge = bumped();
    edge.other_target = 0;
    t.check(run(t, base, exe_of(edge)).verdict == Verdict::Easy, "a jump to the first byte of a hook is no jump into it");
    edge.other_target = 0x6f;
    t.check(run(t, base, exe_of(edge)).verdict == Verdict::Easy, "nor is a jump to where the second join hook starts");

    Options second;
    second.catalog = replaced(catalog_text(base), R"("builds": [)",
                              R"("builds": [)"
                              "\n"
                              R"(    {"label": "50", "buildids": ["50"], "time_date_stamp": 4, "size_of_image": "0x1000", "sigset": "s", "mining_layout": "m", )"
                              R"("steam": {"depot": null, "manifest": null, "exe_sha256": null}, "expected": {}},)");
    const Analysis later = run(t, base, next, second);
    t.check(later.verdict == Verdict::Easy && later.base_label == "100" && later.edit.row == 1, "the new row follows the row of the previous exe wherever it is");

    ExeLayout jumping = bumped();
    jumping.join.after = 0xe9;
    ExeLayout jumping_base;
    jumping_base.join.after = 0xe9;
    t.check(run(t, exe_of(jumping_base), exe_of(jumping)).verdict == Verdict::Easy, "a join call followed by a jump is the other form the hook accepts");

    ExeLayout switched_base;
    switched_base.alpha_switch = true;
    ExeLayout switched = shifted();
    switched.alpha_switch = true;
    const Analysis with_table = run(t, exe_of(switched_base), exe_of(switched));
    t.check(with_table.verdict == Verdict::Easy && with_table.reasons.empty() && !site(with_table, "alpha").difference.has_value(), "a function that ends in a jump table is easy when it moves");
    t.check(site(with_table, "alpha").region && site(with_table, "alpha").region->end == sites_of(switched).beta, "and is compared whole, table included");
}

void check_hard_code(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});
    const ExeSites s = sites_of(base.layout);

    ExeLayout grown = bumped();
    grown.extra_nop = true;
    const Analysis changed = run(t, base, exe_of(grown));
    t.check(changed.verdict == Verdict::Hard && mentions(changed, "alpha") && changed.edit.kind == Edit::Kind::None, "a function that holds another instruction is hard");
    t.check(site(changed, "alpha").difference && site(changed, "alpha").difference->kind == "bytes" && site(changed, "alpha").difference->rva == s.alpha + 12 &&
                site(changed, "alpha").difference->base_rva == s.alpha + 12,
            "and the report says where");
    t.check(!site(changed, "beta").difference.has_value(), "while the functions that did not change have no difference");

    ExeLayout landing = bumped();
    landing.other_target = 4;
    const Analysis into = run(t, base, exe_of(landing));
    t.check(into.verdict == Verdict::Hard && mentions(into, "alpha") && site(into, "alpha").into_hook.size() == 1, "a jump into the bytes a hook overwrites is hard");
    t.check(site(into, "alpha").into_hook.size() == 1 && site(into, "alpha").into_hook[0].from == s.other && site(into, "alpha").into_hook[0].target == s.alpha + 4, "and the report names the jump");
    landing.other_target = 0x6c;
    const Analysis into_call = run(t, base, exe_of(landing));
    t.check(into_call.verdict == Verdict::Hard && mentions(into_call, "join_line") && site(into_call, "join_line").into_hook.size() == 1, "also into the join call");
    landing.other_target = 0x70;
    const Analysis into_next = run(t, base, exe_of(landing));
    t.check(into_next.verdict == Verdict::Hard && mentions(into_next, "join_line") && site(into_next, "join_line").into_hook.size() == 1, "and into the instruction after it");

    ExeLayout table_base;
    table_base.alpha_switch = true;
    ExeLayout other_entry = bumped();
    other_entry.alpha_switch = true;
    other_entry.switch_entry = 0x14;
    const Analysis retargeted = run(t, exe_of(table_base), exe_of(other_entry));
    t.check(retargeted.verdict == Verdict::Hard && mentions(retargeted, "alpha") && site(retargeted, "alpha").difference && site(retargeted, "alpha").difference->kind == "table",
            "a jump table entry that goes elsewhere is hard");

    ExeLayout hooked_base;
    hooked_base.alpha_switch = true;
    hooked_base.switch_entry = 2;
    ExeLayout hooked_entry = hooked_base;
    hooked_entry.time_date_stamp = 101;
    const Analysis hooked = run(t, exe_of(hooked_base), exe_of(hooked_entry));
    const SiteReport& hooked_alpha = site(hooked, "alpha");
    t.check(hooked.verdict == Verdict::Hard && !hooked_alpha.difference.has_value() && hooked_alpha.into_hook.size() == 1, "a jump table entry inside the bytes a hook overwrites is hard");
    t.check(hooked_alpha.into_hook.size() == 1 && hooked_alpha.into_hook[0].from == s.alpha + 0x18 && hooked_alpha.into_hook[0].target == s.alpha + 2, "and the report names the load that reads the table");
}

void check_hard_sites(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});
    const ExeSites s = sites_of(base.layout);

    ExeLayout twice = bumped();
    twice.duplicate_beta = true;
    const Analysis dup = run(t, base, exe_of(twice));
    t.check(dup.verdict == Verdict::Hard && mentions(dup, "beta: 2 matches") && site(dup, "beta").matches == 2 && !site(dup, "beta").rva.has_value(), "a pattern that matches twice is hard");
    ExeLayout lost = bumped();
    lost.lose_gamma = true;
    const Analysis gone = run(t, base, exe_of(lost));
    t.check(gone.verdict == Verdict::Hard && mentions(gone, "chat_post: 0 matches") && site(gone, "chat_post").matches == 0, "a pattern that matches nowhere is hard");
    t.check(mentions(gone, "cannot be checked"), "and the join call, which needs it, says it cannot be checked");
    ExeLayout chat_twice = bumped();
    chat_twice.duplicate_gamma = true;
    const Analysis ambiguous = run(t, base, exe_of(chat_twice));
    t.check(ambiguous.verdict == Verdict::Hard && mentions(ambiguous, "chat_post: 2 matches") && mentions(ambiguous, "cannot be checked"), "so does a chat_post that matches twice");

    ExeLayout leaf = bumped();
    leaf.leaf_changed = true;
    const Analysis indexed = run(t, base, exe_of(leaf));
    t.check(indexed.verdict == Verdict::Hard && mentions(indexed, "param_entity") && site(indexed, "param_entity").difference &&
                site(indexed, "param_entity").difference->rva == s.leaf + 10,
            "an accessor whose window differs is hard");
}

void check_hard_join(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});

    ExeLayout no_join_base;
    no_join_base.join.lose = true;
    const Analysis no_reference = run(t, exe_of(no_join_base), exe_of(bumped()));
    t.check(no_reference.verdict == Verdict::Hard && mentions(no_reference, "join_line"), "a site the previous exe does not have once cannot be compared");
    ExeLayout no_join = bumped();
    no_join.join.lose = true;
    t.check(mentions(run(t, base, exe_of(no_join)), "join_line"), "a site the exe does not have");

    ExeLayout elsewhere_base;
    elsewhere_base.join.calls_chat = false;
    ExeLayout elsewhere = bumped();
    elsewhere.join.calls_chat = false;
    const Analysis not_chat = run(t, exe_of(elsewhere_base), exe_of(elsewhere));
    t.check(not_chat.verdict == Verdict::Hard && mentions(not_chat, "join_line"), "a join call that does not go to chat_post is hard");
    ExeLayout jump_base;
    jump_base.join.jumps = true;
    ExeLayout jump = bumped();
    jump.join.jumps = true;
    const Analysis jumped = run(t, exe_of(jump_base), exe_of(jump));
    t.check(jumped.verdict == Verdict::Hard && mentions(jumped, "is not a call"), "a jump to chat_post where the join call should be is hard");
    Options at_mov;
    at_mov.catalog = replaced(catalog_text(base), R"("offset": "0xa")", R"("offset": "0x0")");
    const Analysis off_call = run(t, base, exe_of(bumped()), at_mov);
    t.check(off_call.verdict == Verdict::Hard && mentions(off_call, "is not a call"), "a join site that is not on the call is hard, whatever else the function calls");
    ExeLayout other_after_base;
    other_after_base.join.after = 0x48;
    ExeLayout other_after = bumped();
    other_after.join.after = 0x48;
    const Analysis odd = run(t, exe_of(other_after_base), exe_of(other_after));
    t.check(odd.verdict == Verdict::Hard && mentions(odd, "join_line"), "a join call followed by anything else is hard");
    ExeLayout changed_after = bumped();
    changed_after.join.after = 0xe9;
    const Analysis swapped = run(t, base, exe_of(changed_after));
    t.check(swapped.verdict == Verdict::Hard && mentions(swapped, "join_line") && site(swapped, "join_line").difference, "the join function is compared too");
}

void check_hard_catalog(compat_test::Suite& t) {
    using enum Verdict;
    const Exe base = exe_of(ExeLayout{});

    const Analysis listed = run(t, base, exe_of(bumped()), with_id("900"));
    t.check(listed.verdict == Hard && mentions(listed, "already listed") && listed.edit.kind == Edit::Kind::None, "a build id another row lists");
    const Analysis labeled = run(t, base, exe_of(bumped()), with_id("legacy"));
    t.check(labeled.verdict == Hard && mentions(labeled, "label of another row") && labeled.edit.kind == Edit::Kind::None, "a build id that is the label of another row");

    const std::string no_expected_operand = replaced(catalog_text(base), R"(,)"
                                                                         "\n"
                                                                         R"(     "expected_operands": {)" +
                                                                             entry("entity_table", 0x830) + "}",
                                                     "");
    Options base_without;
    base_without.catalog = no_expected_operand;
    const Analysis no_base = run(t, base, exe_of(bumped()), base_without);
    t.check(no_base.verdict == Hard && mentions(no_base, "entity_table"), "a base that has no accessor operand to carry over is hard");
    Options sigset_without;
    sigset_without.catalog = replaced(no_expected_operand, R"(, "operands": {"entity_table": "0x6"})", "");
    const Analysis no_sigset = run(t, base, exe_of(bumped()), sigset_without);
    t.check(no_sigset.verdict == Hard && mentions(no_sigset, "entity_table"), "and so is a sigset that has no accessor");
}

void check_hard_hooks(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});
    const ExeSites s = sites_of(base.layout);

    const std::string through_call = "b8 11 11 11 11 48 89 d9 74 02 90 90 e8 ?? ?? ?? ??";
    std::string last_bytes = "c3";
    for (int i = 0; i < 31; ++i) {
        last_bytes += " cc";
    }
    const auto alpha_as = [&](std::string_view bytes, uint32_t offset, uint32_t rva) {
        Options o;
        o.catalog = replaced(replaced(catalog_text(base), R"("site": "alpha", "bytes": "b8 11 11 11 11 48 89 d9", "offset": "0x0")",
                                      std::format(R"("site": "alpha", "bytes": "{}", "offset": "{}")", bytes, hex(offset))),
                             entry("alpha", s.alpha), entry("alpha", rva));
        return o;
    };
    const auto alpha_at = [&](uint32_t offset) { return alpha_as(through_call, offset, s.alpha + offset); };
    const Analysis misaligned = run(t, base, exe_of(bumped()), alpha_as("b8 11 11 11 11 48 89 d9", 1, s.alpha + 1));
    t.check(misaligned.verdict == Verdict::Hard && mentions(misaligned, "alpha") && site(misaligned, "alpha").hook_aligned == false, "a hook that does not start an instruction is hard");
    const Analysis outside = run(t, base, exe_of(bumped()), alpha_as(last_bytes, 0x1c, s.outside_function + 0x1c));
    t.check(outside.verdict == Verdict::Hard && mentions(outside, "outside .text"), "a hook outside .text is hard");

    ExeLayout into_span = bumped();
    into_span.other_target = 0x11 + 6;
    const Analysis deep = run(t, base, exe_of(into_span), alpha_at(0x11));
    t.check(deep.verdict == Verdict::Hard && site(deep, "alpha").into_hook.size() == 1, "a jump into the rest of an instruction the hook overwrites is hard");
    into_span.other_target = 0x11 + 7;
    t.check(run(t, base, exe_of(into_span), alpha_at(0x11)).verdict == Verdict::Easy, "a jump to the instruction after the overwritten bytes is not");

    ExeLayout twice_base;
    twice_base.duplicate_beta = true;
    const Exe doubled_base = exe_of(twice_base);
    Options no_beta;
    no_beta.catalog = replaced(catalog_text(doubled_base), ", " + entry("beta", s.beta), "");
    const Analysis unclear = run(t, doubled_base, exe_of(bumped()), no_beta);
    t.check(unclear.verdict == Verdict::Hard && mentions(unclear, "no single match") && !site(unclear, "beta").base_rva.has_value(), "a site the previous exe has twice cannot be compared");
}

// The same exe under a new fingerprint: only the extra function and the branch map differ between the two builds.
Analysis judge_extra(compat_test::Suite& t, const ExeLayout& layout) {
    ExeLayout next = layout;
    next.time_date_stamp = 101;
    return run(t, exe_of(layout), exe_of(next));
}

void check_branch_map(compat_test::Suite& t) {
    using enum Verdict;
    const ExeSites s = sites_of(ExeLayout{});
    ExeLayout beyond;
    beyond.extra = Extra::Table;
    const Analysis away = judge_extra(t, beyond);
    t.check(away.verdict == Easy && away.undecodable_functions == 0U, "a jump table in another function whose entries stay clear of the hook is easy");
    beyond.switch_entry = 2;
    for (const bool chained : {true, false}) {
        beyond.extra_chained = chained;
        const Analysis into = judge_extra(t, beyond);
        const SiteReport& alpha = site(into, "alpha");
        t.check(into.verdict == Hard && alpha.into_hook.size() == 1 && alpha.into_hook[0].from == s.alpha + 0x18 && alpha.into_hook[0].target == s.alpha + 2,
                "a jump table in another function with an entry inside the bytes the hook overwrites is hard");
    }

    ExeLayout stray;
    stray.extra = Extra::Garbage;
    const Analysis lone = judge_extra(t, stray);
    t.check(lone.verdict == Easy && lone.undecodable_functions == 1U, "a function that cannot be decoded, tied to no site, leaves the verdict and is counted");
    stray.extra_chained = true;
    const Analysis chunk = judge_extra(t, stray);
    t.check(chunk.verdict == Hard && mentions(chunk, "alpha") && chunk.undecodable_functions == 1U, "a chunk of the hooked function that cannot be decoded is hard");

    ExeLayout jumper;
    jumper.extra = Extra::JumpIn;
    const Analysis tied = judge_extra(t, jumper);
    t.check(tied.verdict == Hard && mentions(tied, "alpha") && site(tied, "alpha").into_hook.empty(), "a function that cannot be decoded after a jump into the hooked function is hard");
    jumper.extra_target = 0xc8;
    t.check(judge_extra(t, jumper).verdict == Easy, "one whose jump goes to another function is not");

    ExeLayout unlisted;
    unlisted.unlist_beta = true;
    const Analysis window = judge_extra(t, unlisted);
    t.check(window.verdict == Hard && mentions(window, "beta") && site(window, "beta").region && site(window, "beta").region->window, "a hook in code the exception table does not list is hard");
    t.check(!run(t, exe_of(ExeLayout{}), exe_of(ExeLayout{})).undecodable_functions.has_value(), "a known build builds no map");
}

void check_edit(compat_test::Suite& t) {
    const Exe base = exe_of(ExeLayout{});
    Catalog catalog = load(catalog_text(base));
    const Analysis easy = run(t, base, exe_of(shifted()));
    t.check(livemap::compat::apply_edit(catalog, easy.edit).has_value() && catalog.rows().size() == 4, "an easy build adds a row");
    const livemap::compat::BuildRow& added = catalog.rows().back();
    t.check(added.label == "200" && added.time_date_stamp == 101 && !added.expected.empty() && added.expected[0].value == sites_of(shifted()).alpha, "that is the row the analysis described");

    const Analysis known = run(t, base, base, with_id("300"));
    t.check(livemap::compat::apply_edit(catalog, known.edit).has_value() && catalog.row_with_build_id("300") == 0U, "a known build adds an alias to its row");
    const livemap::compat::BuildRow& aliased = catalog.rows()[0];
    t.check(aliased.manifest == "5555" && aliased.depot == "7" && aliased.exe_sha256 == base.sha, "and the manifest of the new build to that row, which keeps its depot and checksum");

    const size_t rows = catalog.rows().size();
    const std::string before = livemap::compat::write_json(catalog.document());
    const Analysis hard = run(t, base, exe_of(bumped()), with_id("900"));
    t.check(livemap::compat::apply_edit(catalog, hard.edit).has_value() && catalog.rows().size() == rows && livemap::compat::write_json(catalog.document()) == before, "a hard build changes nothing");

    Edit stale = known.edit;
    t.check(!livemap::compat::apply_edit(catalog, stale).has_value(), "an edit that the catalog refuses is an error");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_inputs(t);
    check_known(t);
    check_easy(t);
    check_hard_code(t);
    check_hard_sites(t);
    check_hard_join(t);
    check_hard_catalog(t);
    check_hard_hooks(t);
    check_branch_map(t);
    check_edit(t);
    return t.result();
}
