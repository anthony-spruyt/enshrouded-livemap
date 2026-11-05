// The report is the contract with the workflow that reads it: its keys, the hex form of RVAs, and nothing from the game's bytes.
#include <string>
#include <string_view>
#include <vector>

#include "analyze.h"
#include "json.h"
#include "report.h"
#include "test_support.h"

using livemap::compat::Analysis;
using livemap::compat::Json;
using livemap::compat::report_json;
using livemap::compat::Verdict;

namespace {

std::string text_at(const Json& value, std::string_view key) {
    const Json* found = value.find(key);
    return found == nullptr ? "<missing>" : found->text();
}

const Json& member(const Json& value, std::string_view key) {
    static const Json kMissing = Json::null();
    const Json* found = value.find(key);
    return found == nullptr ? kMissing : *found;
}

Analysis sample() {
    Analysis a;
    a.verdict = Verdict::Easy;
    a.build_id = "300";
    a.manifest = "400";
    a.exe = {1793800000, 0x1ddf000, "ab"};
    a.base_label = "200";
    a.base_sigset = "patch1";
    a.reasons = {"first", "second"};
    a.operands = {{"entity_table", 0x838}};

    livemap::compat::SiteReport moved;
    moved.site = "movement";
    moved.mandatory = true;
    moved.matches = 1;
    moved.rva = 0x2010;
    moved.base_rva = 0x1ff0;
    moved.region = livemap::compat::Region{false, 0x2000, 0x2100};
    moved.base_region = livemap::compat::Region{true, 0x1fe0, 0x20f0};
    moved.hook_aligned = false;
    moved.into_hook = {{0x3000, 0x2012}};
    moved.difference = livemap::compat::Difference{"branch", 0x2044, 0x2024};
    a.sites.push_back(moved);

    livemap::compat::SiteReport missing;
    missing.site = "chest";
    missing.matches = 0;
    a.sites.push_back(missing);
    return a;
}

}  // namespace

int main() {
    compat_test::Suite t;
    const Json report = report_json(sample());

    t.check(report.keys() == std::vector<std::string>{"result", "build_id", "manifest", "exe", "base", "matched_row", "reasons", "undecodable_functions", "operands", "sites"}, "the keys, in reading order");
    t.check(text_at(report, "result") == "easy" && text_at(report, "build_id") == "300" && text_at(report, "manifest") == "400", "verdict and ids");
    const Json& exe = member(report, "exe");
    t.check(exe.find("time_date_stamp")->as_uint() == 1793800000U && text_at(exe, "size_of_image") == "0x1ddf000" && text_at(exe, "sha256") == "ab", "the fingerprint and checksum of the exe");
    t.check(text_at(member(report, "base"), "label") == "200" && text_at(member(report, "base"), "sigset") == "patch1", "the build compared against");
    t.check(member(report, "matched_row").kind() == Json::Kind::Null, "no matched row for a new fingerprint");
    t.check(member(report, "reasons").items().size() == 2 && member(report, "reasons").items()[1].text() == "second", "reasons in order");
    t.check(text_at(member(report, "operands"), "entity_table") == "0x838", "operands in hex");
    t.check(member(report, "undecodable_functions").kind() == Json::Kind::Null, "no count when no map of the branches was built");

    const Json& sites = member(report, "sites");
    t.check(sites.items().size() == 2, "a site for each pattern");
    const Json& moved = sites.items()[0];
    t.check(text_at(moved, "site") == "movement" && member(moved, "mandatory").as_bool() && member(moved, "matches").as_uint() == 1U, "site, flag and match count");
    t.check(text_at(moved, "rva") == "0x2010" && text_at(moved, "base_rva") == "0x1ff0", "positions in hex");
    t.check(text_at(member(moved, "region"), "kind") == "function" && text_at(member(moved, "region"), "begin") == "0x2000" && text_at(member(moved, "region"), "end") == "0x2100", "the function compared");
    t.check(text_at(member(moved, "base_region"), "kind") == "window" && text_at(member(moved, "base_region"), "begin") == "0x1fe0", "a window stands in for code without an entry");
    t.check(member(moved, "hook_aligned").kind() == Json::Kind::Bool && !member(moved, "hook_aligned").as_bool(), "alignment of the hook");
    const Json& into = member(moved, "branches_into_hook");
    t.check(into.items().size() == 1 && text_at(into.items()[0], "from") == "0x3000" && text_at(into.items()[0], "to") == "0x2012", "a branch into the hook");
    const Json& difference = member(moved, "difference");
    t.check(text_at(difference, "kind") == "branch" && text_at(difference, "rva") == "0x2044" && text_at(difference, "base_rva") == "0x2024", "the first difference");

    const Json& missing = sites.items()[1];
    t.check(member(missing, "mandatory").kind() == Json::Kind::Bool && !member(missing, "mandatory").as_bool() && member(missing, "matches").as_uint() == 0U, "a site that is not found");
    t.check(member(missing, "rva").kind() == Json::Kind::Null && member(missing, "base_rva").kind() == Json::Kind::Null && member(missing, "region").kind() == Json::Kind::Null &&
                member(missing, "base_region").kind() == Json::Kind::Null && member(missing, "hook_aligned").kind() == Json::Kind::Null && member(missing, "difference").kind() == Json::Kind::Null,
            "has nothing to say about positions");
    t.check(member(missing, "branches_into_hook").kind() == Json::Kind::Array && member(missing, "branches_into_hook").items().empty(), "and no branches");

    Analysis known = sample();
    known.verdict = Verdict::Known;
    known.matched_label = "250";
    const Json known_report = report_json(known);
    t.check(text_at(known_report, "result") == "known" && text_at(known_report, "matched_row") == "250", "the row a known build matched");
    Analysis hard = sample();
    hard.verdict = Verdict::Hard;
    t.check(text_at(report_json(hard), "result") == "hard", "hard");
    Analysis counted = sample();
    counted.undecodable_functions = 7;
    t.check(member(report_json(counted), "undecodable_functions").as_uint() == 7U, "the count of functions that could not be decoded");
    counted.undecodable_functions = 0;
    t.check(member(report_json(counted), "undecodable_functions").kind() == Json::Kind::Number && member(report_json(counted), "undecodable_functions").as_uint() == 0U, "a count of none is a number, not a missing value");

    const auto reread = livemap::compat::parse_json(livemap::compat::write_json(report));
    t.check(reread.has_value() && livemap::compat::write_json(*reread) == livemap::compat::write_json(report), "the report is valid JSON that reads back the same");
    return t.result();
}
