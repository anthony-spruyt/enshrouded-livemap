// The command line end to end: files in, a report and an extended builds file out, and the exit code for each kind of failure.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "builds.h"
#include "cli.h"
#include "exe_fixture.h"
#include "json.h"
#include "sha256.h"
#include "test_support.h"

using compat_test::ExeLayout;
using livemap::compat::Catalog;
using livemap::compat::Json;

namespace {

// Files go in the working directory under a fixed prefix and are removed on exit.
class Workspace {
public:
    Workspace() = default;
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;
    ~Workspace() {
        for (const std::string& name : names_) {
            std::remove(name.c_str());
        }
    }

    std::string file(std::string_view name) {
        std::string full = std::format("livemap_compat_cli_test_{}", name);
        names_.push_back(full);
        return full;
    }

    static bool exists(const std::string& path) { return std::ifstream(path).good(); }

private:
    std::vector<std::string> names_;
};

void write_bytes(const std::string& path, const std::vector<std::byte>& bytes) {
    std::vector<char> chars;
    std::ranges::transform(bytes, std::back_inserter(chars), [](std::byte b) { return static_cast<char>(std::to_underlying(b)); });
    std::ofstream(path, std::ios::binary).write(chars.data(), static_cast<std::streamsize>(chars.size()));
}

void write_text(const std::string& path, std::string_view text) {
    std::ofstream(path, std::ios::binary) << text;
}

std::string read_text(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    std::stringstream text;
    text << file.rdbuf();
    return text.str();
}

Json parse_file(const std::string& path) {
    auto parsed = livemap::compat::parse_json(read_text(path));
    if (!parsed) {
        std::cout << "not JSON: " << path << ": " << parsed.error() << "\n";
        std::exit(2);
    }
    return std::move(*parsed);
}

constexpr std::string_view kBuilds = R"({
  "sigsets": {"s": [
    {"site": "alpha", "bytes": "b8 11 11 11 11 48 89 d9", "offset": "0x0", "mandatory": true},
    {"site": "param_entity", "bytes": "4c 8b d9 48 8b 81 ?? ?? ?? ?? 8b 04 ?? c3", "offset": "0x0", "mandatory": true, "operands": {"entity_table": "0x6"}},
    {"site": "chat_post", "bytes": "b8 33 33 33 33 48 89 d9", "offset": "0x0", "mandatory": false},
    {"site": "join_line", "bytes": "b8 44 44 44 44 b9 ?? ?? ?? ??", "offset": "0xa", "mandatory": false, "operands": {"join_tag": "0x6"}}
  ]},
  "builds": [
    {"label": "100", "buildids": ["100"], "time_date_stamp": 100, "size_of_image": "0x10000", "sigset": "s", "mining_layout": "m",
     "steam": {"depot": "7", "manifest": "8", "exe_sha256": "@SHA@"},
     "expected": {"alpha": "0x1000", "param_entity": "@LEAF@", "chat_post": "@CHAT@"},
     "expected_operands": {"entity_table": "0x830"}}
  ]
})";

struct Run {
    int code = -1;
    std::string out;
    std::string err;
};

Run cli(const std::vector<std::string>& args) {
    const std::vector<std::string_view> views(args.begin(), args.end());
    std::ostringstream out;
    std::ostringstream err;
    const int code = livemap::compat::run_cli(views, out, err);
    return {code, out.str(), err.str()};
}

std::string text_of(const Json& value, std::string_view key) {
    const Json* found = value.find(key);
    return found == nullptr ? "<missing>" : found->text();
}

}  // namespace

int main() {
    compat_test::Suite t;
    Workspace dir;
    const ExeLayout old_layout;
    const auto old_file = compat_test::build_exe(old_layout);
    ExeLayout moved_layout;
    moved_layout.time_date_stamp = 101;
    moved_layout.lead = 0x40;
    moved_layout.entity_table = 0x838;
    ExeLayout grown_layout = moved_layout;
    grown_layout.extra_nop = true;
    const auto sites = compat_test::sites_of(old_layout);
    std::string builds(kBuilds);
    builds.replace(builds.find("@SHA@"), 5, livemap::compat::sha256_hex(old_file));
    builds.replace(builds.find("@LEAF@"), 6, std::format("0x{:x}", sites.leaf));
    builds.replace(builds.find("@CHAT@"), 6, std::format("0x{:x}", sites.chat));

    write_text(dir.file("builds.json"), builds);
    write_bytes(dir.file("previous.exe"), old_file);
    const auto moved_file = compat_test::build_exe(moved_layout);
    write_bytes(dir.file("moved.exe"), moved_file);
    write_bytes(dir.file("grown.exe"), compat_test::build_exe(grown_layout));
    write_text(dir.file("garbage.exe"), "not an exe");

    const auto args = [&](std::string_view exe, std::string_view id, std::string_view out_name) {
        return std::vector<std::string>{"--builds", dir.file("builds.json"), "--previous", dir.file("previous.exe"), "--exe", dir.file(exe), "--build-id", std::string(id), "--manifest", "5555", "--depot", "9",
                                        "--report", dir.file(std::string(out_name) + ".report.json"), "--builds-out", dir.file(std::string(out_name) + ".builds.json")};
    };

    const Run easy = cli(args("moved.exe", "200", "easy"));
    t.check(easy.code == 0 && easy.out.starts_with("easy: build 200") && easy.err.empty(), "an easy build exits 0 and says so");
    const Json easy_report = parse_file(dir.file("easy.report.json"));
    t.check(text_of(easy_report, "result") == "easy" && text_of(easy_report, "build_id") == "200" && text_of(easy_report, "manifest") == "5555", "the report holds the verdict");
    auto extended = Catalog::from_json(parse_file(dir.file("easy.builds.json")));
    t.check(extended.has_value() && extended->rows().size() == 2 && extended->rows()[1].label == "200", "the extended builds file holds one more row");
    t.check(extended.has_value() && extended->rows()[1].expected_operands.size() == 1 && extended->rows()[1].expected_operands[0].value == 0x838, "with the operand read from the new exe");
    t.check(extended.has_value() && extended->rows()[1].exe_sha256 == livemap::compat::sha256_hex(moved_file), "and the checksum of the new exe");
    t.check(read_text(dir.file("builds.json")) == builds, "and the builds file that was read is not touched");

    t.check(extended.has_value() && extended->rows()[1].depot == "9", "and the depot given on the command line");

    const Run known = cli(args("previous.exe", "300", "known"));
    t.check(known.code == 0 && known.out.starts_with("known: build 300"), "the exe of a row under a new build id is known");
    auto aliased = Catalog::from_json(parse_file(dir.file("known.builds.json")));
    t.check(aliased.has_value() && aliased->rows().size() == 1 && aliased->row_with_build_id("300") == 0U, "and gets an alias");

    const Run hard = cli(args("grown.exe", "200", "hard"));
    t.check(hard.code == 0 && hard.out.starts_with("hard: build 200") && hard.out.contains("alpha"), "a hard build exits 0 and lists the reasons");
    t.check(text_of(parse_file(dir.file("hard.report.json")), "result") == "hard" && !Workspace::exists(dir.file("hard.builds.json")), "and writes no builds file");
    write_text(dir.file("stale.builds.json"), "left by an earlier run");
    t.check(cli(args("grown.exe", "200", "stale")).code == 0 && !Workspace::exists(dir.file("stale.builds.json")), "and removes the builds file an earlier run left at that path");

    std::vector<std::string> report_only = args("moved.exe", "200", "report_only");
    report_only.resize(report_only.size() - 2);
    t.check(cli(report_only).code == 0 && !Workspace::exists(dir.file("report_only.builds.json")), "the builds file is optional");

    const Run missing = cli(args("absent.exe", "200", "missing"));
    t.check(missing.code == 1 && missing.err.contains("absent.exe") && !Workspace::exists(dir.file("missing.report.json")), "an exe that cannot be read exits 1");
    t.check(cli(args("garbage.exe", "200", "garbage")).code == 1, "a file that is not an exe exits 1");
    std::vector<std::string> wrong_previous = args("moved.exe", "200", "wrong_previous");
    wrong_previous[3] = dir.file("moved.exe");
    write_text(dir.file("wrong_previous.builds.json"), "left by an earlier run");
    t.check(cli(wrong_previous).code == 1 && !Workspace::exists(dir.file("wrong_previous.builds.json")), "a previous exe no row describes exits 1 and leaves no builds file from an earlier run");
    std::vector<std::string> over_input = args("moved.exe", "200", "over_input");
    over_input[15] = dir.file("builds.json");
    const Run overwrite = cli(over_input);
    t.check(overwrite.code == 1 && overwrite.err.contains("input") && read_text(dir.file("builds.json")) == builds, "a builds file written over an input is refused and the input stays");
    std::vector<std::string> no_builds = args("moved.exe", "200", "no_builds");
    no_builds[1] = dir.file("absent.json");
    const Run no_catalog = cli(no_builds);
    t.check(no_catalog.code == 1 && no_catalog.err.contains("absent.json"), "a builds file that cannot be read exits 1");
    std::vector<std::string> no_previous = args("moved.exe", "200", "no_previous");
    no_previous[3] = dir.file("absent_previous.exe");
    const Run lost_previous = cli(no_previous);
    t.check(lost_previous.code == 1 && lost_previous.err.contains("absent_previous.exe"), "a previous exe that cannot be read exits 1");
    write_text(dir.file("broken.json"), "{");
    no_builds[1] = dir.file("broken.json");
    t.check(cli(no_builds).code == 1, "a builds file that is not JSON exits 1");
    std::vector<std::string> nowhere = args("moved.exe", "200", "nowhere");
    nowhere[13] = dir.file("no/such/dir/report.json");
    t.check(cli(nowhere).code == 1, "a report that cannot be written exits 1");

    const Run none = cli({});
    t.check(none.code == 2 && none.err.contains("usage"), "no arguments exits 2 with the usage");
    std::vector<std::string> unknown = args("moved.exe", "200", "unknown");
    unknown.insert(unknown.end(), {"--verbose", "1"});
    t.check(cli(unknown).code == 2 && cli(unknown).err.contains("--verbose"), "an argument that does not exist exits 2");
    std::vector<std::string> dangling = args("moved.exe", "200", "dangling");
    dangling.emplace_back("--depot");
    const Run no_value = cli(dangling);
    t.check(no_value.code == 2 && no_value.err.contains("--depot needs a value"), "a flag without a value exits 2");
    std::vector<std::string> twice = args("moved.exe", "200", "twice");
    twice.insert(twice.end(), {"--exe", dir.file("moved.exe")});
    t.check(cli(twice).code == 2, "a flag given twice exits 2");
    std::vector<std::string> lacking = args("moved.exe", "200", "lacking");
    lacking.erase(lacking.begin() + 8, lacking.begin() + 10);
    t.check(cli(lacking).code == 2 && cli(lacking).err.contains("--manifest"), "a missing flag exits 2 and names it");
    std::vector<std::string> no_depot = args("moved.exe", "200", "no_depot");
    no_depot.erase(no_depot.begin() + 10, no_depot.begin() + 12);
    t.check(cli(no_depot).code == 2 && cli(no_depot).err.contains("--depot is required"), "a build cannot be added without the depot it belongs to");
    t.check(cli(args("moved.exe", "0200", "padded")).code == 2, "a build id with a leading zero exits 2");
    t.check(cli(args("moved.exe", "20x", "letters")).code == 2, "a build id with a letter exits 2");
    std::vector<std::string> bad_depot = args("moved.exe", "200", "bad_depot");
    bad_depot[11] = "-1";
    t.check(cli(bad_depot).code == 2, "a depot that is not an id exits 2");
    std::vector<std::string> bad_manifest = args("moved.exe", "200", "bad_manifest");
    bad_manifest[9] = "";
    t.check(cli(bad_manifest).code == 2, "a manifest that is not an id exits 2");

    const auto check = [&](std::string_view builds_name, std::string_view exe) {
        return cli({"check", "--builds", dir.file(builds_name), "--exe", dir.file(exe)});
    };
    const Run passed = check("builds.json", "previous.exe");
    t.check(passed.code == 0 && passed.out.starts_with("ok: row 100") && passed.err.empty(), "a check that finds nothing exits 0 and names the row");
    std::string unlisted = builds;
    unlisted.replace(unlisted.find(livemap::compat::sha256_hex(old_file)), 64, std::string(64, '0'));
    write_text(dir.file("unlisted.json"), unlisted);
    const Run failed = check("unlisted.json", "previous.exe");
    t.check(failed.code == 3 && failed.out.starts_with("failed: row 100") && failed.out.contains("checksum") && failed.err.empty(), "a check that finds a problem exits 3 and lists it");
    const Run unknown_exe = check("builds.json", "moved.exe");
    t.check(unknown_exe.code == 1 && unknown_exe.err.contains("fingerprint"), "an exe that no row describes exits 1");
    t.check(check("builds.json", "absent.exe").code == 1 && check("builds.json", "garbage.exe").code == 1, "an exe that cannot be read exits 1");
    t.check(check("absent.json", "previous.exe").code == 1 && check("broken.json", "previous.exe").code == 1, "a builds file that cannot be read exits 1");
    const Run bare = cli({"check"});
    t.check(bare.code == 2 && bare.err.contains("--builds is required") && bare.err.contains("usage: livemap_compat check"), "a check without arguments exits 2 with its usage");
    t.check(cli({"check", "--builds", dir.file("builds.json")}).err.contains("--exe is required"), "and one without the exe names it");
    const Run stray = cli({"check", "--builds", dir.file("builds.json"), "--exe", dir.file("previous.exe"), "--report", dir.file("x.json")});
    t.check(stray.code == 2 && stray.err.contains("--report"), "a check refuses the arguments of the analysis");
    return t.result();
}
