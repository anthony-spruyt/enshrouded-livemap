// The builds.json model: reading the rows and sigsets, adding an alias and appending a row like the previous one.
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "builds.h"
#include "json.h"
#include "test_support.h"

using livemap::compat::Catalog;
using livemap::compat::NewRow;
using livemap::compat::parse_json;
using livemap::compat::write_json;

namespace {

constexpr std::string_view kDocument = R"({
  "$schema": "./builds.schema.json",
  "sigsets": {
    "one": [
      {
        "site": "alpha",
        "bytes": "48 8b ?? 05",
        "offset": "0x2",
        "mandatory": true
      },
      {
        "site": "param_entity",
        "bytes": "01 ?? ?? ?? ?? 02",
        "offset": "0x0",
        "mandatory": false,
        "operands": {
          "entity_table": "0x1"
        }
      }
    ]
  },
  "builds": [
    {
      "label": "100",
      "buildids": [
        "100",
        "101"
      ],
      "time_date_stamp": 1793700549,
      "size_of_image": "0x1dde000",
      "sigset": "one",
      "mining_layout": "stack_record",
      "steam": {
        "depot": "2278521",
        "manifest": "7782830484557676320",
        "exe_sha256": "aa"
      },
      "expected": {
        "alpha": "0x1002",
        "param_entity": "0x65fc00"
      },
      "expected_operands": {
        "entity_table": "0x830"
      }
    },
    {
      "label": "77",
      "buildids": [
        "50"
      ],
      "time_date_stamp": 7,
      "size_of_image": "0x2000",
      "sigset": "one",
      "mining_layout": "inline_array",
      "steam": {
        "depot": null,
        "manifest": null,
        "exe_sha256": null
      },
      "expected": {
        "alpha": "0x10"
      }
    }
  ]
}
)";

Catalog load(std::string_view text) {
    return *Catalog::from_json(*parse_json(text));
}

std::string replaced(std::string_view text, std::string_view from, std::string_view to) {
    std::string out(text);
    out.replace(out.find(from), from.size(), to);
    return out;
}

void check_reading(compat_test::Suite& t) {
    const Catalog catalog = load(kDocument);
    t.check(catalog.rows().size() == 2 && catalog.sigsets().size() == 1, "two rows and one sigset");
    const auto& row = catalog.rows()[0];
    t.check(row.label == "100" && row.build_ids.size() == 2 && row.build_ids[1] == "101", "label and build ids");
    t.check(row.time_date_stamp == 1793700549U && row.size_of_image == 0x1dde000U, "fingerprint");
    t.check(row.sigset == "one" && row.depot == "2278521" && row.manifest == "7782830484557676320" && row.exe_sha256 == "aa", "sigset and steam block");
    t.check(row.expected.size() == 2 && row.expected[1].name == "param_entity" && row.expected[1].value == 0x65fc00U, "expected RVAs keep their order");
    t.check(row.expected_operands.size() == 1 && row.expected_operands[0].value == 0x830U, "expected operands");
    t.check(!catalog.rows()[1].depot.has_value() && !catalog.rows()[1].exe_sha256.has_value() && catalog.rows()[1].expected_operands.empty(), "null steam fields and no operands");

    const auto* sigset = catalog.sigset("one");
    t.check(sigset != nullptr && sigset->patterns.size() == 2 && catalog.sigset("other") == nullptr, "sigset lookup");
    if (sigset != nullptr) {
        const auto& alpha = sigset->patterns[0];
        t.check(alpha.site == "alpha" && alpha.bytes == "48 8b ?? 05" && alpha.offset == 2 && alpha.mandatory && alpha.operands.empty(), "a pattern");
        const auto& accessor = sigset->patterns[1];
        t.check(!accessor.mandatory && accessor.operands.size() == 1 && accessor.operands[0].name == "entity_table" && accessor.operands[0].value == 1, "a pattern with an operand");
    }
    t.check(write_json(catalog.document()) == kDocument, "reading changes nothing in the document");

    std::ifstream in(LIVEMAP_BUILDS_JSON, std::ios::binary);
    const std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const auto repo = Catalog::from_json(*parse_json(data));
    t.check(repo.has_value() && !repo->rows().empty(), "data/builds.json loads");
    if (repo) {
        for (const auto& row_of_repo : repo->rows()) {
            t.check(repo->sigset(row_of_repo.sigset) != nullptr, "every row names a sigset that exists");
        }
    }
}

bool fails_with(const std::string& text, std::string_view fragment) {
    const auto parsed = parse_json(text);
    if (!parsed) {
        return false;
    }
    const auto catalog = Catalog::from_json(*parsed);
    return !catalog.has_value() && catalog.error().contains(fragment);
}

void check_refusals(compat_test::Suite& t) {
    const auto refused = [&](std::string_view from, std::string_view to, std::string_view fragment, std::string_view why) {
        t.check(fails_with(replaced(kDocument, from, to), fragment), why);
    };
    refused(R"("sigset": "one",)"
            "\n"
            R"(      "mining_layout": "stack_record")",
            R"("sigset": "missing",)"
            "\n"
            R"(      "mining_layout": "stack_record")",
            "'missing'", "a row with an unknown sigset");
    refused(R"("mining_layout")", R"("layout")", "builds[0].mining_layout", "a row without a layout");
    refused(R"("0x1dde000")", R"("1dde000")", "builds[0].size_of_image", "hex without the prefix");
    refused(R"("0x1dde000")", R"("0x1dde0000000")", "builds[0].size_of_image", "hex past 32 bits");
    refused(R"("0x1dde000")", R"("0x01dde000")", "builds[0].size_of_image", "hex with a leading zero");
    refused(R"("0x1dde000")", R"("0x1DDE000")", "builds[0].size_of_image", "hex in upper case");
    refused(R"("0x1dde000")", R"("0x")", "builds[0].size_of_image", "hex without digits");
    refused(R"("0x1dde000")", R"("0x01")", "builds[0].size_of_image", "hex with a leading zero before one digit");
    t.check(Catalog::from_json(*parse_json(replaced(kDocument, R"("0x1dde000")", R"("0xffffffff")"))).has_value(), "hex of eight digits");
    refused(R"("time_date_stamp": 1793700549)", R"("time_date_stamp": "x")", "builds[0].time_date_stamp", "a time stamp that is no number");
    refused(R"("time_date_stamp": 1793700549)", R"("time_date_stamp": 4294967296)", "builds[0].time_date_stamp", "a time stamp past 32 bits");
    refused(R"("time_date_stamp": 1793700549)", R"("time_date_stamp": -1)", "builds[0].time_date_stamp", "a negative time stamp");
    refused(R"("label": "100")", R"("label": 100)", "builds[0].label", "a label that is no string");
    refused(R"("mandatory": true)", R"("mandatory": 1)", "sigsets.one[0].mandatory", "a mandatory flag that is no boolean");
    refused(R"("depot": "2278521")", R"("depot": 2278521)", "builds[0].steam.depot", "a depot that is neither string nor null");
    refused(R"("exe_sha256": "aa")", R"("exe_sha256": 5)", "builds[0].steam.exe_sha256", "a checksum that is neither string nor null");
    refused(R"("101")", R"("1x1")", "builds[0].buildids", "a build id that is no Steam id");
    refused(R"("101")", "101", "builds[0].buildids", "a build id that is a number");
    refused(R"("buildids": [)"
            "\n"
            R"(        "100",)"
            "\n"
            R"(        "101")"
            "\n"
            R"(      ])",
            R"("buildids": [])", "builds[0].buildids", "a row without build ids");
    refused(R"("buildids": [)"
            "\n"
            R"(        "100",)"
            "\n"
            R"(        "101")"
            "\n"
            R"(      ])",
            R"("buildids": {})", "builds[0].buildids", "build ids that are no list");
    refused(R"("alpha": "0x1002")", R"("alpha": 4098)", "builds[0].expected.alpha", "an expected RVA that is no string");
    refused(R"("expected_operands": {)"
            "\n"
            R"(        "entity_table": "0x830")"
            "\n"
            R"(      })",
            R"("expected_operands": 5)", "builds[0].expected_operands", "operands that are no object");
    refused(R"("bytes": "48 8b ?? 05")", R"("bytes": "48 8B")", "sigsets.one[0]: bytes", "bytes that are no signature");
    refused(R"("offset": "0x2")", R"("offset": "0x5")", "sigsets.one[0]: offset", "a hook offset past the pattern");
    refused(R"("entity_table": "0x1")", R"("entity_table": "0x3")", "entity_table", "an operand that runs past the pattern");
    refused(R"("entity_table": "0x1")", R"("entity_table": "0x7")", "entity_table", "an operand that starts past the pattern");
    t.check(Catalog::from_json(*parse_json(replaced(kDocument, R"("entity_table": "0x1")", R"("entity_table": "0x2")"))).has_value(), "an operand that ends on the last byte");
    t.check(Catalog::from_json(*parse_json(replaced(kDocument, R"("offset": "0x2")", R"("offset": "0x4")"))).has_value(), "a hook offset on the end of the pattern");

    const std::string row =
        R"({"label": "1", "buildids": ["1"], "time_date_stamp": 1, "size_of_image": "0x1", "sigset": "s", "mining_layout": "m", )"
        R"("steam": {"depot": null, "manifest": null, "exe_sha256": null}, "expected": {}})";
    const std::string pattern = R"({"site": "a", "bytes": "01", "offset": "0x0", "mandatory": true})";
    t.check(Catalog::from_json(*parse_json(R"({"sigsets": {"s": [)" + pattern + R"(]}, "builds": [)" + row + "]}")).has_value(), "the smallest document is accepted");
    t.check(fails_with("[]", "document"), "a document that is no object");
    t.check(fails_with(R"({"builds": []})", "sigsets"), "a document without sigsets");
    t.check(fails_with(R"({"sigsets": 5, "builds": []})", "sigsets"), "sigsets that are no object");
    t.check(fails_with(R"({"sigsets": {}})", "builds"), "a document without builds");
    t.check(fails_with(R"({"sigsets": {}, "builds": 5})", "builds"), "builds that are no list");
    t.check(fails_with(R"({"sigsets": {}, "builds": []})", "builds"), "no builds");
    t.check(fails_with(R"({"sigsets": {}, "builds": [5]})", "builds[0]"), "a row that is no object");
    t.check(fails_with(R"({"sigsets": {"s": 5}, "builds": [)" + row + "]}", "sigsets.s"), "a sigset that is no list");
    t.check(fails_with(R"({"sigsets": {"s": []}, "builds": [)" + row + "]}", "sigsets.s"), "a sigset without patterns");
    t.check(fails_with(R"({"sigsets": {"s": {"a": 1}}, "builds": [)" + row + "]}", "not a list"), "a sigset that is an object");
    t.check(fails_with(R"({"sigsets": {"s": [5]}, "builds": [)" + row + "]}", "sigsets.s[0]"), "a pattern that is no object");
}

NewRow sample() {
    NewRow row;
    row.build_id = "200";
    row.time_date_stamp = 1793800000;
    row.size_of_image = 0x1ddf000;
    row.manifest = "9999";
    row.exe_sha256 = std::string(64, 'b');
    row.expected = {0x2002, 0x700000};
    row.expected_operands = {0x838};
    return row;
}

size_t count_of(std::string_view text, std::string_view needle) {
    size_t n = 0;
    for (size_t at = text.find(needle); at != std::string_view::npos; at = text.find(needle, at + 1)) {
        ++n;
    }
    return n;
}

void check_alias(compat_test::Suite& t) {
    Catalog alias = load(kDocument);
    t.check(alias.add_alias(0, "102", "8888").has_value(), "an alias is accepted");
    t.check(alias.rows()[0].build_ids.size() == 3 && alias.rows()[0].build_ids[2] == "102", "the alias joins the typed row");
    t.check(alias.rows()[0].manifest == "8888" && alias.rows()[0].depot == "2278521" && alias.rows()[0].exe_sha256 == "aa", "the row takes the manifest of the alias, the one Steam serves, and keeps its depot and checksum");
    t.check(write_json(alias.document()) == replaced(replaced(kDocument, R"("101")"
                                                                         "\n",
                                                              R"("101",)"
                                                              "\n"
                                                              R"(        "102")"
                                                              "\n"),
                                                     "7782830484557676320", "8888"),
            "and the document, and nothing else changes");

    Catalog twice = load(kDocument);
    t.check(!twice.add_alias(0, "101", "8888").has_value() && !twice.add_alias(0, "50", "8888").has_value(), "an id the file already has is refused, in this row or another");
    t.check(!twice.add_alias(0, "0", "8888").has_value() && !twice.add_alias(0, "12x", "8888").has_value() && !twice.add_alias(0, "", "8888").has_value(), "an id that is no Steam id is refused");
    t.check(!twice.add_alias(0, "999999999999999999999", "8888").has_value() && write_json(twice.document()) == kDocument, "a refused alias changes nothing, and 21 digits are too many");
    t.check(!twice.add_alias(0, "103", "0").has_value() && !twice.add_alias(0, "103", "12x").has_value() && !twice.add_alias(0, "103", "").has_value(), "a manifest that is no Steam id is refused");
    t.check(!twice.add_alias(0, "103", "999999999999999999999").has_value() && write_json(twice.document()) == kDocument, "and then neither the id nor the manifest is written");
    t.check(twice.add_alias(0, "99999999999999999999", "99999999999999999999").has_value(), "20 digits are a Steam id");

    Catalog bare = load(kDocument);
    t.check(bare.add_alias(1, "51", "8888").has_value() && bare.rows()[1].manifest == "8888" && !bare.rows()[1].depot.has_value(), "a row that lists no manifest gets one, and nothing else of its Steam block");
}

void check_new_row(compat_test::Suite& t) {
    Catalog added = load(kDocument);
    t.check(added.append_row_like(0, sample()).has_value(), "a row like the first one is accepted");
    t.check(added.rows().size() == 3 && added.rows()[2].label == "200", "the new row is last, labelled with its build id");
    const auto& row = added.rows()[2];
    t.check(row.build_ids == std::vector<std::string>{"200"} && row.time_date_stamp == 1793800000U && row.size_of_image == 0x1ddf000U, "its ids and fingerprint");
    t.check(row.sigset == "one" && row.mining_layout == "stack_record" && row.depot == "2278521", "the sigset, layout and depot are the first row's");
    t.check(row.manifest == "9999" && row.exe_sha256 == std::string(64, 'b'), "the manifest and checksum are new");
    t.check(row.expected.size() == 2 && row.expected[0].name == "alpha" && row.expected[0].value == 0x2002U && row.expected[1].name == "param_entity" && row.expected[1].value == 0x700000U,
            "found RVAs under the first row's names");
    t.check(row.expected_operands.size() == 1 && row.expected_operands[0].name == "entity_table" && row.expected_operands[0].value == 0x838U, "found operands");

    const std::string text = write_json(added.document());
    const auto reread = parse_json(text);
    t.check(reread && write_json(*reread) == text, "the written document reads back the same");
    const auto before = std::string(kDocument.substr(0, kDocument.find("\n  ]\n}\n")));
    t.check(text.starts_with(before + R"(,)"
                                      "\n"
                                      R"(    {)"
                                      "\n"
                                      R"(      "label": "200",)"
                                      "\n"
                                      R"(      "buildids": [)"
                                      "\n"
                                      R"(        "200")"
                                      "\n"
                                      R"(      ],)"
                                      "\n"
                                      R"(      "time_date_stamp": 1793800000,)"
                                      "\n"),
            "everything before the new row is byte for byte the old document, and the row keeps the key order");
    t.check(text.ends_with("      }\n    }\n  ]\n}\n") && text.contains(R"("size_of_image": "0x1ddf000")") && text.contains(R"("entity_table": "0x838")"),
            "the size and operand are written as hex");
    const auto again = Catalog::from_json(*reread);
    t.check(again && again->rows().size() == 3 && again->rows()[2].expected[1].value == 0x700000U, "and the catalog reads the new row");

    NewRow other_depot = sample();
    other_depot.depot = "123";
    Catalog with_depot = load(kDocument);
    t.check(with_depot.append_row_like(0, other_depot).has_value() && with_depot.rows()[2].depot == "123", "a depot given for the new row wins");

    Catalog bare = load(kDocument);
    NewRow no_operands = sample();
    no_operands.expected = {0x20};
    no_operands.expected_operands = {};
    t.check(bare.append_row_like(1, no_operands).has_value(), "a row like one without operands is accepted");
    t.check(bare.rows()[2].expected_operands.empty() && !bare.rows()[2].depot.has_value() && count_of(write_json(bare.document()), "expected_operands") == 1,
            "it has no operands and keeps the null depot");
}

void check_new_row_refusals(compat_test::Suite& t) {
    const auto refused_row = [&](size_t like, const NewRow& row, std::string_view why) {
        Catalog catalog = load(kDocument);
        t.check(!catalog.append_row_like(like, row).has_value() && write_json(catalog.document()) == kDocument && catalog.rows().size() == 2, why);
    };
    const auto refused = [&](size_t like, const auto& change, std::string_view why) {
        NewRow row = sample();
        change(row);
        refused_row(like, row, why);
    };
    refused(0, [](NewRow& r) { r.build_id = "101"; }, "a build id another row has");
    refused(0, [](NewRow& r) { r.build_id = "77"; }, "a build id that is the label of a row");
    refused(0, [](NewRow& r) { r.build_id = "5x"; }, "a build id that is no Steam id");
    refused(0, [](NewRow& r) { r.manifest = "01"; }, "a manifest that is no Steam id");
    refused(0, [](NewRow& r) { r.depot = "x"; }, "a depot that is no Steam id");
    refused(0, [](NewRow& r) { r.exe_sha256 = std::string(63, 'a'); }, "a checksum that is too short");
    refused(0, [](NewRow& r) { r.exe_sha256 = std::string(64, 'A'); }, "a checksum in upper case");
    refused(0, [](NewRow& r) { r.exe_sha256 = std::string(65, 'a'); }, "a checksum that is too long");
    refused(0, [](NewRow& r) { r.expected.pop_back(); }, "fewer RVAs than the row copied has");
    refused(0, [](NewRow& r) { r.expected_operands.clear(); }, "fewer operands than the row copied has");
    refused(1, [](NewRow& r) { r.expected = {1, 2}; }, "more RVAs than the row copied has");
    refused_row(1, sample(), "operands for a row copied from one without");
    Catalog catalog = load(kDocument);
    t.check(!catalog.append_row_like(2, sample()).has_value() && !catalog.append_row_like(7, sample()).has_value(), "a row index past the end");
    t.check(!catalog.add_alias(2, "9", "8").has_value() && !catalog.add_alias(7, "9", "8").has_value(), "an alias for a row past the end");
}

void check_lookups(compat_test::Suite& t) {
    const Catalog catalog = load(kDocument);
    t.check(catalog.row_with_build_id("101") == 0U && catalog.row_with_build_id("50") == 1U && !catalog.row_with_build_id("51").has_value(), "rows by build id");
    t.check(catalog.row_with_label("77") == 1U && !catalog.row_with_label("50").has_value(), "rows by label");
    t.check(catalog.rows_with_fingerprint(7, 0x2000) == std::vector<size_t>{1} && catalog.rows_with_fingerprint(7, 0x2001).empty() && catalog.rows_with_fingerprint(8, 0x2000).empty(),
            "rows by fingerprint need both values");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_reading(t);
    check_refusals(t);
    check_alias(t);
    check_new_row(t);
    check_new_row_refusals(t);
    check_lookups(t);
    return t.result();
}
