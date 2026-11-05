// The tables generated from data/builds.json reproduce the shipped builds of tests/builds_snapshot.h.
// No game bytes involved.
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <format>
#include <memory>
#include <print>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "builds_generated.h"
#include "builds_snapshot.h"
#include "scan.h"

namespace {

int failures = 0;

void check(bool ok, std::string_view detail, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}  {}\n", where.file_name(), where.line(), detail);
        ++failures;
    }
}

const livemap::Named* find(std::span<const livemap::Named> list, const char* name) {
    const auto it = std::ranges::find_if(list, [name](const livemap::Named& n) { return std::strcmp(n.name, name) == 0; });
    return it == list.end() ? nullptr : std::to_address(it);
}

void check_sigset(const livemap::Sigset& generated, const std::vector<snapshot::Site>& want) {
    check(generated.patterns.size() == want.size(),
          std::format("sigset {} has {} patterns, want {}", generated.name, generated.patterns.size(), want.size()));
    for (size_t i = 0; i < want.size() && i < generated.patterns.size(); ++i) {
        const livemap::Pattern& got = generated.patterns[i];
        const snapshot::Site& expect = want[i];
        check(std::strcmp(got.site, expect.name) == 0,
              std::format("{}[{}] is {}, want {}", generated.name, i, got.site, expect.name));
        check(expect.hex == got.bytes, std::format("{} {} bytes differ", generated.name, expect.name));
        check(got.offset == expect.offset,
              std::format("{} {} offset 0x{:x}, want 0x{:x}", generated.name, expect.name, got.offset, expect.offset));
        check(got.mandatory == expect.mandatory,
              std::format("{} {} mandatory flag differs", generated.name, expect.name));
        check(got.operands.size() == expect.operands.size(),
              std::format("{} {} has {} operands, want {}", generated.name, expect.name, got.operands.size(), expect.operands.size()));
        for (const snapshot::Operand& op : expect.operands) {
            const livemap::Named* named = find(got.operands, op.name);
            check(named != nullptr && named->value == op.offset,
                  std::format("{} {} operand {} differs", generated.name, expect.name, op.name));
        }
    }
}

void check_expected(const livemap::Build& build, const snapshot::Row& row) {
    struct SiteRva {
        const char* site;
        uint32_t rva;
    };
    const auto sites = std::to_array<SiteRva>({
        {"player_table", row.player_table},
        {"movement", row.movement},
        {"daytime", row.daytime},
        {"registry", row.registry},
        {"mining", row.mining},
        {"chest", row.chest},
        {"bases", row.bases},
        {"chat_post", row.chat_post},
        {"param_entity", row.param_entity},
    });
    size_t checked = 0;
    for (const auto& s : sites) {
        if (s.rva == 0) {
            continue;
        }
        ++checked;
        const livemap::Named* named = find(build.expected, s.site);
        check(named != nullptr && named->value == s.rva,
              std::format("{} expected rva of {} differs", row.label, s.site));
    }
    check(build.expected.size() == checked,
          std::format("{} expects {} sites, want {}", row.label, build.expected.size(), checked));
    const livemap::Named* table = find(build.expected_operands, "entity_table");
    check(row.entity_table == 0 ? build.expected_operands.empty() : (table != nullptr && table->value == row.entity_table),
          std::format("{} expected entity_table differs", row.label));
}

// A site name the code does not know would leave the build unhookable at run time.
void check_sites_fill_a_slot() {
    for (const livemap::Sigset& set : livemap::kSigsets) {
        for (const livemap::Pattern& p : set.patterns) {
            if (std::string_view(p.site) == "join_line") {
                continue;
            }
            check(livemap::target_member(p.site) != nullptr,
                  std::format("sigset {}: site {} fills no Targets slot", set.name, p.site));
        }
    }
}

}  // namespace

int main() {
    // Builds and sigsets added later are fine; the ones that shipped must not change.
    for (const snapshot::Row& row : snapshot::kRows) {
        const livemap::Build* found = nullptr;
        for (const livemap::Build& b : livemap::kBuilds) {
            if (std::strcmp(b.label, row.label) == 0) {
                found = &b;
            }
        }
        check(found != nullptr, std::format("build {} is missing from builds.json", row.label));
        if (found == nullptr) {
            continue;
        }
        const livemap::Build& build = *found;
        check(build.time_date_stamp == row.time_date_stamp, std::format("{} TimeDateStamp differs", row.label));
        check(build.size_of_image == row.size_of_image, std::format("{} SizeOfImage differs", row.label));
        check(build.mining_layout == (row.patch1 ? livemap::MiningLayout::StackRecord : livemap::MiningLayout::InlineArray),
              std::format("{} mining layout differs", row.label));
        check(std::strcmp(build.sigset->name, row.patch1 ? "patch1" : "launch") == 0,
              std::format("{} uses sigset {}", row.label, build.sigset->name));
        check_expected(build, row);
    }
    for (const char* name : {"launch", "patch1"}) {
        const livemap::Sigset* found = nullptr;
        for (const livemap::Sigset& candidate : livemap::kSigsets) {
            if (std::strcmp(candidate.name, name) == 0) {
                found = &candidate;
            }
        }
        check(found != nullptr, std::format("sigset {} is missing from builds.json", name));
        if (found != nullptr) {
            check_sigset(*found, std::strcmp(name, "launch") == 0 ? snapshot::launch_sites() : snapshot::patch1_sites());
        }
    }
    check_sites_fill_a_slot();
    if (failures == 0) {
        std::puts("builds.json reproduces the hard-coded builds");
    }
    return failures == 0 ? 0 : 1;
}
