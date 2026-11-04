// The tables generated from data/builds.json reproduce the shipped builds of tests/builds_snapshot.h.
// No game bytes involved.
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "builds_generated.h"
#include "builds_snapshot.h"
#include "scan.h"

namespace {

int failures = 0;

#define EXPECT(cond, ...)                                               \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d  %s  ", __FILE__, __LINE__, #cond); \
            std::printf(__VA_ARGS__);                                   \
            std::printf("\n");                                          \
            ++failures;                                                 \
        }                                                               \
    } while (0)

const livemap::Named* find(std::span<const livemap::Named> list, const char* name) {
    for (size_t i = 0; i < list.size(); ++i) {
        if (std::strcmp(list[i].name, name) == 0) {
            return &list[i];
        }
    }
    return nullptr;
}

void check_sigset(const livemap::Sigset& generated, const std::vector<snapshot::Site>& want) {
    EXPECT(generated.patterns.size() == want.size(), "sigset %s has %zu patterns, want %zu", generated.name,
           generated.patterns.size(), want.size());
    for (size_t i = 0; i < want.size() && i < generated.patterns.size(); ++i) {
        const livemap::Pattern& got = generated.patterns[i];
        const snapshot::Site& expect = want[i];
        EXPECT(std::strcmp(got.site, expect.name) == 0, "%s[%zu] is %s, want %s", generated.name, i, got.site, expect.name);
        EXPECT(expect.hex == got.bytes, "%s %s bytes differ", generated.name, expect.name);
        EXPECT(got.offset == expect.offset, "%s %s offset 0x%x, want 0x%zx", generated.name, expect.name, got.offset, expect.offset);
        EXPECT(got.mandatory == expect.mandatory, "%s %s mandatory flag differs", generated.name, expect.name);
        EXPECT(got.operands.size() == expect.operands.size(), "%s %s has %zu operands, want %zu", generated.name,
               expect.name, got.operands.size(), expect.operands.size());
        for (const snapshot::Operand& op : expect.operands) {
            const livemap::Named* named = find(got.operands, op.name);
            EXPECT(named != nullptr && named->value == op.offset, "%s %s operand %s differs", generated.name, expect.name, op.name);
        }
    }
}

void check_expected(const livemap::Build& build, const snapshot::Row& row) {
    struct {
        const char* site;
        uint32_t rva;
    } sites[] = {
        {"player_table", row.player_table},
        {"movement", row.movement},
        {"daytime", row.daytime},
        {"registry", row.registry},
        {"mining", row.mining},
        {"chest", row.chest},
        {"bases", row.bases},
        {"chat_post", row.chat_post},
        {"param_entity", row.param_entity},
    };
    size_t checked = 0;
    for (const auto& s : sites) {
        if (s.rva == 0) {
            continue;
        }
        ++checked;
        const livemap::Named* named = find(build.expected, s.site);
        EXPECT(named != nullptr && named->value == s.rva, "%s expected rva of %s differs", row.label, s.site);
    }
    EXPECT(build.expected.size() == checked, "%s expects %zu sites, want %zu", row.label, build.expected.size(), checked);
    const livemap::Named* table = find(build.expected_operands, "entity_table");
    EXPECT(row.entity_table == 0 ? build.expected_operands.empty() : (table != nullptr && table->value == row.entity_table),
           "%s expected entity_table differs", row.label);
}

// A site name the code does not know would leave the build unhookable at run time.
void check_sites_fill_a_slot() {
    for (const livemap::Sigset& set : livemap::kSigsets) {
        for (const livemap::Pattern& p : set.patterns) {
            if (std::string_view(p.site) == "join_line") {
                continue;
            }
            EXPECT(livemap::target_member(p.site) != nullptr, "sigset %s: site %s fills no Targets slot", set.name, p.site);
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
        EXPECT(found != nullptr, "build %s is missing from builds.json", row.label);
        if (found == nullptr) {
            continue;
        }
        const livemap::Build& build = *found;
        EXPECT(build.time_date_stamp == row.time_date_stamp, "%s TimeDateStamp differs", row.label);
        EXPECT(build.size_of_image == row.size_of_image, "%s SizeOfImage differs", row.label);
        EXPECT(build.mining_layout == (row.patch1 ? livemap::MiningLayout::StackRecord : livemap::MiningLayout::InlineArray),
               "%s mining layout differs", row.label);
        EXPECT(std::strcmp(build.sigset->name, row.patch1 ? "patch1" : "launch") == 0, "%s uses sigset %s", row.label,
               build.sigset->name);
        check_expected(build, row);
    }
    for (const char* name : {"launch", "patch1"}) {
        const livemap::Sigset* found = nullptr;
        for (const livemap::Sigset& candidate : livemap::kSigsets) {
            if (std::strcmp(candidate.name, name) == 0) {
                found = &candidate;
            }
        }
        EXPECT(found != nullptr, "sigset %s is missing from builds.json", name);
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
