// Plain assert-based tests for the finds store (no framework, runs on the build PC).
#include <cmath>
#include <cstdlib>
#include <print>
#include <source_location>
#include <string>

#include "../src/finds.h"

using livemap::finds::Store;

static int failures = 0;

static void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
    }
}

static void hits_within_6m_merge() {
    Store s;
    s.record_ore(100, 50, 200, "Material_T2_Ore_Copper", 10, "A", 1);
    s.record_ore(104, 50, 203, "Material_T2_Ore_Copper", 10, "A", 2);
    check(s.deposits() == 1);
}

static void hits_beyond_6m_start_a_new_deposit() {
    Store s;
    s.record_ore(100, 50, 200, "Material_T2_Ore_Copper", 10, "A", 1);
    s.record_ore(110, 50, 200, "Material_T2_Ore_Copper", 10, "A", 2);
    check(s.deposits() == 2);
}

static void different_sorts_never_merge() {
    Store s;
    s.record_ore(100, 50, 200, "Material_T2_Ore_Copper", 10, "A", 1);
    s.record_ore(101, 50, 200, "Material_T3_Ore_Tin", 15, "A", 2);
    check(s.deposits() == 2);
}

static void finders_are_deduplicated_and_position_averages() {
    Store s;
    s.record_ore(100, 50, 200, "", 10, "A", 1);
    s.record_ore(102, 50, 200, "", 10, "A", 2);
    s.record_ore(104, 50, 200, "", 10, "B", 3);
    std::string j = s.to_json();
    check(j.find("\"hits\":3") != std::string::npos);
    check(j.find("\"by\":[\"A\",\"B\"]") != std::string::npos);
    check(j.find("\"x\":102.0") != std::string::npos);
    check(j.find("\"sort\":null") != std::string::npos);
}

static void chest_is_recorded_once() {
    Store s;
    check(s.record_chest(10, 5, 20, 7, "A", 100));
    check(!s.record_chest(11, 5, 21, 7, "A", 100));   // same player, same time: nothing new
    check(s.record_chest(11, 5, 21, -1, "B", 200));   // same spot, later: updated
    check(s.chests() == 1);
    check(s.record_chest(50, 5, 20, -1, "B", 300));
    check(s.chests() == 2);
}

static void version_moves_on_change() {
    Store s;
    uint64_t v0 = s.version();
    s.record_ore(1, 1, 1, "", 0, "A", 1);
    check(s.version() == v0 + 1);
}

static void json_round_trip() {
    Store s;
    s.record_ore(100.25, 50, 200.5, "Material_T2_Ore_Copper", 10, "OG \"Vanilla\" K", 1792530000);
    s.record_ore(100, 50, 200, "", 7, "B", 1792530001);
    s.record_chest(10, 5, 20, 7, "A", 1792530002);
    s.record_chest(30, 5, 40, -1, "C", 1792530003, 1);
    s.record_chest(60, 5, 40, -1, "C", 1792530004, 0);
    std::string j = s.to_json();
    check(j.find("\"rl\":null") != std::string::npos);
    check(j.find("\"rl\":true") != std::string::npos);
    check(j.find("\"rl\":false") != std::string::npos);
    Store t;
    check(t.from_json(j));
    check(t.deposits() == 2);
    check(t.chests() == 3);
    check(t.version() == s.version());
    check(t.to_json() == j);
    check(!t.from_json("{\"ore\":[{\"x\":1,"));  // truncated
    check(t.from_json("{}"));
    check(t.deposits() == 0);
}

static void ore_like_filter() {
    check(livemap::finds::is_ore_like("Material_T2_Ore_Copper"));
    check(livemap::finds::is_ore_like("Material_T4_Sulfur"));
    check(livemap::finds::is_ore_like("Material_T1_Salt"));
    check(livemap::finds::is_ore_like("Material_T1_Stone_Flint"));  // flint veins (found in game 22 Oct)
    check(livemap::finds::is_ore_like("Material_T2_Clay"));        // clay pits (dug in game 23 Oct)
    check(!livemap::finds::is_ore_like("Material_T1_Stone"));
    check(!livemap::finds::is_ore_like("Material_T2_Copper_Bar"));
    check(!livemap::finds::is_ore_like("Prop_Deco_CopperJug"));
    check(!livemap::finds::is_ore_like("Material_T1_Twigs"));         // debris from ruins
    check(!livemap::finds::is_ore_like("Material_T2_Fired_Brick"));
    check(livemap::finds::is_ore_like("Material_T7_Diamond"));
}

int main() {
    hits_within_6m_merge();
    hits_beyond_6m_start_a_new_deposit();
    different_sorts_never_merge();
    finders_are_deduplicated_and_position_averages();
    chest_is_recorded_once();
    version_moves_on_change();
    json_round_trip();
    ore_like_filter();
    if (failures == 0) {
        std::print("finds tests passed\n");
        return EXIT_SUCCESS;
    }
    std::print("{} finds test(s) failed\n", failures);
    return EXIT_FAILURE;
}
