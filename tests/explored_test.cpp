// Plain assert-based tests for the explored-area store (no framework).
#include <cmath>
#include <print>
#include <source_location>
#include <string>
#include <vector>

#include "../src/explored.h"

using namespace livemap::explored;

static int failures = 0;

static void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
    }
}

int main() {
    // base64 round trips, including the padded lengths.
    for (size_t n : {0u, 1u, 2u, 3u, 4u, 5u, 100u}) {
        std::vector<uint8_t> d(n), back;
        for (size_t i = 0; i < n; ++i) {
            d[i] = static_cast<uint8_t>(i * 37 + 11);
        }
        check(unbase64(base64(d), back) && back == d);
    }
    check(base64({'M', 'a', 'n'}) == "TWFu");
    Store s;
    check(!s.explored("A", 5000, 5000));
    check(s.reveal("A", 5000, 5000));
    check(!s.reveal("A", 5000, 5000));                 // nothing new at the same spot
    check(s.explored("A", 5000, 5000));
    check(s.explored("A", 5000 + 280, 5000));          // inside 300 m
    check(s.explored("A", 5000, 5000 - 280));
    check(!s.explored("A", 5000 + 330, 5000));         // outside
    check(!s.explored("A", 5000 + 230, 5000 + 230));   // 325 m diagonally
    check(!s.explored("B", 5000, 5000));               // per player
    check(!s.reveal("A", -900, 5000));                 // far outside the world: ignored
    check(s.reveal("A", 10, 10));                       // at the edge: clipped, no crash
    check(s.explored("A", 0, 0));
    // Count the cells of one reveal: about pi * 15^2 = 707.
    Store c;
    c.reveal("C", 5010, 5010);
    int cells = 0;
    for (int row = 0; row < kCells; ++row) {
        for (int col = 0; col < kCells; ++col) {
            cells += c.explored("C", (col + 0.5) * kCellMetres, (row + 0.5) * kCellMetres);
        }
    }
    check(cells > 680 && cells < 740);
    // Round trip through the file format.
    s.reveal("Bro \"Two\"", 2000, 3000);
    Store t;
    check(t.from_json(s.to_json()));
    check(t.players() == 2);
    check(t.explored("A", 5000, 5000) && t.explored("Bro \"Two\"", 2000, 3000) && !t.explored("A", 2000, 3000));
    Store u;
    check(!u.from_json(R"({"cells":256,"players":{}})"));
    check(!u.from_json("garbage"));
    if (failures == 0) {
        std::print("explored: all passed (one reveal = {} cells)\n", cells);
    }
    return failures == 0 ? 0 : 1;
}
