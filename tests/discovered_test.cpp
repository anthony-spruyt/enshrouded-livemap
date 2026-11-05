// Plain assert-based tests for the discovered-markers store (no framework).
#include <print>
#include <source_location>
#include <string>

#include "../src/discovered.h"

using livemap::discovered::Store;

static int failures = 0;

static void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
    }
}

int main() {
    Store s;
    check(s.update("OG Vanilla K", {7, 3, 3, 0x7d496e64u}, 100));          // sorted, deduplicated
    check(!s.update("OG Vanilla K", {3, 7, 0x7d496e64u}, 200));            // same set: no change
    const uint64_t v = s.version();
    check(s.update("OG Vanilla K", {3, 7, 9, 0x7d496e64u}, 300));
    check(s.version() > v);
    check(s.update("Bro \"Two\"", {1}, 400));
    std::string json = s.to_json();
    check(json.contains(R"("OG Vanilla K":{"online":true,"at":300,"keys":[3,7,9,2101964388]})"));
    check(json.contains(R"("Bro \"Two\"")"));
    // Logging out keeps the set, only the flag changes.
    s.set_online({"OG Vanilla K"});
    check(s.to_json().contains(R"("Bro \"Two\"":{"online":false,"at":400,"keys":[1]})"));
    // Round trip through the file format; loaded players count as offline until seen again.
    Store t;
    check(t.from_json(s.to_json()));
    check(t.players() == 2);
    std::string back = t.to_json();
    check(back.contains(R"("OG Vanilla K":{"online":false,"at":300,"keys":[3,7,9,2101964388]})"));
    check(back.contains(R"("Bro \"Two\"":{"online":false,"at":400,"keys":[1]})"));
    Store u;
    check(!u.from_json("not json"));
    check(u.players() == 0);
    check(u.from_json(R"({"version":1,"players":{}})"));
    if (failures == 0) {
        std::print("discovered: all passed\n");
    }
    return failures == 0 ? 0 : 1;
}
