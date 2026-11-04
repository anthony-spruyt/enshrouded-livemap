// Offline check: maps an enshrouded_server.exe from disk (without running it) and runs the same
// build check and pattern search the DLL runs inside the server.
//
// Usage: livemap_selftest <path\to\enshrouded_server.exe>
// Exit code 0 = the mod would hook this build, 1 = it would stay inactive, 2 = usage/load error.
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <print>
#include <span>
#include <string>
#include <string_view>

#include "builds_generated.h"
#include "scan.h"

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: livemap_selftest <path\\to\\enshrouded_server.exe>\n");
        return 2;
    }
    HMODULE image = LoadLibraryExW(argv[1], nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (image == nullptr) {
        std::fprintf(stderr, "could not map %ls (error %lu)\n", argv[1], GetLastError());
        return 2;
    }
    auto base = reinterpret_cast<const uint8_t*>(image);
    livemap::Targets t;
    std::string error;
    if (!livemap::find_targets(base, t, error)) {
        std::printf("INACTIVE: %s\n", error.c_str());
        return 1;
    }
    const livemap::Build* row = nullptr;
    for (const livemap::Build& b : livemap::kBuilds) {
        if (std::strcmp(b.label, t.build) == 0) {
            row = &b;
        }
    }
    if (row == nullptr) {
        std::printf("INACTIVE: no expected RVAs for server build %s\n", t.build);
        return 1;
    }
    std::printf("server build %s\n", t.build);
    bool ok = true;
    const auto expected_of = [&](std::span<const livemap::Named> list, std::string_view name) -> const livemap::Named* {
        for (size_t i = 0; i < list.size(); ++i) {
            if (name == list[i].name) {
                return &list[i];
            }
        }
        return nullptr;
    };
    for (const livemap::Named& e : row->expected) {
        if (std::strcmp(e.name, "param_entity") == 0) {
            continue;
        }
        uintptr_t livemap::Targets::* const member = livemap::target_member(e.name);
        const uintptr_t at = member == nullptr ? 0 : t.*member;
        const uintptr_t rva = at - reinterpret_cast<uintptr_t>(base);
        const bool same = member != nullptr && rva == e.value;
        ok = ok && same;
        std::printf("%-13s rva 0x%llx%s\n", e.name, static_cast<unsigned long long>(rva), same ? "" : "  (UNEXPECTED)");
    }
    const uintptr_t accessor = t.param_entity == 0 ? 0 : t.param_entity - reinterpret_cast<uintptr_t>(base);
    const livemap::Named* expected_accessor = expected_of(row->expected, "param_entity");
    const livemap::Named* expected_table = expected_of(row->expected_operands, "entity_table");
    const bool accessor_ok = (expected_accessor == nullptr || accessor == expected_accessor->value) &&
                             (expected_table == nullptr || t.entity_table == expected_table->value);
    ok = ok && accessor_ok;
    std::println("{:<13} rva 0x{:x} entity table +0x{:x}{}", "param_entity", accessor, t.entity_table,
                 accessor_ok ? "" : "  (UNEXPECTED)");
    std::printf(ok ? "OK: all hook sites found\n" : "FAIL: a hook site moved\n");
    return ok ? 0 : 1;
}
