// Offline check: maps an enshrouded_server.exe from disk (without running it) and runs the same
// build check and pattern search the DLL runs inside the server.
//
// Usage: livemap_selftest <path\to\enshrouded_server.exe>
// Exit code 0 = the mod would hook this build, 1 = it would stay inactive, 2 = usage/load error.
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

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
    const bool is_new = std::strcmp(t.build, "26083076") == 0;
    const bool patch1 = std::strcmp(t.build, "26319703") == 0;
    std::printf("server build %s\n", t.build);
    struct { const char* name; uintptr_t at; uintptr_t expected; } sites[] = {
        {"player_table", t.player_table, patch1 ? 0x7bed90ull : is_new ? 0x7b5800ull : 0x7b34c0ull},
        {"movement", t.movement, patch1 ? 0x9581aull : is_new ? 0x91d2aull : 0x90e7aull},
        {"daytime", t.daytime, patch1 ? 0x969be2ull : is_new ? 0x95f842ull : 0x95d1f2ull},
        {"registry", t.registry, patch1 ? 0x67e720ull : is_new ? 0x677240ull : 0x675e10ull},
        {"mining", t.mining, patch1 ? 0x22a01aull : is_new ? 0x2245a8ull : 0x2236f8ull},
        {"chest", t.chest, patch1 ? 0xa578aull : is_new ? 0xa1afaull : 0xa0c4aull},
        {"bases", t.bases, patch1 ? 0xee3f0ull : is_new ? 0xea090ull : 0xe91e0ull},
        {"chat_post", t.chat_post, patch1 ? 0x915170ull : is_new ? 0x90b330ull : 0x908ce0ull},
    };
    bool ok = true;
    for (const auto& s : sites) {
        uintptr_t rva = s.at - reinterpret_cast<uintptr_t>(base);
        ok = ok && rva == s.expected;
        std::printf("%-13s rva 0x%llx%s\n", s.name, static_cast<unsigned long long>(rva),
                    rva == s.expected ? "" : "  (UNEXPECTED)");
    }
    std::printf(ok ? "OK: all hook sites found\n" : "FAIL: a hook site moved\n");
    return ok ? 0 : 1;
}
