#include "scan.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <format>
#include <vector>

#include "builds_generated.h"

namespace livemap {

namespace {

constexpr const char* kJoinLineSite = "join_line";
constexpr size_t kCallLength = 5;  // call or jmp with a rel32

struct Masked {
    std::vector<uint8_t> bytes;
    std::vector<bool> fixed;
};

// The .text section of the mapped image: every address the scan derives has to lie inside it.
struct Code {
    const uint8_t* begin = nullptr;
    size_t size = 0;

    bool holds(uintptr_t at, size_t length) const {
        const uintptr_t first = reinterpret_cast<uintptr_t>(begin);
        return begin != nullptr && at >= first && at - first < size && length <= size - (at - first);
    }
};

Code find_code(const uint8_t* base, const IMAGE_NT_HEADERS64* nt) {
    Code code;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            code.begin = base + sec[i].VirtualAddress;
            code.size = sec[i].Misc.VirtualSize;
        }
    }
    return code;
}

Masked parse(const char* text) {
    Masked p;
    for (const char* s = text; s[0] != 0 && s[1] != 0;) {
        if (*s == ' ') { ++s; continue; }
        if (s[0] == '?' && s[1] == '?') {
            p.bytes.push_back(0);
            p.fixed.push_back(false);
        } else {
            char hex[3] = {s[0], s[1], 0};
            p.bytes.push_back(static_cast<uint8_t>(std::strtoul(hex, nullptr, 16)));
            p.fixed.push_back(true);
        }
        s += 2;
    }
    return p;
}

std::vector<uintptr_t> find_all(const uint8_t* begin, size_t size, const Masked& p) {
    std::vector<uintptr_t> hits;
    const size_t n = p.bytes.size();
    size_t lead = 0;
    while (lead < n && !p.fixed[lead]) ++lead;
    if (lead == n) return hits;
    for (size_t i = 0; i + n <= size; ++i) {
        if (begin[i + lead] != p.bytes[lead]) continue;
        bool ok = true;
        for (size_t k = 0; k < n && ok; ++k) ok = !p.fixed[k] || begin[i + k] == p.bytes[k];
        if (ok) hits.push_back(reinterpret_cast<uintptr_t>(begin + i));
    }
    return hits;
}

uintptr_t call_target(uintptr_t call) {
    int32_t rel = 0;
    std::memcpy(&rel, reinterpret_cast<const void*>(call + 1), sizeof rel);
    return call + 5 + static_cast<intptr_t>(rel);
}

// Start of the pattern's only match, or 0 when it matches anywhere else than once (`count` says how often).
uintptr_t find_unique(const uint8_t* begin, size_t size, const Pattern& p, int& count) {
    const std::vector<uintptr_t> hits = find_all(begin, size, parse(p.bytes));
    count = static_cast<int>(hits.size());
    return count == 1 ? hits[0] : 0;
}

const Named* find_operand(const Pattern& p, const char* name) {
    for (const Named& op : p.operands) {
        if (std::strcmp(op.name, name) == 0) return &op;
    }
    return nullptr;
}

bool has_fingerprint(const IMAGE_NT_HEADERS64* nt, const Build& b) {
    return nt->FileHeader.TimeDateStamp == b.time_date_stamp && nt->OptionalHeader.SizeOfImage == b.size_of_image;
}

// The row of the image, or null when no row or more than one row has its fingerprint (`matches` says how many).
const Build* recognise(const IMAGE_NT_HEADERS64* nt, std::span<const Build> builds, size_t& matches) {
    const Build* found = nullptr;
    matches = 0;
    for (const Build& b : builds) {
        if (!has_fingerprint(nt, b)) continue;
        found = &b;
        ++matches;
    }
    return matches == 1 ? found : nullptr;
}

bool join_sites(const Code& code, const Pattern& join, const Pattern& post, ChatSites& out) {
    const std::vector<uintptr_t> hits = find_all(code.begin, code.size, parse(join.bytes));
    if (hits.size() != 1) return false;
    int count = 0;
    uintptr_t chat = find_unique(code.begin, code.size, post, count);
    const Named* tag = find_operand(join, "join_tag");
    if (chat == 0 || tag == nullptr) return false;
    chat += post.offset;
    const uintptr_t call = hits[0] + join.offset;
    // The call's five bytes and the opcode after them are read, the tag is copied out of the match.
    if (!code.holds(chat, 1) || !code.holds(call, kCallLength + 1) || !code.holds(hits[0] + tag->value, sizeof out.join_tag)) {
        return false;
    }
    const uint8_t call_op = *reinterpret_cast<const uint8_t*>(call);
    const uint8_t after_op = *reinterpret_cast<const uint8_t*>(call + kCallLength);
    if (call_op == 0xe8) {
        if (call_target(call) != chat) return false;
    } else if (call_op != 0xe9) {
        return false;  // neither the call nor another mod's jump to its hook
    }
    if (after_op != 0x44 && after_op != 0xe9) return false;
    out.join_call = call;
    out.join_after = call + kCallLength;
    out.chat_post = chat;
    out.shared = call_op == 0xe9;
    std::memcpy(&out.join_tag, reinterpret_cast<const void*>(hits[0] + tag->value), sizeof out.join_tag);
    return true;
}

}  // namespace

uintptr_t Targets::* target_member(std::string_view site) {
    static constexpr struct {
        std::string_view site;
        uintptr_t Targets::* member;
    } kMembers[] = {
        {"player_table", &Targets::player_table}, {"movement", &Targets::movement},
        {"daytime", &Targets::daytime},           {"registry", &Targets::registry},
        {"mining", &Targets::mining},             {"chest", &Targets::chest},
        {"chat_post", &Targets::chat_post},       {"bases", &Targets::bases},
        {"param_entity", &Targets::param_entity},
    };
    for (const auto& m : kMembers) {
        if (m.site == site) return m.member;
    }
    return nullptr;
}

bool find_targets(const uint8_t* base, Targets& out, std::string& error) {
    return find_targets(base, kBuilds, out, error);
}

bool find_targets(const uint8_t* base, std::span<const Build> builds, Targets& out, std::string& error) {
    out = Targets{};
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    char buf[160];
    size_t matches = 0;
    const Build* build = recognise(nt, builds, matches);
    if (build == nullptr) {
        if (matches == 0) {
            std::snprintf(buf, sizeof buf, "unknown server build (TimeDateStamp %lu, SizeOfImage 0x%lx), not hooking",
                          nt->FileHeader.TimeDateStamp, nt->OptionalHeader.SizeOfImage);
            error = buf;
        } else {
            error = std::format("more than one build in builds.json ({} rows) has the TimeDateStamp and SizeOfImage of this server, not hooking",
                                matches);
        }
        return false;
    }
    out.build = build->label;
    out.matched = build;
    out.mining_layout = build->mining_layout;
    const Code code = find_code(base, nt);
    if (code.begin == nullptr) {
        error = "no .text section";
        return false;
    }
    // Mandatory sites stop the hooking when they are not found exactly once; optional ones leave
    // their feature off and the rest keeps working.
    for (const Pattern& p : build->sigset->patterns) {
        if (std::strcmp(p.site, kJoinLineSite) == 0) continue;
        uintptr_t Targets::* const member = target_member(p.site);
        if (member == nullptr) {
            error = std::format("sigset '{}' has the unknown site '{}', not hooking", build->sigset->name, p.site);
            return false;
        }
        int count = 0;
        const uintptr_t start = find_unique(code.begin, code.size, p, count);
        out.*member = start == 0 ? 0 : start + p.offset;
        if (start != 0) {
            if (!code.holds(start + p.offset, 1)) {
                error = std::format("pattern '{}' puts its hook site outside .text, not hooking", p.site);
                return false;
            }
            if (const Named* table = find_operand(p, "entity_table")) {
                if (!code.holds(start + table->value, sizeof out.entity_table)) {
                    error = std::format("pattern '{}' reads its entity table outside .text, not hooking", p.site);
                    return false;
                }
                std::memcpy(&out.entity_table, reinterpret_cast<const void*>(start + table->value), sizeof out.entity_table);
            }
        } else if (p.mandatory) {
            error = std::format("pattern '{}' matched {} times (need exactly 1), not hooking", p.site, count);
            return false;
        }
    }
    // world::install hooks these whatever the sigset says about them.
    for (const char* site : kInstalledSites) {
        uintptr_t Targets::* const member = target_member(site);
        if (member == nullptr || out.*member == 0) {
            error = std::format("sigset '{}' does not find '{}', which is always hooked, not hooking", build->sigset->name, site);
            return false;
        }
    }
    return true;
}

bool find_chat_sites(const uint8_t* base, const Build& build, ChatSites& out) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (!has_fingerprint(nt, build)) return false;
    const Code code = find_code(base, nt);
    const Pattern* join = nullptr;
    const Pattern* post = nullptr;
    for (const Pattern& p : build.sigset->patterns) {
        if (std::strcmp(p.site, kJoinLineSite) == 0) join = &p;
        if (std::strcmp(p.site, "chat_post") == 0) post = &p;
    }
    return join != nullptr && post != nullptr && join_sites(code, *join, *post, out);
}

}  // namespace livemap
