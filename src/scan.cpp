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

const Build* recognise(const IMAGE_NT_HEADERS64* nt) {
    for (const Build& b : kBuilds) {
        if (nt->FileHeader.TimeDateStamp == b.time_date_stamp && nt->OptionalHeader.SizeOfImage == b.size_of_image) return &b;
    }
    return nullptr;
}

bool join_sites(const uint8_t* code, size_t size, const Pattern& join, const Pattern& post, ChatSites& out) {
    const std::vector<uintptr_t> hits = find_all(code, size, parse(join.bytes));
    if (hits.size() != 1) return false;
    int count = 0;
    uintptr_t chat = find_unique(code, size, post, count);
    const Named* tag = find_operand(join, "join_tag");
    if (chat == 0 || tag == nullptr) return false;
    chat += post.offset;
    const uintptr_t call = hits[0] + join.offset;
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
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    char buf[160];
    const Build* build = recognise(nt);
    if (build == nullptr) {
        std::snprintf(buf, sizeof buf, "unknown server build (TimeDateStamp %lu, SizeOfImage 0x%lx), not hooking",
                      nt->FileHeader.TimeDateStamp, nt->OptionalHeader.SizeOfImage);
        error = buf;
        return false;
    }
    out.build = build->label;
    out.mining_layout = build->mining_layout;
    const IMAGE_SECTION_HEADER* text = nullptr;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) text = &sec[i];
    }
    if (text == nullptr) {
        error = "no .text section";
        return false;
    }
    const uint8_t* code = base + text->VirtualAddress;
    const size_t size = text->Misc.VirtualSize;
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
        const uintptr_t start = find_unique(code, size, p, count);
        out.*member = start == 0 ? 0 : start + p.offset;
        if (start != 0) {
            if (const Named* table = find_operand(p, "entity_table")) {
                std::memcpy(&out.entity_table, reinterpret_cast<const void*>(start + table->value), sizeof out.entity_table);
            }
        } else if (p.mandatory) {
            error = std::format("pattern '{}' matched {} times (need exactly 1), not hooking", p.site, count);
            return false;
        }
    }
    return true;
}

bool find_chat_sites(const uint8_t* base, ChatSites& out) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    const uint8_t* code = nullptr;
    size_t size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::memcmp(sec[i].Name, ".text", 5) == 0) {
            code = base + sec[i].VirtualAddress;
            size = sec[i].Misc.VirtualSize;
        }
    }
    for (const Sigset& set : kSigsets) {
        const Pattern* join = nullptr;
        const Pattern* post = nullptr;
        for (const Pattern& p : set.patterns) {
            if (std::strcmp(p.site, kJoinLineSite) == 0) join = &p;
            if (std::strcmp(p.site, "chat_post") == 0) post = &p;
        }
        if (join != nullptr && post != nullptr && join_sites(code, size, *join, *post, out)) return true;
    }
    return false;
}

}  // namespace livemap
