// The checks on the sigset of a row against its exe, run on synthetic exes with one small function for each hook site.
#include <algorithm>
#include <cstdlib>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "builds.h"
#include "check.h"
#include "json.h"
#include "pe.h"
#include "pe_builder.h"
#include "sha256.h"
#include "test_support.h"

using compat_test::bytes_of;
using livemap::compat::Catalog;
using livemap::compat::CheckResult;

namespace {

constexpr uint32_t kTextAt = 0x1000;
constexpr uint32_t kStride = 0x100;
constexpr uint32_t kStamp = 7;
constexpr std::string_view kZeroSha = "0000000000000000000000000000000000000000000000000000000000000000";

using Bytes = std::vector<std::byte>;

// One function of the exe that a pattern of the sigset covers whole.
struct Body {
    std::string site;
    Bytes code;
    uint32_t offset = 0;  // of the hook from the start of the pattern
    bool listed = true;   // in the exception table
};

Bytes plus(Bytes first, const Bytes& more) {
    first.insert(first.end(), more.begin(), more.end());
    return first;
}

// The code, a marker that no other function has, and a return.
Bytes function_of(size_t index, const Bytes& code) {
    return plus(plus(code, bytes_of({0x41, 0xba, static_cast<unsigned>(0x10 + index), 0, 0, 0})), bytes_of({0xc3}));
}

uint32_t begin_of(size_t index) {
    return kTextAt + static_cast<uint32_t>(index) * kStride;
}

std::string hex_bytes(const Bytes& bytes) {
    std::string text;
    for (const std::byte b : bytes) {
        text += std::format("{}{:02x}", text.empty() ? "" : " ", std::to_integer<unsigned>(b));
    }
    return text;
}

// A cold chunk of the function that holds a site: code of its own with its own entry in the exception table.
struct Chunk {
    size_t of = 0;  // the index of the body it continues
    Bytes code;
};

struct Exe {
    Bytes file;
    std::string sha;
    livemap::compat::Image image;
    std::vector<Body> bodies;
};

Exe exe_of(std::vector<Body> bodies, uint32_t stamp = kStamp, const std::vector<Chunk>& chunks = {}) {
    compat_test::PeSpec spec;
    spec.time_date_stamp = stamp;
    Bytes text(0x1000, std::byte{0xcc});
    for (size_t i = 0; i < bodies.size(); ++i) {
        bodies[i].code = function_of(i, bodies[i].code);
        std::ranges::copy(bodies[i].code, text.begin() + (begin_of(i) - kTextAt));
        if (bodies[i].listed) {
            spec.functions.emplace_back(begin_of(i), begin_of(i) + static_cast<uint32_t>(bodies[i].code.size()));
        }
    }
    for (size_t i = 0; i < chunks.size(); ++i) {
        const uint32_t begin = begin_of(bodies.size() + i);
        std::ranges::copy(chunks[i].code, text.begin() + (begin - kTextAt));
        spec.functions.emplace_back(begin, begin + static_cast<uint32_t>(chunks[i].code.size()), begin_of(chunks[i].of));
    }
    spec.sections.emplace_back(".text", kTextAt, text, 0);
    Exe exe;
    exe.file = compat_test::build_pe(spec);
    exe.sha = livemap::compat::sha256_hex(exe.file);
    auto image = livemap::compat::load_image(exe.file);
    if (!image) {
        std::cout << "the test exe is not a PE: " << image.error() << "\n";
        std::exit(2);
    }
    exe.image = std::move(*image);
    exe.bodies = std::move(bodies);
    return exe;
}

struct Row {
    std::string layout = "stack_record";
    std::string sha;  // empty: the checksum of the exe
    bool shifted = false;  // the row lists RVAs one byte off
};

std::string catalog_text(const Exe& exe, const Row& row = {}) {
    std::string patterns;
    std::string expected;
    for (size_t i = 0; i < exe.bodies.size(); ++i) {
        const Body& body = exe.bodies[i];
        patterns += std::format(R"({}{{"site": "{}", "bytes": "{}", "offset": "0x{:x}", "mandatory": false}})", i == 0 ? "" : ",", body.site, hex_bytes(body.code), body.offset);
        expected += std::format(R"({}"{}": "0x{:x}")", i == 0 ? "" : ",", body.site, begin_of(i) + body.offset + (row.shifted ? 1 : 0));
    }
    return std::format(R"({{"sigsets": {{"s": [{}]}}, "builds": [{{"label": "100", "buildids": ["100"], "time_date_stamp": {}, "size_of_image": "0x{:x}", "sigset": "s", "mining_layout": "{}",
        "steam": {{"depot": null, "manifest": null, "exe_sha256": "{}"}}, "expected": {{{}}}}}]}})",
                       patterns, kStamp, exe.image.size_of_image(), row.layout, row.sha.empty() ? exe.sha : row.sha, expected);
}

Catalog load(const std::string& text) {
    auto parsed = livemap::compat::parse_json(text);
    if (!parsed) {
        std::cout << "the test catalog is not JSON: " << parsed.error() << "\n";
        std::exit(2);
    }
    auto catalog = Catalog::from_json(std::move(*parsed));
    if (!catalog) {
        std::cout << "the test catalog is invalid: " << catalog.error() << "\n";
        std::exit(2);
    }
    return std::move(*catalog);
}

CheckResult run(compat_test::Suite& t, const Exe& exe, const Row& row = {}) {
    auto result = livemap::compat::check_exe(load(catalog_text(exe, row)), exe.image, exe.sha);
    t.check(result.has_value(), result ? "the check ran" : result.error());
    return result ? std::move(*result) : CheckResult{};
}

void passes(compat_test::Suite& t, const CheckResult& result, const std::string& name) {
    t.check(result.problems.empty(), result.problems.empty() ? name : std::format("{}: {}", name, result.problems.front()));
}

bool mentions(const CheckResult& result, std::string_view fragment) {
    return std::ranges::any_of(result.problems, [&](std::string_view problem) { return problem.contains(fragment); });
}

Bytes player_table() { return bytes_of({0x48, 0x89, 0xcb, 0x48, 0x89, 0xd8}); }                // mov rbx,rcx; mov rax,rbx
Bytes movement() { return bytes_of({0x48, 0x89, 0xd8, 0x48, 0x8b, 0x4c, 0x24, 0x08}); }       // mov rax,rbx; mov rcx,[rsp+8]
Bytes daytime() { return bytes_of({0x48, 0x01, 0xd8, 0x48, 0x89, 0xf8}); }                    // add rax,rbx; mov rax,rdi
Bytes registry() { return bytes_of({0x48, 0x89, 0xd1, 0x4c, 0x89, 0xc0}); }                   // mov rcx,rdx; mov rax,r8
Bytes mining() { return bytes_of({0x48, 0x01, 0xd8, 0x48, 0x01, 0xef}); }                     // add rax,rbx; add rdi,rbp
Bytes chest() { return bytes_of({0x48, 0x01, 0xef, 0x48, 0x8b, 0x44, 0x24, 0x08}); }          // add rdi,rbp; mov rax,[rsp+8]
Bytes bases() { return bytes_of({0x48, 0x8b, 0x45, 0xf8, 0x48, 0x89, 0xc1}); }                // mov rax,[rbp-8]; mov rcx,rax
Bytes join_line() { return bytes_of({0x48, 0x89, 0xc2, 0xe8, 0, 0, 0, 0, 0x31, 0xc0, 0x31, 0xc9, 0x90}); }  // mov rdx,rax; call; xor eax,eax; xor ecx,ecx; nop

std::vector<Body> all_sites() {
    return {{"player_table", player_table()}, {"movement", movement()}, {"daytime", daytime()}, {"registry", registry()}, {"mining", mining()}, {"chest", chest()}, {"bases", bases()}, {"join_line", join_line(), 3}};
}

Exe with(const std::string& site, const Bytes& code, uint32_t offset = 0, bool listed = true) {
    auto bodies = all_sites();
    const auto found = std::ranges::find(bodies, site, &Body::site);
    *found = Body{site, code, offset, listed};
    return exe_of(std::move(bodies));
}

// The site with `head`, then a jump to a cold chunk of its function that holds `cold`.
Exe with_cold(const std::string& site, const Bytes& head, const Bytes& cold, bool conditional = false) {
    auto bodies = all_sites();
    const auto found = std::ranges::find(bodies, site, &Body::site);
    const auto index = static_cast<size_t>(found - bodies.begin());
    const uint32_t jump_at = begin_of(index) + static_cast<uint32_t>(head.size());
    const uint32_t length = conditional ? 6 : 5;
    const uint32_t disp = begin_of(bodies.size()) - (jump_at + length);
    Bytes code = plus(head, conditional ? bytes_of({0x0f, 0x84}) : bytes_of({0xe9}));
    for (unsigned shift = 0; shift < 32; shift += 8) {
        code.push_back(static_cast<std::byte>(disp >> shift));
    }
    *found = Body{site, code, 0, true};
    return exe_of(std::move(bodies), kStamp, {Chunk{index, cold}});
}

void check_good(compat_test::Suite& t) {
    const Exe exe = exe_of(all_sites());
    const CheckResult result = run(t, exe);
    t.check(result.problems.empty(), result.problems.empty() ? "" : result.problems.front());
    t.check(result.label == "100" && result.sigset == "s", "the result names the row and its sigset");
    t.check(result.hooks == 9, "each hook counts, the join line has two");
}

void check_inputs(compat_test::Suite& t) {
    const Exe exe = exe_of(all_sites());
    const Exe other = exe_of(all_sites(), kStamp + 1);
    const auto unknown = livemap::compat::check_exe(load(catalog_text(exe)), other.image, other.sha);
    t.check(!unknown.has_value() && unknown.error().contains("fingerprint"), "an exe that no row describes cannot be checked");

    Row wrong;
    wrong.sha = kZeroSha;
    t.check(mentions(run(t, exe, wrong), "checksum"), "the exe is not the one the row lists");
    Row shifted;
    shifted.shifted = true;
    t.check(mentions(run(t, exe, shifted), "found at"), "the row lists another address than the sigset finds");
}

void check_alignment(compat_test::Suite& t) {
    t.check(mentions(run(t, with("movement", movement(), 1)), "does not start on an instruction"), "a hook inside an instruction");
    t.check(!mentions(run(t, with("movement", movement(), 3)), "does not start on an instruction"), "a hook on the second instruction is on an instruction");
    t.check(mentions(run(t, with("movement", movement(), 0, false)), "exception table"), "code the exception table does not list");

    const Bytes long_call = bytes_of({0xff, 0x15, 0, 0, 0, 0, 0x90, 0x90, 0x90});  // call [rip+0]: the second hook falls inside it
    t.check(mentions(run(t, with("join_line", long_call)), "join_line: the hook at"), "the second hook of the join line is on an instruction too");
}

void check_branches(compat_test::Suite& t) {
    const Bytes lands_in = bytes_of({0x48, 0x89, 0xd8, 0x48, 0x8b, 0x4c, 0x24, 0x08, 0x85, 0xc0, 0x75, 0xf7});
    t.check(mentions(run(t, with("movement", lands_in)), "branches land inside"), "a branch to the second instruction of the hook");

    const Bytes lands_at = bytes_of({0x48, 0x89, 0xd8, 0x48, 0x8b, 0x4c, 0x24, 0x08, 0x85, 0xc0, 0x75, 0xf4});
    t.check(!mentions(run(t, with("movement", lands_at)), "branches land inside"), "a branch to the first instruction is no problem");

    const Bytes after = plus(bytes_of({0xe8, 0, 0, 0, 0, 0x31, 0xc0, 0x31, 0xc9, 0x90, 0x85, 0xc0}), bytes_of({0x75, 0xf9}));
    t.check(mentions(run(t, with("join_line", after)), "branches land inside"), "a branch into the second hook of the join line");
}

void check_registers(compat_test::Suite& t) {
    t.check(mentions(run(t, with("bases", bytes_of({0xbd, 1, 0, 0, 0, 0x48, 0x89, 0xe8}))), "rbp"), "a register the code overwrites before it reads it");
    t.check(mentions(run(t, with("player_table", bytes_of({0x48, 0x89, 0xd8, 0x48, 0x89, 0xc1}))), "on_player_table"), "the callback is named");
    passes(t, run(t, with("bases", plus(bytes_of({0x48, 0x89, 0xc1, 0x48, 0x89, 0xc2}), bytes_of({0x48, 0x8b, 0x45, 0xf8})))), "a register the code reads after the hook counts");
    t.check(mentions(run(t, with("registry", bytes_of({0x48, 0x89, 0xd1, 0x48, 0x89, 0xc8}))), "r8"), "one of two registers is not used");

    const Exe mining_exe = with("mining", mining());
    passes(t, run(t, mining_exe), "the registers of the stack record layout");
    Row inline_array;
    inline_array.layout = "inline_array";
    t.check(mentions(run(t, mining_exe, inline_array), "r15"), "the registers of the inline array layout are another set");
    Row unknown;
    unknown.layout = "flat";
    t.check(mentions(run(t, mining_exe, unknown), "mining layout"), "a layout that no callback is written for");
}

void check_following(compat_test::Suite& t) {
    const Bytes mov_rcx = bytes_of({0x48, 0x89, 0xc1});  // mov rcx,rax
    const Bytes reads_rbp = bytes_of({0x48, 0x8b, 0x45, 0xf8, 0xc3});  // mov rax,[rbp-8]; ret

    passes(t, run(t, with_cold("bases", mov_rcx, reads_rbp)), "a register the code reads in a cold chunk of its function counts");
    t.check(mentions(run(t, with_cold("bases", mov_rcx, bytes_of({0x90, 0xc3}))), "rbp"), "a cold chunk that does not read it does not");

    const Bytes undecodable = bytes_of({0x06});
    const CheckResult stopped = run(t, with_cold("bases", bytes_of({0x48, 0x8b, 0x45, 0xf8, 0x85, 0xc0}), undecodable, true));
    t.check(mentions(stopped, "could not be followed"), "a cold chunk that cannot be decoded cannot be followed");
    t.check(mentions(stopped, "could not be decoded"), "and the function around the hook says so");

    t.check(mentions(run(t, with_cold("bases", mov_rcx, bytes_of({0x48, 0x89, 0xd8}))), "could not be followed"), "a cold chunk that runs off its end");
    t.check(mentions(run(t, with("bases", plus(mov_rcx, bytes_of({0x74, 0x03, 0xb8, 0xc3, 0x00, 0x00, 0x00})))), "could not be followed"), "a branch into the middle of an instruction");

    t.check(mentions(run(t, with("bases", plus(mov_rcx, bytes_of({0xff, 0xe0})))), "rbp"), "a jump through a register with no table is a tail call");
    t.check(mentions(run(t, with("bases", plus(mov_rcx, bytes_of({0xff, 0x25, 0, 0, 0, 0})))), "rbp"), "a jump through memory is a tail call");
}

void check_calls(compat_test::Suite& t) {
    const CheckResult only_rcx = run(t, with("registry", bytes_of({0x48, 0x89, 0xc1, 0xe8, 0, 0, 0, 0})));  // mov rcx,rax; call
    t.check(mentions(only_rcx, "rdx") && mentions(only_rcx, "r8"), "a call does not read the argument registers that nothing set up");

    const Bytes set_up = bytes_of({0x48, 0x89, 0xc2, 0x49, 0x89, 0xd8, 0xe8, 0, 0, 0, 0});  // mov rdx,rax; mov r8,rbx; call
    passes(t, run(t, with("registry", set_up, 6)), "a call reads the argument registers the code before it wrote");
}

void check_unhooked(compat_test::Suite& t) {
    auto bodies = all_sites();
    bodies.emplace_back("param_entity", bytes_of({0x48, 0x89, 0xd8, 0x90, 0x90}));
    const CheckResult result = run(t, exe_of(std::move(bodies)));
    passes(t, result, "a site with no hook is not inspected");
    t.check(result.hooks == 9, "and has no hooks");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_good(t);
    check_inputs(t);
    check_alignment(t);
    check_branches(t);
    check_registers(t);
    check_following(t);
    check_calls(t);
    check_unhooked(t);
    return t.result();
}
