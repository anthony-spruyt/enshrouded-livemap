#pragma once

// A synthetic server exe for the analysis tests: the layout knobs move or change its code the way a patch would. No game bytes.
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

#include "pe_builder.h"

namespace compat_test {

enum class Extra { None,
                   Table,
                   Garbage,
                   JumpIn };

struct JoinLayout {
    bool lose = false;        // the join line's pattern is gone
    uint8_t after = 0x44;     // the byte after the join call
    bool calls_chat = true;   // the join call goes to chat_post
    bool jumps = false;       // the instruction at the join call is a jmp instead
    uint32_t tag = 0x1234;
};

struct ExeLayout {
    uint32_t time_date_stamp = 100;
    uint32_t size_of_image = 0x10000;
    uint32_t lead = 0;            // padding before the first function: moves every site
    uint32_t entity_table = 0x830;
    uint32_t outside = 0;         // moves what the calls and RIP-relative loads point at
    bool extra_nop = false;       // alpha holds one instruction more
    bool leaf_changed = false;    // the accessor indexes with another register
    uint32_t other_target = 5;    // where the unrelated function jumps, as an offset from alpha
    bool duplicate_beta = false;  // beta's pattern appears a second time
    bool lose_gamma = false;      // chat_post's pattern is gone
    bool duplicate_gamma = false;  // chat_post's pattern appears a second time
    JoinLayout join;
    bool alpha_switch = false;    // alpha ends in a jump table, and is twice as long
    uint32_t switch_entry = 0x12;  // where the middle entry of that table goes, as an offset from alpha
    Extra extra = Extra::None;     // a function after the others: Table holds alpha's jump table, Garbage stops decoding, JumpIn jumps and then stops
    bool extra_chained = false;    // that function is a chunk of alpha
    uint32_t extra_target = 0x10;  // where JumpIn jumps, as an offset from alpha
    uint32_t extra_pad = 0;        // padding before that function, after the others
    bool unlist_beta = false;      // beta has no entry in the exception table
};

constexpr uint32_t kTextRva = 0x1000;
constexpr uint32_t kRdataRva = 0x3000;
constexpr uint32_t kFunctionSize = 0x20;

struct ExeSites {
    uint32_t alpha = 0;
    uint32_t beta = 0;
    uint32_t chat = 0;
    uint32_t join = 0;  // start of the join pattern; the call is 10 bytes on
    uint32_t leaf = 0;
    uint32_t other = 0;
    uint32_t outside_function = 0;
    uint32_t extra = 0;
};

inline bool has_switch(const ExeLayout& layout) {
    return layout.alpha_switch || layout.extra == Extra::Table;
}

inline ExeSites sites_of(const ExeLayout& layout) {
    ExeSites s;
    s.alpha = kTextRva + layout.lead;
    s.beta = s.alpha + (has_switch(layout) ? 2 * kFunctionSize : kFunctionSize);
    s.chat = s.beta + kFunctionSize;
    s.join = s.chat + kFunctionSize;
    s.leaf = s.join + kFunctionSize;
    s.other = s.leaf + kFunctionSize;
    s.outside_function = s.other + kFunctionSize;
    s.extra = s.outside_function + kFunctionSize + layout.extra_pad;
    return s;
}

class Assembler {
public:
    explicit Assembler(uint32_t rva) : rva_(rva) {}

    uint32_t here() const { return rva_ + static_cast<uint32_t>(code_.size()); }
    const std::vector<std::byte>& code() const { return code_; }

    void emit(std::initializer_list<unsigned> values) {
        for (const unsigned v : values) {
            code_.push_back(static_cast<std::byte>(v));
        }
    }

    void imm32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) {
            code_.push_back(static_cast<std::byte>(value >> (8 * i)));
        }
    }

    void branch32(unsigned opcode, uint32_t target) {
        emit({opcode});
        imm32(target - (here() + 4));
    }

    void rip_load(uint32_t target) {
        emit({0x48, 0x8b, 0x05});
        imm32(target - (here() + 4));
    }

    void pad_to(uint32_t rva) {
        while (here() < rva) {
            emit({0xcc});
        }
    }

private:
    uint32_t rva_;
    std::vector<std::byte> code_;
};

// mov eax,[rdx+rcx*4+table]; add rax,rdx; jmp rax
inline void switch_jump(Assembler& a, uint32_t table) {
    a.emit({0x8b, 0x84, 0x8a});
    a.imm32(table);
    a.emit({0x48, 0x01, 0xd0, 0xff, 0xe0});
}

constexpr uint32_t kSwitchLength = 13;

struct Switching {
    bool on = false;
    uint32_t table = 0;  // 0: the table follows the return
};

inline void marked_function(Assembler& a, uint32_t begin, unsigned marker, const ExeLayout& layout, bool extra_nop, uint32_t external, Switching switching = {}) {
    a.emit({0xb8, marker, marker, marker, marker});
    a.emit({0x48, 0x89, 0xd9});
    a.emit({0x74, 0x02, 0x90, 0x90});
    if (extra_nop) {
        a.emit({0x90});
    }
    a.branch32(0xe8, external + layout.outside);
    a.rip_load(kRdataRva + 0x10 + layout.outside);
    if (switching.on) {
        switch_jump(a, switching.table != 0 ? switching.table : a.here() + kSwitchLength);
    }
    a.emit({0xc3});
    if (switching.on && switching.table == 0) {
        a.imm32(begin + 0x12);
        a.imm32(begin + layout.switch_entry);
        a.imm32(begin + 0x12);
    }
    a.pad_to(begin + (switching.on ? 2 * kFunctionSize : kFunctionSize));
}

inline std::vector<std::byte> build_exe(const ExeLayout& layout) {
    const ExeSites s = sites_of(layout);
    Assembler a(kTextRva);
    a.pad_to(s.alpha);
    const uint32_t table = layout.extra == Extra::Table ? s.extra : 0;
    marked_function(a, s.alpha, 0x11, layout, layout.extra_nop, s.outside_function, Switching{has_switch(layout), table});
    marked_function(a, s.beta, 0x22, layout, false, s.outside_function);
    if (layout.lose_gamma) {
        a.emit({0xb8, 0x99, 0x99, 0x99, 0x99, 0x48, 0x89, 0xd9, 0xc3});
    } else {
        a.emit({0xb8, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89, 0xd9, 0xc3});
    }
    a.pad_to(s.join);
    const unsigned join_marker = layout.join.lose ? 0x55U : 0x44U;
    a.emit({0xb8, join_marker, join_marker, join_marker, join_marker, 0xba});
    a.imm32(layout.join.tag);
    a.branch32(layout.join.jumps ? 0xe9 : 0xe8, layout.join.calls_chat ? s.chat : s.outside_function);
    a.emit({layout.join.after, 0x8b, 0xc0, 0x48, 0x89, 0xc1, 0xc3});
    a.pad_to(s.leaf);
    a.emit({0x4c, 0x8b, 0xd9, 0x48, 0x8b, 0x81});
    a.imm32(layout.entity_table);
    a.emit({0x8b, 0x04, layout.leaf_changed ? 0x89U : 0x91U, 0xc3});
    a.pad_to(s.other);
    a.branch32(0xe9, s.alpha + layout.other_target);
    a.emit({0xc3});
    a.pad_to(s.outside_function);
    a.emit({0xc3});
    if (layout.duplicate_beta) {
        a.emit({0xb8, 0x22, 0x22, 0x22, 0x22, 0x48, 0x89, 0xd9});
    }
    if (layout.duplicate_gamma) {
        a.emit({0xb8, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89, 0xd9});
    }
    a.pad_to(s.extra);
    if (layout.extra == Extra::Table) {
        a.imm32(s.alpha + 0x12);
        a.imm32(s.alpha + layout.switch_entry);
        a.imm32(s.alpha + 0x12);
    } else if (layout.extra == Extra::Garbage) {
        a.emit({0x90, 0x06});
    } else if (layout.extra == Extra::JumpIn) {
        a.branch32(0xe9, s.alpha + layout.extra_target);
        a.emit({0x06});
    }
    if (layout.extra != Extra::None) {
        a.pad_to(s.extra + kFunctionSize);
    }

    PeSpec spec;
    spec.time_date_stamp = layout.time_date_stamp;
    spec.size_of_image = layout.size_of_image;
    spec.sections.emplace_back(".text", kTextRva, a.code(), 0);
    spec.sections.emplace_back(".rdata", kRdataRva, std::vector<std::byte>(0x40, std::byte{0x5a}), 0);
    for (const uint32_t begin : {s.alpha, s.beta, s.chat, s.join, s.other, s.outside_function}) {
        if (layout.unlist_beta && begin == s.beta) {
            continue;
        }
        const bool switching = has_switch(layout) && begin == s.alpha;
        spec.functions.emplace_back(begin, begin + (switching ? 2 * kFunctionSize : kFunctionSize));
    }
    if (layout.extra != Extra::None) {
        spec.functions.emplace_back(s.extra, s.extra + kFunctionSize, layout.extra_chained ? s.alpha : 0);
    }
    return build_pe(spec);
}

}  // namespace compat_test
