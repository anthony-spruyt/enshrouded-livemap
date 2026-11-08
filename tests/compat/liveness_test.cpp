// Which registers an instruction reads and overwrites, and which of them the code still reads from a given address on.
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "disasm.h"
#include "liveness.h"
#include "registers.h"
#include "test_support.h"

using compat_test::bytes_of;
using livemap::compat::Branch;
using livemap::compat::BranchMap;
using livemap::compat::Code;
using livemap::compat::Decoder;
using livemap::compat::Fault;
using livemap::compat::Flow;
using livemap::compat::Function;
using livemap::compat::Instruction;
using livemap::compat::Registers;

namespace {

constexpr uint32_t kAt = 0x1000;
const BranchMap kNoBranches{};

Registers set_of(std::initializer_list<std::string_view> names) {
    Registers set = 0;
    for (const std::string_view name : names) {
        const auto bit = livemap::compat::register_named(name);
        if (!bit.has_value()) {
            std::cout << "the test names no register '" << name << "'\n";
            std::exit(2);
        }
        set |= *bit;
    }
    return set;
}

Instruction first_of(const std::vector<std::byte>& bytes) {
    const auto insn = Decoder{}.decode(bytes, kAt, {});
    if (!insn) {
        std::cout << "the test bytes are no instruction\n";
        std::exit(2);
    }
    return *insn;
}

Code code_at(uint32_t begin, const std::vector<std::byte>& bytes) {
    const auto decoded = livemap::compat::decode_function(Decoder{}, bytes, Function{begin, begin + static_cast<uint32_t>(bytes.size())}, {});
    if (decoded.stopped.has_value()) {
        std::cout << "the test code does not decode\n";
        std::exit(2);
    }
    return decoded.code;
}

std::vector<std::byte> joined(std::initializer_list<std::vector<std::byte>> parts) {
    std::vector<std::byte> out;
    for (const auto& part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

Registers live_at(const std::vector<Code>& chain, uint32_t rva) {
    const auto live = livemap::compat::live_before(chain, rva);
    if (!live.has_value()) {
        std::cout << "the test address is no instruction\n";
        std::exit(2);
    }
    return *live;
}

Registers live_at(const std::vector<std::byte>& bytes, uint32_t rva = kAt) {
    return live_at(std::vector{code_at(kAt, bytes)}, rva);
}

std::optional<Fault> fault_at(const std::vector<Code>& chain, uint32_t rva) {
    const auto live = livemap::compat::live_before(chain, rva);
    return live.has_value() ? std::nullopt : std::optional{live.error()};
}

std::optional<Fault> fault_at(const std::vector<std::byte>& bytes, uint32_t rva = kAt) {
    return fault_at(std::vector{code_at(kAt, bytes)}, rva);
}

void check_effects(compat_test::Suite& t) {
    const auto move = first_of(bytes_of({0x48, 0x89, 0xd8}));  // mov rax,rbx
    t.check(move.reads == set_of({"rbx"}) && move.kills == set_of({"rax"}), "a move reads its source and overwrites its target");

    const auto indexed = first_of(bytes_of({0x8b, 0x04, 0x91}));  // mov eax,[rcx+rdx*4]
    t.check(indexed.reads == set_of({"rcx", "rdx"}) && indexed.kills == set_of({"rax"}), "the base and the index of an address are read; a 32-bit write overwrites the whole register");

    const auto narrow = first_of(bytes_of({0x88, 0xd8}));  // mov al,bl
    t.check(narrow.reads == set_of({"rbx"}) && narrow.kills == 0, "a write of 8 bits keeps the rest of the register");

    const auto zero = first_of(bytes_of({0x31, 0xc0}));  // xor eax,eax
    t.check(zero.reads == 0 && zero.kills == set_of({"rax"}), "xor of a register with itself reads nothing");
    const auto zero_high = first_of(bytes_of({0x4d, 0x31, 0xc0}));  // xor r8,r8
    t.check(zero_high.reads == 0 && zero_high.kills == set_of({"r8"}), "also for the registers r8 to r15");
    const auto xor_two = first_of(bytes_of({0x31, 0xd8}));  // xor eax,ebx
    t.check(xor_two.reads == set_of({"rax", "rbx"}) && xor_two.kills == set_of({"rax"}), "xor of two registers reads both");

    const auto add = first_of(bytes_of({0x48, 0x01, 0xd8}));  // add rax,rbx
    t.check(add.reads == set_of({"rax", "rbx"}), "an add reads the register it adds to");

    const auto cond = first_of(bytes_of({0x0f, 0x44, 0xc1}));  // cmovz eax,ecx
    t.check((cond.reads & set_of({"rcx"})) != 0 && cond.kills == 0, "a conditional move may leave its target alone");

    const auto push = first_of(bytes_of({0x50}));  // push rax
    t.check(push.reads == set_of({"rax", "rsp"}), "a push reads the register and the stack pointer");

    const auto store = first_of(bytes_of({0x48, 0x89, 0x18}));  // mov [rax],rbx
    t.check(store.reads == set_of({"rax", "rbx"}) && store.kills == 0, "a store reads the address and the value and overwrites no register");

    const auto lea = first_of(bytes_of({0x48, 0x8d, 0x43, 0x08}));  // lea rax,[rbx+8]
    t.check(lea.reads == set_of({"rbx"}) && lea.kills == set_of({"rax"}), "lea reads the registers of the address");

    const auto high = first_of(bytes_of({0x88, 0xe0}));  // mov al,ah
    t.check(high.reads == set_of({"rax"}), "ah is part of rax");
}

void check_flow(compat_test::Suite& t) {
    using enum Flow;
    t.check(first_of(bytes_of({0x90})).flow == Next, "nop goes on");
    t.check(first_of(bytes_of({0xe8, 0, 0, 0, 0})).flow == Call, "call");
    t.check(first_of(bytes_of({0xc3})).flow == Return, "ret");
    t.check(first_of(bytes_of({0x74, 0x05})).flow == Branch, "a conditional jump");
    t.check(first_of(bytes_of({0xeb, 0x05})).flow == Jump, "a relative jump");
    t.check(first_of(bytes_of({0xff, 0xe0})).flow == Indirect, "a jump through a register");
    t.check(first_of(bytes_of({0xff, 0x25, 0, 0, 0, 0})).flow == Indirect, "a jump through memory");
    t.check(first_of(bytes_of({0xcc})).flow == Stop, "int3");
    t.check(first_of(bytes_of({0x0f, 0x0b})).flow == Stop, "ud2");
}

void check_straight_line(compat_test::Suite& t) {
    const auto move_and_return = bytes_of({0x48, 0x89, 0xd8, 0xc3});  // mov rax,rbx; ret
    t.check(live_at(move_and_return) == set_of({"rbx", "rsp"}), "what the code reads before it overwrites it, and the stack pointer a return reads");
    t.check(live_at(move_and_return, kAt + 3) == set_of({"rax", "rsp"}), "at a return the result register is live");

    const auto overwritten = joined({bytes_of({0xbb, 1, 0, 0, 0}), bytes_of({0x48, 0x89, 0xd8, 0xc3})});  // mov ebx,1; mov rax,rbx; ret
    t.check(live_at(overwritten) == set_of({"rsp"}), "a register written before it is read is dead");

    t.check(live_at(bytes_of({0xcc})) == 0, "nothing follows a trap");
    t.check(fault_at(move_and_return, kAt + 1) == Fault::NoInstruction, "an address inside an instruction has no answer");
    t.check(fault_at(move_and_return, kAt + 0x40) == Fault::NoInstruction, "nor one outside the code");
}

void check_branches(compat_test::Suite& t) {
    // test eax,eax; jz end; mov rax,rbx; ret; end: ret
    const auto fork = joined({bytes_of({0x85, 0xc0, 0x74, 0x04}), bytes_of({0x48, 0x89, 0xd8, 0xc3, 0xc3})});
    t.check(live_at(fork, kAt + 4) == set_of({"rbx", "rsp"}), "one path reads rbx");
    t.check(live_at(fork, kAt + 2) == set_of({"rax", "rbx", "rsp"}), "a register one path reads is live at the branch, and the result register the other path returns");
    t.check(live_at(fork) == set_of({"rax", "rbx", "rsp"}), "the test reads rax");

    // loop: add rax,rbx; dec rcx; jnz loop; ret
    const auto loop = bytes_of({0x48, 0x01, 0xd8, 0x48, 0xff, 0xc9, 0x75, 0xf8, 0xc3});
    t.check(live_at(loop, kAt + 3) == set_of({"rax", "rbx", "rcx", "rsp"}), "a read at the top of a loop is live at the bottom of it");

    // jz lands inside the mov that follows
    const auto inside = bytes_of({0x74, 0x03, 0xb8, 0xc3, 0x00, 0x00, 0x00, 0xc3});
    t.check(fault_at(inside) == Fault::Unfollowable, "a branch into the middle of an instruction cannot be followed");
    t.check(!fault_at(inside, kAt + 7).has_value(), "code from which the branch is out of reach is fine");

    t.check(fault_at(bytes_of({0x48, 0x89, 0xd8})) == Fault::Unfollowable, "code that runs off its end cannot be followed");
    t.check(fault_at(bytes_of({0x85, 0xc0, 0x74, 0x00})) == Fault::Unfollowable, "nor can a branch that may fall off its end");
}

void check_calls(compat_test::Suite& t) {
    const auto then_read = bytes_of({0xe8, 0, 0, 0, 0, 0x48, 0x89, 0xd8, 0xc3});  // call; mov rax,rbx; ret
    t.check(live_at(then_read) == set_of({"rbx", "rsp"}), "a call reads no argument register that nothing set up, keeps the registers it preserves and overwrites the others");

    const auto result = bytes_of({0xe8, 0, 0, 0, 0, 0x48, 0x89, 0xc3, 0xc3});  // call; mov rbx,rax; ret
    t.check(live_at(result) == set_of({"rsp"}), "the result of a call is not the value from before it");

    const auto set_up = bytes_of({0xb9, 1, 0, 0, 0, 0x4c, 0x89, 0xc2, 0xe8, 0, 0, 0, 0, 0xc3});  // mov ecx,1; mov rdx,r8; call; ret
    t.check(live_at(set_up, kAt + 8) == set_of({"rcx", "rdx", "rsp"}), "a call reads the argument registers the code before it wrote");
    t.check(live_at(set_up) == set_of({"r8", "rsp"}), "and the code that wrote them has them dead before");

    const auto joined_in = bytes_of({0x74, 0x05, 0xb9, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xc3});  // jz call; mov ecx,1; call: ret
    t.check(live_at(joined_in, kAt + 7) == set_of({"rsp"}), "a write before a point where other code joins is not known to reach the call");

    const auto after_call = bytes_of({0xb9, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xc3});  // mov ecx,1; call; call; ret
    t.check(live_at(after_call, kAt + 10) == set_of({"rsp"}), "nor is a write before an earlier call");
    t.check(live_at(after_call, kAt + 5) == set_of({"rcx", "rsp"}), "which reads it itself");
}

void check_exits(compat_test::Suite& t) {
    const Registers args = set_of({"rcx", "rdx", "r8", "r9"});
    const auto tail = bytes_of({0xe9, 0xfb, 0x0f, 0x00, 0x00});  // jmp 0x2000
    t.check(live_at(tail) == (args | set_of({"rsp"})), "a jump out of the code is a call that returns for the caller");
    t.check(live_at(bytes_of({0xff, 0xe0})) == (args | set_of({"rax", "rsp"})), "a jump through a register with no table leaves the code like a tail call");
    t.check(live_at(bytes_of({0xff, 0x25, 0, 0, 0, 0})) == (args | set_of({"rsp"})), "so does a jump through memory");

    const auto cold = bytes_of({0x48, 0x89, 0xd8, 0xc3});  // mov rax,rbx; ret
    const std::vector chain{code_at(kAt, bytes_of({0xe9, 0xfb, 0x0f, 0x00, 0x00})), code_at(0x2000, cold)};
    t.check(live_at(chain, kAt) == set_of({"rbx", "rsp"}), "a jump into another chunk of the chain goes on there");
}

void check_tables(compat_test::Suite& t) {
    // mov eax,[rdx+rcx*4+table]; add rax,rdx; jmp rax; 100c: mov rax,rbx; ret; 1010: ret; 1011: table of two entries
    const auto function = joined({bytes_of({0x8b, 0x84, 0x8a, 0x11, 0x10, 0x00, 0x00}), bytes_of({0x48, 0x01, 0xd0, 0xff, 0xe0}), bytes_of({0x48, 0x89, 0xd8, 0xc3, 0xc3}),
                                  bytes_of({0x0c, 0x10, 0, 0, 0x10, 0x10, 0, 0})});
    const Code code = code_at(kAt, function);
    t.check(code.tables.size() == 1, "the test function holds a table");
    const std::vector chain{code};
    t.check(live_at(chain, kAt + 0xa) == set_of({"rax", "rbx", "rsp"}), "a jump through a table goes where the table says");
    t.check(live_at(chain, kAt) == set_of({"rbx", "rcx", "rdx", "rsp"}), "and the registers that find the entry are read before it");

    auto crooked = function;
    crooked[crooked.size() - 4] = std::byte{0x0d};  // the second entry now lands inside the mov
    const std::vector bad_chain{code_at(kAt, crooked)};
    t.check(fault_at(bad_chain, kAt + 0xa) == Fault::Unfollowable, "an entry of a table that starts no instruction cannot be followed");
}

Registers written_at(const std::vector<Code>& chain, uint32_t rva, const BranchMap& branches = kNoBranches, uint32_t entry = kAt) {
    const auto written = livemap::compat::written_before(chain, entry, rva, branches);
    if (!written.has_value()) {
        std::cout << "the test address is no instruction\n";
        std::exit(2);
    }
    return *written;
}

Registers written_at(const std::vector<std::byte>& bytes, uint32_t rva, const BranchMap& branches = kNoBranches) {
    return written_at(std::vector{code_at(kAt, bytes)}, rva, branches);
}

Registers in_use_at(const std::vector<Code>& chain, uint32_t rva, const BranchMap& branches = kNoBranches, uint32_t entry = kAt) {
    const auto used = livemap::compat::in_use_at(chain, entry, rva, branches);
    if (!used.has_value()) {
        std::cout << "the test address is no instruction\n";
        std::exit(2);
    }
    return *used;
}

void check_written(compat_test::Suite& t) {
    const auto straight = bytes_of({0x48, 0x89, 0xd8, 0xb9, 1, 0, 0, 0, 0x90});  // mov rax,rbx; mov ecx,1; nop
    t.check(written_at(straight, kAt) == set_of({"rsp"}), "the entry of a function holds the stack pointer and nothing else");
    t.check(written_at(straight, kAt + 8) == set_of({"rax", "rcx", "rsp"}), "the registers written on the way are written");

    const auto narrow = bytes_of({0xb3, 1, 0x90});  // mov bl,1; nop
    t.check(written_at(narrow, kAt + 2) == set_of({"rsp"}), "a write of 8 bits leaves the register unwritten");

    // test eax,eax; jz else; mov ebx,1; mov ecx,1; jmp join; else: mov ebx,2; join: ret
    const auto fork = bytes_of({0x85, 0xc0, 0x74, 0x0c, 0xbb, 1, 0, 0, 0, 0xb9, 1, 0, 0, 0, 0xeb, 0x05, 0xbb, 2, 0, 0, 0, 0xc3});
    t.check(written_at(fork, kAt + 21) == set_of({"rbx", "rsp"}), "where two paths meet only the registers both wrote are written");
    t.check(written_at(fork, kAt + 9) == set_of({"rbx", "rsp"}), "a path keeps what it wrote");
    const BranchMap own_jumps{{Branch{kAt + 2, kAt + 16}, Branch{kAt + 14, kAt + 21}}, {}};
    t.check(written_at(fork, kAt + 21, own_jumps) == set_of({"rbx", "rsp"}), "the jumps of the chain itself add no other way in");

    // mov ebx,1; test eax,eax; jz join; nop; join: ret
    const auto skip = bytes_of({0xbb, 1, 0, 0, 0, 0x85, 0xc0, 0x74, 0x01, 0x90, 0xc3});
    const BranchMap jumped{{Branch{kAt + 7, kAt + 10}}, {}};
    t.check(written_at(skip, kAt + 10, jumped) == set_of({"rbx", "rsp"}), "a jump of the chain that the map lists keeps what was written");
    const BranchMap dispatched{{Branch{kAt + 7, kAt + 10, true}}, {}};
    t.check(written_at(skip, kAt + 10, dispatched) == set_of({"rsp"}), "control that a handler hands back, from the code of a jump, still brings only the stack pointer");

    // mov eax,[rdx+rcx*4+table]; add rax,rdx; jmp rax; 100c: mov rax,rbx; ret; 1010: ret; 1011: table of two entries
    const auto switched = joined({bytes_of({0x8b, 0x84, 0x8a, 0x11, 0x10, 0x00, 0x00, 0x48, 0x01, 0xd0, 0xff, 0xe0, 0x48, 0x89, 0xd8, 0xc3, 0xc3}), bytes_of({0x0c, 0x10, 0, 0, 0x10, 0x10, 0, 0})});
    const BranchMap entries{{Branch{kAt, kAt + 0xc}, Branch{kAt, kAt + 0x10}}, {}};
    t.check(written_at(switched, kAt + 0xc, entries) == set_of({"rax", "rsp"}), "an entry of a table that a jump of the chain reads keeps what was written");

    // mov eax,[rdx+rcx*4+table]; mov ebx,1; 100c: nop; ret; 100e: table of two entries
    const auto unread = joined({bytes_of({0x8b, 0x84, 0x8a, 0x0e, 0x10, 0x00, 0x00, 0xbb, 1, 0, 0, 0, 0x90, 0xc3}), bytes_of({0x0c, 0x10, 0, 0, 0x0d, 0x10, 0, 0})});
    const BranchMap unread_entry{{Branch{kAt, kAt + 0xc}}, {}};
    t.check(code_at(kAt, unread).tables.size() == 1, "the test function holds a table");
    t.check(written_at(unread, kAt + 0xc) == set_of({"rax", "rbx", "rsp"}), "an instruction that only the code before it leads to has what that code wrote");
    t.check(written_at(unread, kAt + 0xc, unread_entry) == set_of({"rsp"}), "an entry of a table that no jump of the chain reads brings only the stack pointer");

    // mov ebx,1; loop: mov ecx,1; test eax,eax; jnz loop; ret
    const auto loop = bytes_of({0xbb, 1, 0, 0, 0, 0xb9, 1, 0, 0, 0, 0x85, 0xc0, 0x75, 0xf7, 0xc3});
    t.check(written_at(loop, kAt + 5) == set_of({"rbx", "rsp"}), "a loop head has what the entry wrote, not what the loop writes");
    t.check(written_at(loop, kAt + 14) == set_of({"rbx", "rcx", "rsp"}), "and after the loop both");

    const auto call = bytes_of({0xbb, 1, 0, 0, 0, 0xb9, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x90});  // mov ebx,1; mov ecx,1; call; nop
    t.check(written_at(call, kAt + 15) == set_of({"rax", "rbx", "rsp"}), "a call keeps the registers it preserves and the result, and the others hold nothing");

    const auto dead = bytes_of({0xc3, 0xbb, 1, 0, 0, 0, 0x90, 0xc3});  // ret; mov ebx,1; nop; ret
    t.check(written_at(dead, kAt + 1) == set_of({"rsp"}), "code that nothing reaches is entered with the stack pointer only");
    t.check(written_at(dead, kAt + 6) == set_of({"rsp"}), "and so is every later instruction of it");
    const auto spin = bytes_of({0xbb, 1, 0, 0, 0, 0xc3, 0xb9, 1, 0, 0, 0, 0xeb, 0xf9});  // mov ebx,1; ret; again: mov ecx,1; jmp again
    t.check(written_at(spin, kAt + 6) == set_of({"rsp"}), "also a loop that nothing reaches");
    t.check(written_at(spin, kAt + 11) == set_of({"rsp"}), "at every instruction of it");

    const auto two = bytes_of({0xbb, 1, 0, 0, 0, 0xb9, 1, 0, 0, 0, 0x90});  // mov ebx,1; mov ecx,1; nop
    const BranchMap elsewhere{{Branch{0x3000, kAt + 5}}, {}};
    t.check(written_at(two, kAt + 5, elsewhere) == set_of({"rsp"}), "a branch from another function brings nothing in");
    t.check(written_at(two, kAt + 10, elsewhere) == set_of({"rcx", "rsp"}), "but the code after it goes on from there");
    const BranchMap taken{{Branch{kAt, kAt + 5}}, {}};
    t.check(written_at(two, kAt + 5, taken) == set_of({"rsp"}), "nor does an address another instruction forms");
    const auto called = bytes_of({0xbb, 1, 0, 0, 0, 0xb9, 1, 0, 0, 0, 0xe8, 0xf6, 0xff, 0xff, 0xff, 0x90});  // mov ebx,1; again: mov ecx,1; call again; nop
    const BranchMap recursion{{Branch{kAt + 10, kAt + 5}}, {}};
    t.check(written_at(called, kAt + 5, recursion) == set_of({"rsp"}), "nor does a call to the middle of the chain");

    const std::vector split{code_at(kAt, bytes_of({0xbb, 1, 0, 0, 0, 0xe9, 0xf6, 0x0f, 0x00, 0x00})), code_at(0x2000, bytes_of({0x90, 0xc3}))};  // mov ebx,1; jmp 0x2000
    t.check(written_at(split, 0x2000) == set_of({"rbx", "rsp"}), "another chunk of the chain is entered from the jump that leads there");
    t.check(written_at(split, 0x2000, kNoBranches, 0x2000) == set_of({"rsp"}), "and the entry is the one named");

    const auto missing = livemap::compat::written_before(std::vector{code_at(kAt, straight)}, kAt, kAt + 1, kNoBranches);
    t.check(!missing.has_value() && missing.error() == Fault::NoInstruction, "an address inside an instruction has no answer");
    const auto no_entry = livemap::compat::written_before(std::vector{code_at(kAt, straight)}, kAt + 1, kAt, kNoBranches);
    t.check(!no_entry.has_value() && no_entry.error() == Fault::Unfollowable, "nor has a function whose entry starts no instruction");
}

void check_in_use(compat_test::Suite& t) {
    const auto store_then_clear = bytes_of({0x89, 0x47, 0x08, 0x31, 0xc9, 0xc3});  // mov [rdi+8],eax; xor ecx,ecx; ret
    const std::vector chain{code_at(kAt, store_then_clear)};
    t.check(live_at(store_then_clear, kAt + 3) == set_of({"rax", "rsp"}), "after the store only the result register and the stack pointer are live");
    t.check(in_use_at(chain, kAt + 3) == live_at(store_then_clear, kAt + 3), "a register the instruction just before touches is not in use when nothing wrote it");
    t.check(in_use_at(chain, kAt) == live_at(store_then_clear), "the first instruction has none before it");

    const auto written_first = bytes_of({0xbf, 1, 0, 0, 0, 0x48, 0x89, 0x5f, 0x08, 0x31, 0xc9, 0xc3});  // mov edi,1; mov [rdi+8],rbx; xor ecx,ecx; ret
    const std::vector set_up{code_at(kAt, written_first)};
    t.check(in_use_at(set_up, kAt + 9) == set_of({"rax", "rdi", "rsp"}), "a register the instruction before touches is in use once the code wrote it");

    // test eax,eax; jz else; mov edi,1; jmp join; else: mov edi,2; join: xor ecx,ecx; ret
    const auto both_write = bytes_of({0x85, 0xc0, 0x74, 0x07, 0xbf, 1, 0, 0, 0, 0xeb, 0x05, 0xbf, 2, 0, 0, 0, 0x31, 0xc9, 0xc3});
    t.check(in_use_at({code_at(kAt, both_write)}, kAt + 16) == set_of({"rax", "rdi", "rsp"}), "also when every path to the hook wrote it");
    // test eax,eax; jz join; mov edi,1; join: xor ecx,ecx; ret
    const auto one_writes = bytes_of({0x85, 0xc0, 0x74, 0x05, 0xbf, 1, 0, 0, 0, 0x31, 0xc9, 0xc3});
    t.check(in_use_at({code_at(kAt, one_writes)}, kAt + 9) == set_of({"rax", "rsp"}), "but not when a path to the hook skips the write");

    const auto after_jump = bytes_of({0xff, 0xe7, 0x31, 0xc9, 0xc3});  // jmp rdi; xor ecx,ecx; ret
    t.check(in_use_at({code_at(kAt, after_jump)}, kAt + 2) == live_at(after_jump, kAt + 2), "an instruction that never falls through lends nothing to the next");

    const auto call_then = bytes_of({0xe8, 0, 0, 0, 0, 0x31, 0xc9, 0xc3});  // call; xor ecx,ecx; ret
    t.check((in_use_at({code_at(kAt, call_then)}, kAt + 5) & set_of({"rdx"})) == 0, "a call lends the registers it names, not those it reads for its callee");

    const std::vector split{code_at(kAt, bytes_of({0xe9, 0xfb, 0x0f, 0x00, 0x00})), code_at(0x2000, bytes_of({0x48, 0x89, 0xd8, 0xc3}))};
    t.check(in_use_at(split, 0x2000) == live_at(split, 0x2000), "the start of another chunk has none before it");
    const auto used = livemap::compat::in_use_at(chain, kAt, kAt + 1, kNoBranches);
    t.check(!used.has_value() && used.error() == Fault::NoInstruction, "an address inside an instruction has no answer");

    const std::vector off_the_end{code_at(kAt, bytes_of({0x48, 0x89, 0xd8}))};
    const auto lost = livemap::compat::in_use_at(off_the_end, kAt, kAt, kNoBranches);
    t.check(!lost.has_value() && lost.error() == Fault::Unfollowable, "code that cannot be followed has no answer either");
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_written(t);
    check_in_use(t);
    check_effects(t);
    check_flow(t);
    check_straight_line(t);
    check_branches(t);
    check_calls(t);
    check_exits(t);
    check_tables(t);
    return t.result();
}
