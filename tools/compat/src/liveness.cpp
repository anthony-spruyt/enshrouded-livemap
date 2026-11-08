#include "liveness.h"

#include <algorithm>
#include <cstddef>
#include <vector>

namespace livemap::compat {

namespace {

constexpr Registers kAll = 0xffff;

// The Windows x64 convention: four argument registers, and the registers a callee may overwrite.
constexpr Registers kArguments = register_set({"rcx", "rdx", "r8", "r9"});
constexpr Registers kVolatile = register_set({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"});
constexpr Registers kReturned = register_set({"rax", "rsp"});
constexpr Registers kTailCalled = kArguments | register_set({"rsp"});

struct Node {
    const Code* code = nullptr;
    const Instruction* insn = nullptr;
    Registers uses = 0;
    Registers defs = 0;
    Registers beyond = 0;  // read by code outside the chain that the instruction leads to
    std::vector<size_t> next;
};

using Graph = std::vector<Node>;

std::optional<size_t> index_at(const Graph& graph, int64_t rva) {
    const auto found = std::ranges::lower_bound(graph, rva, {}, [](const Node& node) { return int64_t{node.insn->rva}; });
    if (found == graph.end() || found->insn->rva != rva) {
        return std::nullopt;
    }
    return static_cast<size_t>(found - graph.begin());
}

bool in_chain(std::span<const Code> chain, int64_t rva) {
    return std::ranges::any_of(chain, [&](const Code& code) { return rva >= code.range.begin && rva < code.range.end; });
}

void follow(const Graph& graph, std::span<const Code> chain, Node& node, int64_t target) {
    if (const auto at = index_at(graph, target)) {
        node.next.push_back(*at);
    } else {
        node.beyond |= in_chain(chain, target) ? kAll : kTailCalled;
    }
}

void follow_tables(const Graph& graph, Node& node) {
    if (node.code->tables.empty()) {
        node.beyond |= kAll;
    }
    for (const Table& table : node.code->tables) {
        for (const uint32_t entry : table.entries) {
            if (const auto at = index_at(graph, entry)) {
                node.next.push_back(*at);
            } else {
                node.beyond |= kAll;
            }
        }
    }
}

void link(const Graph& graph, std::span<const Code> chain, Node& node) {
    const Instruction& insn = *node.insn;
    switch (insn.flow) {
        case Flow::Return:
            node.beyond |= kReturned;
            return;
        case Flow::Stop:
            return;
        case Flow::Indirect:
            follow_tables(graph, node);
            return;
        case Flow::Jump:
            follow(graph, chain, node, insn.target);
            return;
        case Flow::Branch:
            follow(graph, chain, node, insn.target);
            break;
        case Flow::Call:
        case Flow::Next:
            break;
    }
    if (const auto at = index_at(graph, int64_t{insn.rva} + insn.length)) {
        node.next.push_back(*at);
    } else {
        node.beyond |= kAll;
    }
}

Graph build(std::span<const Code> chain) {
    Graph graph;
    for (const Code& code : chain) {
        for (const Instruction& insn : code.instructions) {
            const bool call = insn.flow == Flow::Call;
            graph.push_back(Node{&code, &insn, static_cast<Registers>(insn.reads | (call ? kArguments : 0)), static_cast<Registers>(insn.kills | (call ? kVolatile : 0)), 0, {}});
        }
    }
    std::ranges::sort(graph, {}, [](const Node& node) { return node.insn->rva; });
    for (Node& node : graph) {
        link(graph, chain, node);
    }
    return graph;
}

std::vector<Registers> solve(const Graph& graph) {
    std::vector<Registers> live(graph.size(), 0);
    for (bool changed = true; changed;) {
        changed = false;
        for (size_t i = graph.size(); i-- > 0;) {
            const Node& node = graph[i];
            Registers out = node.beyond;
            for (const size_t next : node.next) {
                out |= live[next];
            }
            const auto in = static_cast<Registers>(node.uses | (out & ~node.defs));
            changed = changed || in != live[i];
            live[i] = in;
        }
    }
    return live;
}

}  // namespace

std::optional<Registers> live_before(std::span<const Code> chain, uint32_t rva) {
    const Graph graph = build(chain);
    const auto at = index_at(graph, rva);
    if (!at) {
        return std::nullopt;
    }
    return solve(graph)[*at];
}

std::optional<Registers> in_use_at(std::span<const Code> chain, uint32_t rva) {
    const std::optional<Registers> live = live_before(chain, rva);
    if (!live) {
        return std::nullopt;
    }
    Registers used = *live;
    for (const Code& code : chain) {
        for (const Instruction& insn : code.instructions) {
            if (insn.rva + insn.length == rva && (insn.flow == Flow::Next || insn.flow == Flow::Call || insn.flow == Flow::Branch)) {
                used = static_cast<Registers>(used | insn.reads | insn.kills);
            }
        }
    }
    return used;
}

}  // namespace livemap::compat
