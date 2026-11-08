#include "liveness.h"

#include <algorithm>
#include <cstddef>
#include <vector>

namespace livemap::compat {

namespace {

// The Windows x64 convention: four argument registers, and the registers a callee may overwrite.
constexpr Registers kArguments = register_set({"rcx", "rdx", "r8", "r9"});
constexpr Registers kVolatile = register_set({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"});
constexpr Registers kReturned = register_set({"rax", "rsp"});
constexpr Registers kResult = register_set({"rax"});
constexpr Registers kAtEntry = register_set({"rsp"});
constexpr Registers kTailCalled = kArguments | register_set({"rsp"});

struct Node {
    const Code* code = nullptr;
    const Instruction* insn = nullptr;
    Registers uses = 0;
    Registers defs = 0;
    Registers beyond = 0;  // read by code outside the chain that the instruction leads to
    bool lost = false;     // leads where the chain cannot be followed
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
    if (const auto at = index_at(graph, target); at.has_value()) {
        node.next.push_back(*at);
    } else if (in_chain(chain, target)) {
        node.lost = true;
    } else {
        node.beyond |= kTailCalled;
    }
}

void follow_tables(const Graph& graph, Node& node) {
    if (node.code->tables.empty()) {
        node.beyond |= kTailCalled;
    }
    for (const Table& table : node.code->tables) {
        for (const uint32_t entry : table.entries) {
            if (const auto at = index_at(graph, entry); at.has_value()) {
                node.next.push_back(*at);
            } else {
                node.lost = true;
            }
        }
    }
}

void link(const Graph& graph, std::span<const Code> chain, Node& node) {
    using enum Flow;
    const Instruction& insn = *node.insn;
    switch (insn.flow) {
        case Return:
            node.beyond |= kReturned;
            return;
        case Stop:
            return;
        case Indirect:
            follow_tables(graph, node);
            return;
        case Jump:
            follow(graph, chain, node, insn.target);
            return;
        case Branch:
            follow(graph, chain, node, insn.target);
            break;
        case Call:
        case Next:
            break;
    }
    if (const auto at = index_at(graph, int64_t{insn.rva} + insn.length); at.has_value()) {
        node.next.push_back(*at);
    } else {
        node.lost = true;
    }
}

bool falls_through(const Node& from, const Node& to) {
    using enum Flow;
    const Flow flow = from.insn->flow;
    return (flow == Next || flow == Call || flow == Branch) && from.insn->rva + from.insn->length == to.insn->rva;
}

// The nodes that some edge reaches from somewhere other than the instruction just before them.
std::vector<bool> joined_nodes(const Graph& graph) {
    std::vector<bool> joined(graph.size(), false);
    for (size_t from = 0; from < graph.size(); ++from) {
        for (const size_t to : graph[from].next) {
            joined[to] = joined[to] || to != from + 1 || !falls_through(graph[from], graph[to]);
        }
    }
    return joined;
}

// The argument registers that the straight-line code just before the call at `call` wrote: back to the start of its
// block, a join, a branch or an earlier call.
Registers set_up_for(const Graph& graph, const std::vector<bool>& joined, size_t call) {
    Registers written = 0;
    for (size_t at = call; at > 0 && !joined[at] && falls_through(graph[at - 1], graph[at]) && graph[at - 1].insn->flow == Flow::Next; --at) {
        written |= graph[at - 1].insn->kills;
    }
    return written & kArguments;
}

Graph build(std::span<const Code> chain) {
    Graph graph;
    for (const Code& code : chain) {
        for (const Instruction& insn : code.instructions) {
            const bool call = insn.flow == Flow::Call;
            graph.push_back(Node{&code, &insn, insn.reads, static_cast<Registers>(insn.kills | (call ? kVolatile : 0)), 0, false, {}});
        }
    }
    std::ranges::sort(graph, {}, [](const Node& node) { return node.insn->rva; });
    for (Node& node : graph) {
        link(graph, chain, node);
    }
    const std::vector<bool> joined = joined_nodes(graph);
    for (size_t i = 0; i < graph.size(); ++i) {
        if (graph[i].insn->flow == Flow::Call) {
            graph[i].uses |= set_up_for(graph, joined, i);
        }
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

bool reaches_lost(const Graph& graph, size_t from) {
    std::vector<bool> seen(graph.size(), false);
    std::vector pending{from};
    seen[from] = true;
    while (!pending.empty()) {
        const Node& node = graph[pending.back()];
        pending.pop_back();
        if (node.lost) {
            return true;
        }
        for (const size_t next : node.next) {
            if (!seen[next]) {
                seen[next] = true;
                pending.push_back(next);
            }
        }
    }
    return false;
}

using Predecessors = std::vector<std::vector<size_t>>;

Predecessors predecessors(const Graph& graph) {
    Predecessors from(graph.size());
    for (size_t at = 0; at < graph.size(); ++at) {
        for (const size_t next : graph[at].next) {
            from[next].push_back(at);
        }
    }
    return from;
}

// Whether the graph has the edge that a branch of the map stands for: a jump of the chain, or an entry of a table that some
// indirect jump of the chain reads. A branch that an exception handler dispatches enters from outside the chain.
bool explained(const Graph& graph, const Predecessors& from, const Branch& branch, size_t to) {
    using enum Flow;
    const auto source = index_at(graph, branch.from);
    if (!source.has_value() || branch.dispatched) {
        return false;
    }
    const Node& node = graph[*source];
    if (node.insn->flow == Jump || node.insn->flow == Branch) {
        return true;
    }
    return node.insn->table_ref && std::ranges::any_of(from[to], [&](size_t pred) { return graph[pred].insn->flow == Indirect; });
}

// The nodes that control can reach from outside the chain.
std::vector<bool> entered_from_outside(const Graph& graph, const Predecessors& from, const BranchMap& branches) {
    std::vector<bool> outside(graph.size(), false);
    for (size_t at = 0; at < graph.size(); ++at) {
        const auto [first, last] = std::ranges::equal_range(branches.branches, int64_t{graph[at].insn->rva}, {}, &Branch::target);
        outside[at] = std::any_of(first, last, [&](const Branch& branch) { return !explained(graph, from, branch, at); });
    }
    return outside;
}

void mark_reached(const Graph& graph, size_t start, std::vector<bool>& reached) {
    std::vector pending{start};
    reached[start] = true;
    while (!pending.empty()) {
        const size_t at = pending.back();
        pending.pop_back();
        for (const size_t next : graph[at].next) {
            if (!reached[next]) {
                reached[next] = true;
                pending.push_back(next);
            }
        }
    }
}

// The entry, the nodes entered from outside, and every node that none of them reaches.
std::vector<bool> starting_points(const Graph& graph, size_t entry, std::vector<bool> roots) {
    std::vector<bool> reached(graph.size(), false);
    roots[entry] = true;
    for (size_t at = 0; at < graph.size(); ++at) {
        if (roots[at] && !reached[at]) {
            mark_reached(graph, at, reached);
        }
    }
    for (size_t at = 0; at < graph.size(); ++at) {
        roots[at] = roots[at] || !reached[at];
    }
    return roots;
}

Registers written_after(const Node& node, Registers before) {
    if (node.insn->flow != Flow::Call) {
        return static_cast<Registers>(before | node.insn->kills);
    }
    return static_cast<Registers>(((before | node.insn->kills) & ~kVolatile) | kResult);
}

// What each node can rely on having been written when it starts.
std::vector<Registers> solve_written(const Graph& graph, const Predecessors& from, const std::vector<bool>& roots) {
    constexpr Registers kUnknown = 0xffff;
    std::vector<Registers> before(graph.size(), kUnknown);
    for (bool changed = true; changed;) {
        changed = false;
        for (size_t at = 0; at < graph.size(); ++at) {
            Registers meet = roots[at] ? kAtEntry : kUnknown;
            for (const size_t pred : from[at]) {
                meet &= written_after(graph[pred], before[pred]);
            }
            changed = changed || meet != before[at];
            before[at] = meet;
        }
    }
    return before;
}

}  // namespace

std::expected<Registers, Fault> live_before(std::span<const Code> chain, uint32_t rva) {
    const Graph graph = build(chain);
    const auto at = index_at(graph, rva);
    if (!at.has_value()) {
        return std::unexpected(Fault::NoInstruction);
    }
    if (reaches_lost(graph, *at)) {
        return std::unexpected(Fault::Unfollowable);
    }
    return solve(graph)[*at];
}

std::expected<Registers, Fault> written_before(std::span<const Code> chain, uint32_t entry, uint32_t rva, const BranchMap& branches) {
    const Graph graph = build(chain);
    const auto at = index_at(graph, rva);
    if (!at.has_value()) {
        return std::unexpected(Fault::NoInstruction);
    }
    const auto first = index_at(graph, entry);
    if (!first.has_value()) {
        return std::unexpected(Fault::Unfollowable);
    }
    const Predecessors from = predecessors(graph);
    const std::vector<bool> roots = starting_points(graph, *first, entered_from_outside(graph, from, branches));
    return solve_written(graph, from, roots)[*at];
}

std::expected<Registers, Fault> in_use_at(std::span<const Code> chain, uint32_t entry, uint32_t rva, const BranchMap& branches) {
    using enum Flow;
    const std::expected<Registers, Fault> live = live_before(chain, rva);
    if (!live.has_value()) {
        return live;
    }
    const std::expected<Registers, Fault> written = written_before(chain, entry, rva, branches);
    if (!written.has_value()) {
        return written;
    }
    Registers used = *live;
    for (const Code& code : chain) {
        for (const Instruction& insn : code.instructions) {
            if (insn.rva + insn.length == rva && (insn.flow == Next || insn.flow == Call || insn.flow == Branch)) {
                used = static_cast<Registers>(used | ((insn.reads | insn.kills) & *written));
            }
        }
    }
    return used;
}

}  // namespace livemap::compat
