// Compiler register conventions at the independently validated mining hook sites.
#pragma once
#include <cstdint>

namespace livemap {
enum class MiningLayout { InlineArray, StackRecord };
struct MiningSample { uint32_t item; uint32_t amount; };
constexpr MiningSample mining_sample(MiningLayout layout, uint64_t rax, uint64_t rbp, uint64_t r15) {
    // 26083076: inline loot-array stores item=ebp, amount=r15d.
    // 26319703: stack loot-record stores item=eax, amount=ebp before appending it.
    return layout == MiningLayout::StackRecord
        ? MiningSample{static_cast<uint32_t>(rax), static_cast<uint32_t>(rbp)}
        : MiningSample{static_cast<uint32_t>(rbp), static_cast<uint32_t>(r15)};
}
}
