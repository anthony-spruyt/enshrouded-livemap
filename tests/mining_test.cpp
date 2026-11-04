#include "../src/mining.h"
#include <cassert>
#include <cstdio>
using namespace livemap;
int main() {
    auto old = mining_sample(MiningLayout::InlineArray, 0xdeadbeef, 0x12345678, 17);
    assert(old.item == 0x12345678 && old.amount == 17);
    auto current = mining_sample(MiningLayout::StackRecord, 0x12345678, 17, 0xdeadbeef);
    assert(current.item == old.item && current.amount == old.amount);
    auto narrowed = mining_sample(MiningLayout::StackRecord, 0xfeedface12345678ULL, 0xdeadbeef00000011ULL, 99);
    assert(narrowed.item == old.item && narrowed.amount == old.amount);
    std::puts("mining register layouts passed");
}
