// param_entity must read the entity id table at the offset the caller passes: the scanner takes
// that offset from the game (+0x830 on build 26404334) and a fixed +0x828 never matches a player.
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <print>

#include "../src/ecs.h"

namespace {

constexpr uint32_t kEntityTable = 0x830;
constexpr uint32_t kOtherTable = 0x828;
constexpr uint32_t kIndex = 3;
constexpr uint32_t kRowWords = 4;  // a table row is 16 bytes, the id is its first word
constexpr uint32_t kEntityId = 0x1234abcd;
constexpr uint32_t kOtherId = 0x0badf00d;

// What an ECS system's first parameter points to: {world, index}.
struct Param {
    uintptr_t world;
    uint32_t index;
};
static_assert(offsetof(Param, index) == 8);

template <typename T>
uintptr_t address_of(const T* p) {
    return reinterpret_cast<uintptr_t>(p);
}

}  // namespace

int main() {
    std::array<uint32_t, kRowWords * kIndex> entity_ids{};
    entity_ids[(kIndex - 1) * kRowWords] = kEntityId;
    std::array<uint32_t, kRowWords * kIndex> other_ids{};
    other_ids[(kIndex - 1) * kRowWords] = kOtherId;

    std::array<uintptr_t, 0x120> world{};
    world[kEntityTable / sizeof(uintptr_t)] = address_of(entity_ids.data());
    world[kOtherTable / sizeof(uintptr_t)] = address_of(other_ids.data());

    const Param param{address_of(world.data()), kIndex};

    assert(livemap::param_entity(address_of(&param), kEntityTable) == kEntityId);
    assert(livemap::param_entity(address_of(&param), kOtherTable) != kEntityId);

    std::println("param_entity entity table offset passed");
}
