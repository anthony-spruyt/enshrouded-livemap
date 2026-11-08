#include "callbacks.h"

#include <array>

namespace livemap::compat {

namespace {

constexpr std::array kCallbacks{
    Callback{"on_player_table", "player_table", 0, "", register_set({"rcx"})},
    Callback{"on_movement", "movement", 0, "", register_set({"rbx", "rsp"})},
    Callback{"on_daytime", "daytime", 0, "", register_set({"rax", "rbx", "rdi"})},
    Callback{"on_registry", "registry", 0, "", register_set({"rdx", "r8"})},
    Callback{"on_mining", "mining", 0, "", register_set({"rbx", "rdi"})},
    Callback{"on_mining", "mining", 0, "inline_array", register_set({"rbp", "r15"})},
    Callback{"on_mining", "mining", 0, "stack_record", register_set({"rax", "rbp"})},
    Callback{"on_chest", "chest", 0, "", register_set({"rbp", "rdi", "rsp"})},
    Callback{"on_base", "bases", 0, "", register_set({"rbp"})},
    Callback{"on_join_call", "join_line", 0, "", register_set({"rdx", "rsp"})},
    Callback{"on_join_after", "join_line", kCallLength, "", 0},
};

}  // namespace

std::span<const Callback> callbacks() {
    return kCallbacks;
}

}  // namespace livemap::compat
