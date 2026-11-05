// The call from the stand-in game (fault_gate.exe) into the mod side (fault_gate_mod.dll).
#pragma once

inline constexpr int kHookFailed = 98;
inline constexpr int kSurvived = 99;

using GameFault = void (*)(volatile int* target);

// Runs one mode and returns the exit code the executable ends with. `game_fault` is a function of the game's own image.
extern "C" int gate_run(const char* mode, GameFault game_fault);
