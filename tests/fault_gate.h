// The call from the stand-in game (fault_gate.exe) into the mod side (fault_gate_mod.dll).
#pragma once

#ifdef FAULT_GATE_EXPORTS
#define FAULT_GATE_API __declspec(dllexport)
#else
#define FAULT_GATE_API __declspec(dllimport)
#endif

inline constexpr int kHookFailed = 98;
inline constexpr int kSurvived = 99;

// The executable exports this function, `void (volatile int* target)`, as the code that counts as the game's own.
inline constexpr const char* kGameFaultExport = "game_fault";

// Runs one mode and returns the exit code the executable ends with.
extern "C" FAULT_GATE_API int gate_run(const char* mode);
