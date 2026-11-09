// The call from the stand-in game (fault_gate.exe) into the mod side (fault_gate_mod.dll).
#pragma once

#ifdef FAULT_GATE_EXPORTS
#define FAULT_GATE_API __declspec(dllexport)
#else
#define FAULT_GATE_API __declspec(dllimport)
#endif

// Exit codes for a run that ended on its own. tools/test_fault_gate.py names the same three.
inline constexpr int kCheckFailed = 97;  // the code under test failed a check the gate makes before the fault
inline constexpr int kHookFailed = 98;   // the gate could not set up, so no fault was tried
inline constexpr int kSurvived = 99;     // the fault did not end the process

// The executable exports this function, `void (volatile int* target)`, as the code that counts as the game's own.
inline constexpr const char* kGameFaultExport = "game_fault";

// Runs one mode and returns the exit code the executable ends with.
extern "C" FAULT_GATE_API int gate_run(const char* mode);
