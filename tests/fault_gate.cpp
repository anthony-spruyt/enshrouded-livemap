// The stand-in for the game: it owns the code that counts as the game's own. The mod side, with the real hook wrapper,
// logger and fault handler, is fault_gate_mod.dll. tools/test_fault_gate.py runs this once per mode and reads livemap.log.
#include <Windows.h>

#include "fault_gate.h"

namespace {

void game_fault(volatile int* target) {
    *target = 1;
}

}  // namespace

int main(int argc, char** argv) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return argc == 2 ? gate_run(argv[1], game_fault) : kHookFailed;
}
