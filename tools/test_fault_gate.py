"""Gate for the FAULT line: runs fault_gate, a stand-in for the game that loads fault_gate_mod.dll (the real hook
wrapper, logger and fault handler), once per mode and reads the livemap.log it leaves.

ctest runs it on Windows. CI runs it again under Wine by setting FAULT_GATE_RUNNER to the Wine binary.
"""

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest

GATE = os.environ.get("FAULT_GATE_EXE", "")
RUNNER = shlex.split(os.environ.get("FAULT_GATE_RUNNER", ""))
ACCESS_VIOLATION = 0xC0000005
SENTINEL_EXITS = {98, 99}
TIMESTAMP_WIDTH = len("2000-01-01 00:00:00.000 ")
SURVIVED = "gate: the fault did not end the process"
SITE_CALLBACK = "gate_callback"
SITE_TRAMPOLINE = "gate_trampoline"
SITE_GAME = "gate_game"
HOOK_RAN = "gate: the hook ran"
AT_MODULE = "livemap"
AT_TRAMPOLINE = "trampoline"
AT_GAME = "game"
CALLBACK, TRAMPOLINE, TWICE = "callback", "trampoline", "twice"
GAME, UNHOOKED = "game", "unhooked"
PROBE, PROBE_THEN_FAULT = "probe", "probe_then_fault"
FAULT_LINE = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \[livemap\] FAULT code=0x[0-9A-F]{8}"
    rf" at=(?P<where>{AT_MODULE}|{AT_TRAMPOLINE}|{AT_GAME})\+0x[0-9A-F]{{8}} site=(?P<site>\S+)"
)
FAULTS = [
    (CALLBACK, AT_MODULE, SITE_CALLBACK),
    (TRAMPOLINE, AT_TRAMPOLINE, SITE_TRAMPOLINE),
    (TWICE, AT_TRAMPOLINE, SITE_TRAMPOLINE),
    (GAME, AT_GAME, SITE_GAME),
    (PROBE_THEN_FAULT, AT_MODULE, SITE_CALLBACK),
]
DEATHS = [CALLBACK, TRAMPOLINE, TWICE, GAME, UNHOOKED, PROBE_THEN_FAULT]


class Run(NamedTuple):
    exit_code: int
    lines: list[str]

    def faults(self):
        return [line for line in self.lines if "FAULT" in line]


def run_gate(directory: Path, mode: str) -> Run:
    assert GATE, "FAULT_GATE_EXE must name the fault_gate executable"
    done = subprocess.run([*RUNNER, GATE, mode], cwd=directory, capture_output=True, check=False, timeout=120)
    text = (directory / "livemap.log").read_bytes().decode("utf-8")
    assert text.endswith("\r\n"), "the log must end on a whole line"
    return Run(done.returncode & 0xFFFFFFFF, text[:-2].split("\r\n"))


@pytest.mark.parametrize(("mode", "where", "site"), FAULTS)
def test_a_fault_in_the_map_writes_one_fault_line(tmp_path, mode, where, site):
    run = run_gate(tmp_path, mode)

    assert len(run.faults()) == 1
    match = FAULT_LINE.fullmatch(run.faults()[0])
    assert match, run.faults()[0]
    assert (match["where"], match["site"]) == (where, site)


def test_a_fault_in_the_game_outside_a_hook_callback_writes_no_fault_line(tmp_path):
    assert run_gate(tmp_path, UNHOOKED).faults() == []


def test_a_bad_read_the_map_handles_itself_writes_no_fault_line(tmp_path):
    run = run_gate(tmp_path, PROBE)

    assert run.exit_code == 0
    assert run.lines[-1].endswith("gate: the probe handled its own bad read")
    assert run.faults() == []


@pytest.mark.parametrize("mode", DEATHS)
def test_the_process_dies_the_normal_way(tmp_path, mode):
    run = run_gate(tmp_path, mode)

    assert not any(line.endswith(SURVIVED) for line in run.lines)
    assert run.exit_code not in SENTINEL_EXITS
    if not RUNNER:
        assert run.exit_code == ACCESS_VIOLATION


def test_the_fault_line_follows_the_lines_written_before_it(tmp_path):
    run = run_gate(tmp_path, CALLBACK)

    assert [line[TIMESTAMP_WIDTH:] for line in run.lines[:2]] == [
        "gate: handler installed",
        "gate: calling the hooked function",
    ]
    assert FAULT_LINE.fullmatch(run.lines[2])


def test_the_trampoline_fault_follows_the_hook_callback(tmp_path):
    run = run_gate(tmp_path, TRAMPOLINE)

    fault = next(i for i, line in enumerate(run.lines) if "FAULT" in line)
    assert run.lines[fault - 1].endswith(HOOK_RAN)


def test_the_first_fault_is_the_only_one_written(tmp_path):
    run = run_gate(tmp_path, TWICE)

    skipped = [i for i, line in enumerate(run.lines) if line.endswith("gate: the first fault was skipped")]
    assert len(skipped) == 1
    assert FAULT_LINE.fullmatch(run.lines[skipped[0] - 1])
    assert len(run.faults()) == 1
