"""Tests for boot_test.py with synthetic builds, logs and a stand-in map server; ctest runs them with pytest."""

import hashlib
import http.server
import json
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import boot_test
import pytest
from boot_test import BootTestError
from test_data_only import job_block

ROOT = Path(__file__).resolve().parents[1]
ENCODING = "utf-8"
DATA = "data/builds.json"
PLAIN = "plain"
PATCHED = "patched"
KEY = "k3y-Under_test"
KEY_SHAPE = re.compile(r"[\w-]{3,64}", re.ASCII)
MANDATORY = ["player_table", "movement", "daytime", "registry"]
FRESH = {"raw": 100, "ageMs": 40, "dayStart": 1, "dayEnd": 2, "isDay": True}


def site(name, mandatory):
    return {"site": name, "bytes": "00", "offset": "0x0", "mandatory": mandatory}


def row(label, ids, sigset=PLAIN, **steam):
    return {
        "label": label,
        "buildids": ids,
        "sigset": sigset,
        "steam": {"depot": "1", "manifest": "9", "exe_sha256": "a" * 64, **steam},
    }


def builds_of(*rows):
    return {
        "sigsets": {
            PLAIN: [site(name, True) for name in MANDATORY] + [site("param_entity", False), site("mining", False)],
            PATCHED: [site(name, True) for name in [*MANDATORY, "param_entity"]] + [site("mining", False)],
        },
        "builds": list(rows),
    }


def hook_log(*names):
    lines = ["livemap starting: Enabled=1 Port=18080"]
    for name in names:
        if name == "param_entity":
            lines.append("entity ids  at world+0x830 (param_entity at 14065fc00)")
        else:
            lines.append(f"hooked {name:<12} at 1407bed90")
    return "\n".join(lines) + "\n"


def test_the_target_is_the_row_with_the_highest_steam_build_id():
    newest = row("b", ["300", "250"])
    builds = builds_of(row("a", ["100"]), newest, row("c", ["200"]))
    assert boot_test.pick_target(builds) is newest


def test_a_row_without_a_depot_or_manifest_cannot_be_the_target():
    wanted = row("old", ["100"])
    builds = builds_of(wanted, row("no-depot", ["900"], depot=None), row("no-manifest", ["800"], manifest=None))
    assert boot_test.pick_target(builds) is wanted


def test_no_row_with_a_download_is_an_error():
    with pytest.raises(BootTestError, match="depot"):
        boot_test.pick_target(builds_of(row("a", ["1"], depot=None)))


def test_the_shipped_builds_have_a_target():
    builds = json.loads((ROOT / DATA).read_text(encoding=ENCODING))
    target = boot_test.pick_target(builds)
    assert target["steam"]["depot"]
    assert boot_test.mandatory_sites(builds, target)


def test_mandatory_sites_follow_the_sigset_of_the_target():
    builds = builds_of(row("a", ["1"], PLAIN), row("b", ["2"], PATCHED))
    assert boot_test.mandatory_sites(builds, builds["builds"][0]) == MANDATORY
    assert boot_test.mandatory_sites(builds, builds["builds"][1]) == [*MANDATORY, "param_entity"]


def test_a_mandatory_site_with_no_known_log_line_is_an_error():
    builds = builds_of(row("a", ["1"]))
    builds["sigsets"][PLAIN].append(site("novel", True))
    with pytest.raises(BootTestError, match="novel"):
        boot_test.mandatory_sites(builds, builds["builds"][0])


def test_every_mandatory_hook_logged_leaves_nothing_missing():
    assert boot_test.missing_hooks(hook_log(*MANDATORY, "param_entity"), [*MANDATORY, "param_entity"]) == []


@pytest.mark.parametrize("gone", [*MANDATORY, "param_entity"])
def test_a_mandatory_hook_that_is_not_logged_is_reported(gone):
    names = [name for name in [*MANDATORY, "param_entity"] if name != gone]
    assert boot_test.missing_hooks(hook_log(*names), [*MANDATORY, "param_entity"]) == [gone]


def test_a_hook_of_another_site_does_not_count():
    assert boot_test.missing_hooks(hook_log("mining"), ["movement"]) == ["movement"]


def test_a_site_name_inside_another_word_does_not_count():
    assert boot_test.missing_hooks("hooked xregistry at 10\n", ["registry"]) == ["registry"]


def test_a_hook_line_needs_an_address():
    assert boot_test.missing_hooks("hooked registry at \n", ["registry"]) == ["registry"]


def test_a_failed_start_is_found_by_its_log_line():
    assert boot_test.start_failures("a\nmandatory pattern daytime not found; no live map\nb\n") == [
        "mandatory pattern daytime not found; no live map"
    ]
    assert boot_test.start_failures(hook_log(*MANDATORY)) == []


def test_an_unsafe_line_is_not_repeated_even_when_it_reports_a_failed_start():
    assert boot_test.start_failures("no live map 203.0.113.9\nno live map key=abc\nno live map announce\n") == []


def test_the_key_is_valid_and_new_every_time():
    first, second = boot_test.make_key(), boot_test.make_key()
    assert first != second
    assert KEY_SHAPE.fullmatch(first)


def test_the_ini_holds_the_key_and_keeps_the_map_off_the_network_lookups():
    text = boot_test.make_ini(KEY, 18080)
    pairs = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    assert pairs["Key"] == KEY
    assert pairs["Port"] == "18080"
    assert pairs["Enabled"] == "1"
    assert pairs["DetectPublicAddress"] == "0"
    assert pairs["AnnounceInChat"] == "0"
    assert pairs["Log"] == "1"
    assert text.startswith("[livemap]\n")


SUPERVISOR_OK = "2026-11-05 09:19:30,411 INFO success: enshrouded-server entered RUNNING state, process has stayed up"
SUPERVISOR_EXIT = "2026-11-05 09:19:31,000 WARN exited: enshrouded-server (exit status 1; not expected)"


@pytest.mark.parametrize(
    "line",
    [
        "Public ipv4: 203.0.113.9",
        "Server SteamId: 90000000000000000",
        "2026-11-05 09:19:07.334 supervisord: enshrouded-bootstrap INFO - Running enshrouded-bootstrap",
        "2026-11-05 09:19:30,411 INFO success: x entered RUNNING 203.0.113.9",
        "2026-11-05 09:19:30,411 INFO spawned: 'announce' with pid 4",
        "2026-11-05 09:19:30,411 INFO spawned: 'x' key=abc",
        "2026-11-05 09:19:30,411 INFO spawned: 'x' with map link http://example.invalid/",
        "2026-11-05 09:19:30,411 INFO spawned: 'x' with the Server SteamId 7",
        "map link: http://example.invalid/?key=abc",
        "a line from the game",
    ],
)
def test_only_supervisor_events_without_addresses_or_secrets_are_repeated(line):
    assert boot_test.supervisor_lines(f"{SUPERVISOR_OK}\n{line}\n{SUPERVISOR_EXIT}\n") == [
        SUPERVISOR_OK,
        SUPERVISOR_EXIT,
    ]


def test_a_fresh_state_has_no_problems():
    assert boot_test.state_problems({"time": FRESH}, {"time": {**FRESH, "raw": 200}}) == []


@pytest.mark.parametrize(
    ("edit", "words"),
    [
        (lambda s: s.update(time=None), "time"),
        (lambda s: s.pop("time"), "time"),
        (lambda s: s["time"].update(ageMs=boot_test.MAX_AGE_MS + 1), "old"),
        (lambda s: s["time"].update(ageMs=-1), "old"),
        (lambda s: s["time"].pop("ageMs"), "old"),
        (lambda s: s["time"].update(ageMs="40"), "old"),
        (lambda s: s["time"].update(raw=100), "stand"),
    ],
    ids=["null", "missing", "stale", "negative", "no age", "age as text", "clock stands still"],
)
def test_a_state_that_is_not_fresh_is_reported(edit, words):
    later = {"time": {**FRESH, "raw": 200}}
    earlier = {"time": {**FRESH}}
    edit(later)
    problems = boot_test.state_problems(earlier, later)
    assert problems
    assert any(words in problem for problem in problems)


def answer(self):
    authorised = self.path == f"/state?key={KEY}"
    self.send_response(self.status if authorised else 403)
    self.end_headers()
    self.wfile.write(self.body if authorised else b"forbidden")


@pytest.fixture
def serve():
    started = []

    def start(body=b"{}", status=200):
        handler = type(
            "Handler",
            (http.server.BaseHTTPRequestHandler,),
            {"do_GET": answer, "log_message": lambda *_args: None, "body": body, "status": status},
        )
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return server.server_address[1]

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def test_the_state_is_read_with_the_key(serve):
    port = serve(json.dumps({"time": FRESH}).encode())
    assert boot_test.fetch_state(port, KEY) == {"time": FRESH}


def test_a_refused_key_is_an_error_that_does_not_repeat_the_key(serve):
    port = serve()
    with pytest.raises(BootTestError) as caught:
        boot_test.fetch_state(port, "another-key")
    assert "403" in str(caught.value)
    assert "another-key" not in str(caught.value)


def test_a_state_that_is_not_json_is_an_error(serve):
    port = serve(b"<html>")
    with pytest.raises(BootTestError, match="JSON"):
        boot_test.fetch_state(port, KEY)


def test_a_state_that_is_not_an_object_is_an_error(serve):
    port = serve(b"[1]")
    with pytest.raises(BootTestError, match="object"):
        boot_test.fetch_state(port, KEY)


def test_nothing_listening_is_an_error_that_does_not_repeat_the_key():
    with pytest.raises(BootTestError) as caught:
        boot_test.fetch_state(1, KEY)
    assert KEY not in str(caught.value)


STATUS_UP = "enshrouded-server                RUNNING   pid 172, uptime 0:00:12"
STATUS_STARTING = "enshrouded-server                STARTING"
STATUS_FATAL = "enshrouded-server                FATAL     Exited too quickly (process log may have details)"
EXE = "enshrouded_server.exe"
SERVER = "server"
DLL = "iphlpapi.dll"
LOG = "livemap.log"
IMAGE = "example.invalid/server:1"
IDS = (1000, 1001)
PID = 172
CHILD = "c"
SOAK = boot_test.SOAK_SECONDS
TWICE = "2 times"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (STATUS_UP, ("RUNNING", PID)),
        (STATUS_STARTING, ("STARTING", None)),
        (STATUS_FATAL, ("FATAL", None)),
        (f"enshrouded-updater   RUNNING   pid 9, uptime 0:00:01\n{STATUS_STARTING}\n", ("STARTING", None)),
        ("enshrouded-updater   RUNNING   pid 9, uptime 0:00:01\n", None),
        ("Error: no such process", None),
        ("", None),
    ],
)
def test_the_supervisor_status_of_the_server_is_read_from_its_line(text, expected):
    assert boot_test.parse_status(text) == expected


class FakeClock:
    def __init__(self):
        self.seconds = 0.0

    def now(self):
        return self.seconds

    def sleep(self, seconds):
        self.seconds += seconds


HEALTHY = {
    "up_after": 30,
    "dies_after": None,
    "restarts_after": None,
    "extra_spawns": 0,
    "answers_after": None,
    "mute": False,
}


class FakeDocker:
    """Stands in for the docker command; the container named by sick follows its own timetable in simulated seconds."""

    def __init__(self, clock, sick=None, **plan):
        self.clock = clock
        self.sick = sick
        self.plan = {**HEALTHY, **plan}
        self.calls = []
        self.started = {}
        self.removed = []
        self.on_run = {}
        self.refuse = None
        self.unreadable_log = False
        self.logs = ""

    def timetable(self, name):
        return self.plan if self.sick in (None, name) else HEALTHY

    def __call__(self, *args):
        self.calls.append(args)
        verb = args[0]
        if verb == "run":
            return self.run(args[args.index("--name") + 1])
        if verb == "rm":
            self.removed.append(args[-1])
            return 0, ""
        if verb == "logs":
            return 0, self.logs
        return self.query(verb, args[1] if verb == "exec" else args[-1], args[2:])

    def spawns(self, plan, age):
        restarted = plan["restarts_after"] is not None and age >= plan["restarts_after"]
        return 1 + plan["extra_spawns"] + (1 if restarted else 0)

    def query(self, verb, name, command):
        if name not in self.started:
            return 1, "no such container"
        plan, age = self.timetable(name), self.clock.now() - self.started[name]
        if verb == "inspect":
            dead = plan["dies_after"] is not None and age >= plan["dies_after"]
            return 0, "exited" if dead else "running"
        return self.exec_reply(plan, age, command[0])

    def exec_reply(self, plan, age, program):
        if program == "grep":
            if self.unreadable_log:
                return 2, "grep: " + boot_test.SUPERVISOR_LOG + ": No such file or directory"
            return (0 if self.spawns(plan, age) else 1), f"{self.spawns(plan, age)}\n"
        if program == "python3":
            ready_at = plan["up_after"] if plan["answers_after"] is None else plan["answers_after"]
            return (0 if not plan["mute"] and age >= ready_at else 1), ""
        if age < plan["up_after"]:
            return 0, STATUS_STARTING
        return 0, STATUS_UP.replace(str(PID), str(PID + self.spawns(plan, age) - 1))

    def run(self, name):
        if self.refuse == name:
            return 1, ""
        self.started[name] = self.clock.now()
        self.on_run.get(name, lambda: None)()
        return 0, name

    def ran(self, name):
        return any(call[0] == "run" and name in call for call in self.calls)


def wait_up(docker, clock, timeout=300):
    docker.started[CHILD] = clock.now()
    return boot_test.wait_running(docker, CHILD, clock, timeout)


def test_wait_running_returns_the_server_pid_once_it_is_running():
    clock = FakeClock()
    assert wait_up(FakeDocker(clock, up_after=30), clock) == PID
    assert 30 <= clock.now() < 60


def test_wait_running_gives_up_after_the_timeout():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="STARTING"):
        wait_up(FakeDocker(clock, up_after=10_000), clock, timeout=100)
    assert 100 <= clock.now() < 130


def test_wait_running_stops_at_once_when_the_container_has_exited():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="exited"):
        wait_up(FakeDocker(clock, up_after=10_000, dies_after=0), clock)
    assert clock.now() == 0


def test_wait_running_stops_at_once_when_the_server_cannot_start():
    clock = FakeClock()

    def docker(*args):
        return (0, STATUS_FATAL) if args[0] == "exec" else (0, "running")

    with pytest.raises(BootTestError, match="FATAL"):
        boot_test.wait_running(docker, CHILD, clock, 300)
    assert clock.now() == 0


def test_wait_answering_stops_when_the_container_stops_before_the_game_answers():
    clock = FakeClock()
    docker = FakeDocker(clock, mute=True, dies_after=40)
    docker.started[CHILD] = clock.now()
    with pytest.raises(BootTestError, match="stopped before"):
        boot_test.wait_answering(docker, CHILD, clock, 1_000)
    assert 40 <= clock.now() < 40 + boot_test.POLL_SECONDS


def hold(docker, clock, seconds=SOAK):
    docker.started[CHILD] = clock.now() - 100
    boot_test.hold_running(docker, CHILD, clock, PID, seconds)


def test_hold_running_lasts_the_whole_time():
    clock = FakeClock()
    hold(FakeDocker(clock, up_after=0), clock)
    assert clock.now() >= SOAK


def test_hold_running_fails_when_the_container_exits():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="exited"):
        hold(FakeDocker(clock, up_after=0, dies_after=250), clock)
    assert clock.now() < 400


def test_hold_running_fails_when_the_server_restarts_under_its_supervisor():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="restart"):
        hold(FakeDocker(clock, up_after=0, restarts_after=250), clock)
    assert clock.now() < 400


def test_hold_running_fails_when_the_server_is_no_longer_running():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="STARTING"):
        hold(FakeDocker(clock, up_after=1_000), clock)


def reads(*states):
    queue = list(states)

    def fetch():
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return fetch


def at(raw, age=10):
    return {"time": {**FRESH, "raw": raw, "ageMs": age}}


def test_wait_fresh_passes_on_two_fresh_reads_apart():
    clock = FakeClock()
    boot_test.wait_fresh(reads(at(1), at(2)), clock, 60)
    assert clock.now() >= boot_test.READ_GAP_SECONDS


def test_wait_fresh_waits_for_the_clock_to_be_seen():
    boot_test.wait_fresh(reads({"time": None}, {"time": None}, at(1), at(2)), FakeClock(), 60)


def test_wait_fresh_fails_when_the_clock_never_moves():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="stands still"):
        boot_test.wait_fresh(reads(at(1)), clock, 30)
    assert clock.now() >= 30


def test_wait_fresh_reports_a_map_that_does_not_answer():
    def refuse():
        raise BootTestError("the map did not answer (URLError)")

    with pytest.raises(BootTestError, match="did not answer"):
        boot_test.wait_fresh(refuse, FakeClock(), 20)


def test_check_hooks_passes_when_all_are_logged():
    boot_test.check_hooks(lambda: hook_log(*MANDATORY), MANDATORY, FakeClock(), 30)


def test_check_hooks_names_the_hooks_that_never_appear():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="daytime") as caught:
        boot_test.check_hooks(lambda: hook_log("player_table", "movement", "registry"), MANDATORY, clock, 30)
    assert "registry" not in str(caught.value)
    assert clock.now() >= 30


def test_check_hooks_waits_for_a_late_log():
    texts = iter(["", "", hook_log(*MANDATORY)])
    boot_test.check_hooks(lambda: next(texts), MANDATORY, FakeClock(), 30)


def test_check_hooks_stops_at_once_on_a_failed_start():
    clock = FakeClock()
    with pytest.raises(BootTestError, match="no live map"):
        boot_test.check_hooks(lambda: "mandatory pattern daytime missing; no live map\n", MANDATORY, clock, 300)
    assert clock.now() == 0


def package_dir(parent, with_dll=True):
    package = parent / "package"
    (package / "livemap").mkdir(parents=True)
    (package / "livemap" / "index.html").write_bytes(b"page")
    if with_dll:
        (package / DLL).write_bytes(b"dll")
    return package


class Run:
    """One boot test against a fake docker; the containers leave files behind as the real ones do."""

    def __init__(self, tmp_path, log=None, **plan):
        self.root = tmp_path / "work" / "enshrouded"
        self.server = self.root / SERVER
        self.server.mkdir(parents=True)
        self.clock = FakeClock()
        self.seen = {}
        self.fetched = []
        self.output = []
        self.state = lambda: at(self.clock.now() + 1)
        self.log = hook_log(*MANDATORY, "param_entity") if log is None else log
        self.docker = FakeDocker(self.clock, **plan)
        self.docker.on_run[boot_test.BASELINE] = self.baseline_started
        self.docker.on_run[boot_test.WITH_DLL] = self.dll_started
        self.package = package_dir(tmp_path)
        self.dll_started_at = None

    def baseline_started(self):
        self.seen["baseline_had_dll"] = (self.server / DLL).exists()
        self.seen["version"] = (self.root / "current_version").read_text(encoding=ENCODING)
        (self.server / "savegame").mkdir()
        (self.server / "enshrouded_server.json").write_text("{}", encoding=ENCODING)
        (self.server / LOG).write_text("old\n", encoding=ENCODING)

    def dll_started(self):
        self.dll_started_at = self.clock.now()
        self.seen["baseline_lived"] = self.clock.now() - self.docker.started[boot_test.BASELINE]
        self.seen["baseline_removed"] = boot_test.BASELINE in self.docker.removed
        self.seen["log_kept"] = (self.server / LOG).exists()
        self.seen["savegame_kept"] = (self.server / "savegame").exists()
        self.seen["config_kept"] = (self.server / "enshrouded_server.json").exists()
        self.seen["ini"] = (self.server / "livemap.ini").read_text(encoding=ENCODING)
        self.seen["dll"] = (self.server / DLL).read_bytes()
        self.seen["page"] = (self.server / "livemap" / "index.html").exists()
        (self.server / LOG).write_text(self.log, encoding=ENCODING)

    def fetch(self, port, key):
        self.fetched.append((port, key, self.clock.now()))
        return self.state()

    def go(self):
        builds = builds_of(row("a", ["26430253", "100"], PATCHED))
        target = builds["builds"][0]
        setup = boot_test.Setup(
            root=self.root,
            package=self.package,
            target=target,
            names=boot_test.mandatory_sites(builds, target),
            image=IMAGE,
            key=KEY,
            ids=IDS,
        )
        return boot_test.run_boot_test(setup, boot_test.Tools(self.docker, self.clock, self.fetch, self.output.append))

    def errors(self):
        return [line for line in self.output if line.startswith("::error::")]


def test_a_server_that_boots_with_the_dll_passes(tmp_path):
    run = Run(tmp_path)
    assert run.go() == 0
    assert run.output[-1].startswith("boot test passed")


def test_the_baseline_runs_first_without_the_dll_and_on_the_target_version(tmp_path):
    run = Run(tmp_path)
    run.go()
    assert run.seen["baseline_had_dll"] is False
    assert run.seen["version"].strip() == "26430253"
    runs = [call for call in run.docker.calls if call[0] == "run"]
    assert [call[call.index("--name") + 1] for call in runs] == [boot_test.BASELINE, boot_test.WITH_DLL]


def test_the_dll_run_starts_from_a_fresh_world_with_the_dll_and_the_generated_ini(tmp_path):
    run = Run(tmp_path)
    run.go()
    assert run.seen["baseline_removed"] is True
    assert run.seen["savegame_kept"] is False
    assert run.seen["config_kept"] is False
    assert run.seen["log_kept"] is False
    assert run.seen["dll"] == b"dll"
    assert run.seen["page"] is True
    assert f"Key={KEY}\n" in run.seen["ini"]


def test_the_server_runs_as_the_runner_with_updates_off_and_only_the_map_port_published(tmp_path):
    run = Run(tmp_path)
    run.go()
    baseline, with_dll = (call for call in run.docker.calls if call[0] == "run")
    for call in (baseline, with_dll):
        assert "PUID=1000" in call
        assert "PGID=1001" in call
        assert "GAME_BRANCH=nonexistent" in call
        assert call[-1] == IMAGE
        assert f"{run.root}:/opt/enshrouded" in call
    assert "-p" not in baseline
    assert f"127.0.0.1:{boot_test.PORT}:{boot_test.PORT}/tcp" in with_dll


def test_the_soak_lasts_ten_minutes_and_the_map_is_checked_again_at_its_end(tmp_path):
    run = Run(tmp_path)
    run.go()
    assert run.clock.now() - run.dll_started_at >= SOAK
    assert run.fetched[-1][2] - run.dll_started_at >= SOAK


def test_the_key_is_masked_first_and_never_printed_again(tmp_path):
    run = Run(tmp_path)
    run.go()
    assert run.output[0] == f"::add-mask::{KEY}"
    assert not any(KEY in line for line in run.output[1:])


def test_both_containers_are_removed_at_the_end(tmp_path):
    run = Run(tmp_path)
    run.go()
    assert set(run.docker.removed) == {boot_test.BASELINE, boot_test.WITH_DLL}


def test_a_baseline_that_never_boots_fails_before_the_dll_is_tried(tmp_path):
    run = Run(tmp_path, up_after=10_000)
    assert run.go() == 1
    assert not run.docker.ran(boot_test.WITH_DLL)
    assert any("baseline" in line for line in run.errors())
    assert set(run.docker.removed) == {boot_test.BASELINE, boot_test.WITH_DLL}


def test_a_missing_mandatory_hook_fails_and_names_it(tmp_path):
    run = Run(tmp_path, log=hook_log("player_table", "movement", "registry", "param_entity"))
    assert run.go() == 1
    assert any("daytime" in line for line in run.errors())
    assert set(run.docker.removed) == {boot_test.BASELINE, boot_test.WITH_DLL}


def test_a_dll_that_reports_no_live_map_fails_with_its_reason(tmp_path):
    run = Run(tmp_path, log="pattern daytime matched 0 times; no live map\n")
    assert run.go() == 1
    assert any("matched 0 times" in line for line in run.errors())


def test_a_server_that_exits_during_the_soak_fails(tmp_path):
    run = Run(tmp_path, sick=boot_test.WITH_DLL, dies_after=200)
    assert run.go() == 1
    assert any("exited" in line for line in run.errors())


def test_a_server_that_restarts_during_the_soak_fails(tmp_path):
    run = Run(tmp_path, sick=boot_test.WITH_DLL, restarts_after=300)
    assert run.go() == 1
    assert any("restart" in line for line in run.errors())


def test_a_map_without_fresh_data_fails(tmp_path):
    run = Run(tmp_path)
    run.state = lambda: {"time": None}
    assert run.go() == 1
    assert any("time is null" in line for line in run.errors())
    assert run.clock.now() - run.dll_started_at < SOAK


def test_docker_refusing_to_start_the_container_fails_without_repeating_its_output(tmp_path):
    run = Run(tmp_path)
    run.docker.refuse = boot_test.BASELINE
    assert run.go() == 1
    assert any("docker run" in line for line in run.errors())


def test_a_package_without_the_dll_fails_before_anything_is_started(tmp_path):
    run = Run(tmp_path)
    run.package = package_dir(tmp_path / "other", with_dll=False)
    assert run.go() == 1
    assert not run.docker.ran(boot_test.BASELINE)
    assert any(DLL in line for line in run.errors())


def test_a_failure_shows_supervisor_events_and_nothing_else_of_the_container_log(tmp_path):
    run = Run(tmp_path, up_after=10_000)
    run.docker.logs = f"Public ipv4: 203.0.113.9\n{SUPERVISOR_EXIT}\nServer SteamId: 7\n"
    run.go()
    shown = "\n".join(run.output)
    assert SUPERVISOR_EXIT in shown
    assert "203.0.113.9" not in shown
    assert "SteamId" not in shown


def test_a_baseline_that_is_restarted_by_its_supervisor_fails_even_though_it_reaches_running(tmp_path):
    run = Run(tmp_path, sick=boot_test.BASELINE, extra_spawns=1)
    assert run.go() == 1
    assert not run.docker.ran(boot_test.WITH_DLL)
    assert any("baseline" in line and TWICE in line for line in run.errors())


def test_a_dll_run_that_was_restarted_before_running_fails_before_the_soak(tmp_path):
    run = Run(tmp_path, sick=boot_test.WITH_DLL, extra_spawns=1)
    assert run.go() == 1
    assert any(TWICE in line for line in run.errors())
    assert run.clock.now() - run.dll_started_at < SOAK


def test_a_restart_after_the_last_check_of_the_soak_still_fails_the_run(tmp_path):
    run = Run(tmp_path, sick=boot_test.WITH_DLL)
    reads = []

    def state():
        reads.append(run.clock.now())
        if len(reads) == 3:
            run.docker.plan["restarts_after"] = run.clock.now() - run.docker.started[boot_test.WITH_DLL]
        return at(run.clock.now() + 1)

    run.state = state
    assert run.go() == 1
    assert any(TWICE in line for line in run.errors())
    assert run.clock.now() - run.dll_started_at >= SOAK


def test_a_supervisor_log_that_cannot_be_read_fails_the_run(tmp_path):
    run = Run(tmp_path)
    run.docker.unreadable_log = True
    assert run.go() == 1
    assert any("supervisor log" in line for line in run.errors())


def test_a_grep_that_failed_is_not_trusted_even_when_it_printed_a_count():
    with pytest.raises(boot_test.BootTestError, match="supervisor log"):
        boot_test.spawn_count(lambda *_: (2, "1\n"), boot_test.BASELINE)


def test_a_supervisor_log_that_lists_no_start_fails_the_run():
    with pytest.raises(boot_test.BootTestError, match="0 times"):
        boot_test.require_single_start(lambda *_: (1, "0\n"), boot_test.BASELINE)


def test_the_baseline_waits_until_the_game_answers_its_query_port_and_then_stays_up_a_minute(tmp_path):
    run = Run(tmp_path, sick=boot_test.BASELINE, answers_after=120)
    assert run.go() == 0
    assert run.seen["baseline_lived"] >= 120 + boot_test.BASELINE_HOLD_SECONDS


def test_a_baseline_that_never_answers_its_query_port_fails_before_the_dll_is_tried(tmp_path):
    run = Run(tmp_path, sick=boot_test.BASELINE, mute=True)
    assert run.go() == 1
    assert not run.docker.ran(boot_test.WITH_DLL)
    assert any("baseline" in line and "query port" in line for line in run.errors())


def test_a_baseline_that_exits_within_a_minute_of_answering_fails(tmp_path):
    run = Run(tmp_path, sick=boot_test.BASELINE, dies_after=boot_test.BASELINE_HOLD_SECONDS)
    assert run.go() == 1
    assert not run.docker.ran(boot_test.WITH_DLL)
    assert any("baseline" in line and "exited" in line for line in run.errors())


def serve_queries(answers):
    """A stand-in game on a UDP port; answers(datagram) gives the reply or None."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))

    def loop():
        while True:
            try:
                data, peer = udp.recvfrom(1400)
            except OSError:
                return
            reply = answers(data)
            if reply is not None:
                udp.sendto(reply, peer)

    threading.Thread(target=loop, daemon=True).start()
    return udp


A2S_HEADER = b"\xff\xff\xff\xff"
A2S_REQUEST = A2S_HEADER + b"TSource Engine Query\x00"
A2S_CHALLENGE = b"\x01\x02\x03\x04"


def probe(port):
    return subprocess.run(
        [sys.executable, "-I", "-c", boot_test.query_probe(port, timeout=0.5)], capture_output=True, check=False
    ).returncode


@pytest.fixture
def game():
    sockets = []

    def start(answers):
        udp = serve_queries(answers)
        sockets.append(udp)
        return udp.getsockname()[1]

    yield start
    for udp in sockets:
        udp.close()


def test_the_query_probe_accepts_a_game_that_answers_the_info_request(game):
    port = game(lambda data: A2S_HEADER + b"I" + b"info" if data == A2S_REQUEST else None)
    assert probe(port) == 0


def test_the_query_probe_answers_the_challenge_a_game_sends_first(game):
    def answers(data):
        if data == A2S_REQUEST:
            return A2S_HEADER + b"A" + A2S_CHALLENGE
        return A2S_HEADER + b"I" + b"info" if data == A2S_REQUEST + A2S_CHALLENGE else None

    assert probe(game(answers)) == 0


def test_the_query_probe_rejects_a_reply_that_is_not_an_info_answer(game):
    assert probe(game(lambda _data: A2S_HEADER + b"E" + b"nope")) != 0
    assert probe(game(lambda _data: b"hello")) != 0


def test_the_query_probe_rejects_a_port_nobody_answers(game):
    assert probe(game(lambda _data: None)) != 0


def write_exe(directory, data=b"synthetic server bytes"):
    (directory / EXE).write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def test_the_downloaded_exe_must_match_the_digest_of_the_target(tmp_path):
    digest = write_exe(tmp_path)
    boot_test.verify_exe(row("a", ["1"], exe_sha256=digest), tmp_path)
    with pytest.raises(BootTestError, match="does not match"):
        boot_test.verify_exe(row("a", ["1"], exe_sha256="0" * 64), tmp_path)


def test_a_target_without_a_recorded_digest_cannot_be_verified(tmp_path):
    write_exe(tmp_path)
    with pytest.raises(BootTestError, match="no exe_sha256"):
        boot_test.verify_exe(row("a", ["1"], exe_sha256=None), tmp_path)


def test_a_download_without_the_exe_is_an_error(tmp_path):
    with pytest.raises(BootTestError, match="not found"):
        boot_test.verify_exe(row("a", ["1"]), tmp_path)


def test_the_download_ids_are_digits_only_so_they_are_safe_in_a_command():
    ids = boot_test.download_ids(row("a", ["25", "300"], depot="2278521", manifest="8886672487109033979"))
    assert ids == {"depot": "2278521", "manifest": "8886672487109033979", "buildid": "300"}


@pytest.mark.parametrize(
    "target",
    [
        row("a", ["1"], depot="1; id"),
        row("a", ["1"], manifest="$(id)"),
        row("a", ["1 && id"]),
        row("a", ["01"]),
    ],
)
def test_ids_that_are_not_plain_digits_are_refused(target):
    with pytest.raises(BootTestError, match="not a plain id"):
        boot_test.download_ids(target)


def test_a_row_with_a_hostile_build_id_does_not_crash_the_pick():
    builds = builds_of(row("a", ["1 && id"]), row("b", ["5"]))
    assert boot_test.pick_target(builds)["label"] == "b"


def write_builds(root, builds):
    (root / "data").mkdir()
    (root / DATA).write_text(json.dumps(builds), encoding=ENCODING)


def test_the_target_command_writes_the_download_ids_for_the_workflow(tmp_path, monkeypatch, capsys):
    write_builds(tmp_path, builds_of(row("a", ["300"], depot="7", manifest="8")))
    output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert boot_test.main(["target"], tmp_path) == 0
    assert output.read_text(encoding=ENCODING) == "depot=7\nmanifest=8\nbuildid=300\n"
    assert "300" in capsys.readouterr().out


def test_the_target_command_fails_on_a_file_without_a_download(tmp_path, capsys):
    write_builds(tmp_path, builds_of(row("a", ["1"], depot=None)))
    assert boot_test.main(["target"], tmp_path) == 1
    assert "::error::" in capsys.readouterr().out


def test_the_verify_command_checks_the_download_against_the_target(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    server = tmp_path / SERVER
    server.mkdir()
    write_builds(tmp_path, builds_of(row("a", ["1"], exe_sha256=write_exe(server))))
    assert boot_test.main(["verify-exe", str(server)], tmp_path) == 0
    write_builds_again = builds_of(row("a", ["1"], exe_sha256="0" * 64))
    (tmp_path / DATA).write_text(json.dumps(write_builds_again), encoding=ENCODING)
    assert boot_test.main(["verify-exe", str(server)], tmp_path) == 1
    assert "does not match" in capsys.readouterr().out


@pytest.mark.parametrize("shape", [("verify-exe", "out"), ("run", "out", "in"), ("run", "in", "out")])
def test_a_path_outside_the_working_directory_and_runner_temp_exits_1(shape, tmp_path, monkeypatch, capsys):
    cwd, inside, outside = tmp_path / "cwd", tmp_path / "temp", tmp_path / "elsewhere"
    for folder in (cwd, inside, outside):
        folder.mkdir()
    write_builds(tmp_path, builds_of(row("a", ["1"], exe_sha256=write_exe(outside))))
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("RUNNER_TEMP", str(inside))
    choice = {"in": str(inside), "out": str(outside)}
    assert boot_test.main([choice.get(word, word) for word in shape], tmp_path) == 1
    assert "outside the working directory" in capsys.readouterr().out


def test_an_unknown_command_is_a_usage_error(tmp_path, capsys):
    assert boot_test.main(["frobnicate"], tmp_path) == 2
    assert "usage" in capsys.readouterr().out


def test_run_needs_the_image_from_the_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BOOT_TEST_IMAGE", raising=False)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    assert boot_test.main(["run", str(tmp_path), str(tmp_path)], tmp_path) == 1
    assert "BOOT_TEST_IMAGE" in capsys.readouterr().out


def test_the_docker_wrapper_returns_the_exit_code_and_text_of_the_command():
    docker = boot_test.Docker((sys.executable, "-c", "import sys; print(sys.argv[1:]); sys.exit(3)"))
    assert docker("a", "b") == (3, "['a', 'b']\n")


def test_a_docker_command_that_hangs_is_an_error_and_not_a_hung_job():
    docker = boot_test.Docker((sys.executable, "-c", "import time; time.sleep(30)"), call_timeout=0.5)
    with pytest.raises(BootTestError, match="did not finish"):
        docker("ps")


def test_starting_a_container_may_take_the_longer_time_a_pull_needs():
    docker = boot_test.Docker((sys.executable, "-c", "import time; time.sleep(1.5)"), call_timeout=0.5, run_timeout=30)
    assert docker("run")[0] == 0
    with pytest.raises(BootTestError, match="did not finish"):
        docker("ps")


def test_the_docker_wrapper_reports_a_command_that_cannot_run(tmp_path):
    with pytest.raises(BootTestError, match="could not run"):
        boot_test.Docker((str(tmp_path / "no-such-docker"),))("ps")


BOOT_JOB = "boot-test"
EXE_CAPTURE = ROOT / ".github" / "workflows" / "exe-capture.yaml"
IMAGE_PIN = (
    r"# renovate: datasource=docker depName=mornedhels/enshrouded-server\n"
    r"\s+BOOT_TEST_IMAGE: \"mornedhels/enshrouded-server:[^@\"\s]+@sha256:[0-9a-f]{64}\"\n"
)


def test_a_failing_boot_test_fails_the_check():
    assert "continue-on-error" not in job_block(BOOT_JOB)


def test_no_game_file_can_leave_the_runner_through_the_job():
    block = job_block(BOOT_JOB)
    for word in ("upload-artifact", "actions/cache", "cache:"):
        assert word not in block


def test_the_boot_test_job_can_only_read_the_repository():
    assert re.search(r" {4}permissions:\n {6}contents: read\n(?! {6})", job_block(BOOT_JOB))


def test_the_server_image_is_pinned_in_the_shape_the_renovate_manager_reads():
    assert re.search(IMAGE_PIN, job_block(BOOT_JOB))


def test_the_depot_downloads_write_their_file_lists_to_a_file_and_not_to_the_log():
    downloads = [
        line for line in job_block(BOOT_JOB).splitlines() if "tools/DepotDownloader" in line and "-app" in line
    ]
    assert len(downloads) == 2
    assert all('"$log" 2>&1' in line for line in downloads)


def test_the_downloader_is_checked_and_the_depot_verified_before_the_server_boots():
    block = job_block(BOOT_JOB)
    order = (
        "boot_test.py target",
        "sha256sum --check",
        'tools/DepotDownloader" -app',
        "boot_test.py verify-exe",
        "boot_test.py run",
    )
    positions = [block.index(part) for part in order]
    assert positions == sorted(positions)


def test_the_containers_and_game_files_are_removed_even_after_a_failure():
    block = job_block(BOOT_JOB)
    assert re.search(r"- name: Remove[^\n]*\n\s+if: always\(\)\n", block)
    assert "docker rm -f" in block


def pinned_value(text, name):
    match = re.search(rf"^ +{name}: (\S+)$", text, re.MULTILINE)
    assert match, f"{name} is not set"
    return match.group(1)


@pytest.mark.parametrize("name", ["DEPOTDOWNLOADER_URL", "DEPOTDOWNLOADER_SHA256"])
def test_the_downloader_is_pinned_to_the_same_release_as_the_exe_capture_job(name):
    ours = pinned_value(job_block(BOOT_JOB), name)
    assert ours == pinned_value(EXE_CAPTURE.read_text(encoding=ENCODING), name)
