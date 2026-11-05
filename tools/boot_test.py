"""Boots the real Enshrouded server with the built DLL and checks that the map comes up.

Run it from the repository root. The game files stay under the work directory and are never printed, logged or
uploaded; the output carries only site names, supervisor events and verdicts. ctest runs test_boot_test.py.
"""

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from data_only import annotation, github_output
from paths import safe_path

DATA_FILE = "data/builds.json"
USAGE = "usage: boot_test.py target | verify-exe SERVER_DIR | run WORK_DIR PACKAGE_DIR"
ENCODING = "utf-8"
PORT = 18080
MAX_AGE_MS = 5000
STATE_TIMEOUT = 5
ID_SHAPE = re.compile(r"[1-9]\d{0,19}", re.ASCII)
COUNT_SHAPE = re.compile(r"\d{1,6}", re.ASCII)

BASELINE = "boot-test-baseline"
WITH_DLL = "boot-test-livemap"
SERVER_PROGRAM = "enshrouded-server"
SUPERVISOR_LOG = "/var/log/supervisor/supervisord.log"
QUERY_PORT = 15637
EXE_NAME = "enshrouded_server.exe"
DLL_NAME = "iphlpapi.dll"
SERVER_DIR = "server"
RUNTIME_STATE = ("appcache", "config", "logs", "savegame", "enshrouded_server.json", "livemap.log")
STATUS_LINE = re.compile(rf"^{SERVER_PROGRAM}\s+(\w+)(?:\s+pid (\d+))?", re.MULTILINE)

POLL_SECONDS = 2
READ_GAP_SECONDS = 5
RUNNING_TIMEOUT = 300
ANSWER_TIMEOUT = 240
BASELINE_HOLD_SECONDS = 60
CALL_TIMEOUT = 60
PULL_TIMEOUT = 300
HOOKS_TIMEOUT = 60
FRESH_TIMEOUT = 180
FINAL_FRESH_TIMEOUT = 60
SOAK_SECONDS = 600
SOAK_INTERVAL = 15
LOG_TAIL = 30

HOOKED_SITES = {"player_table", "movement", "daytime", "registry", "mining", "chest", "bases"}
ENTITY_LINE = re.compile(r"entity ids\s+at world\+0x[0-9a-f]+ \(param_entity at [0-9a-f]+\)")
SUPERVISOR_EVENT = re.compile(
    r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} (INFO|WARN|CRIT) (spawned|success|exited|gave up|waiting|killing)\b"
)
UNSAFE = re.compile(r"\d{1,3}(\.\d{1,3}){3}|announce|key=|map link|SteamId", re.IGNORECASE)
FAILED_START = "no live map"


class BootTestError(Exception):
    pass


def pick_target(builds):
    """The newest supported build that records where to download it."""
    rows = [b for b in builds["builds"] if b["steam"]["depot"] and b["steam"]["manifest"]]
    if not rows:
        raise BootTestError(f"no build in {DATA_FILE} records a Steam depot and manifest to download")
    return max(rows, key=_build_number)


def _build_number(target):
    return max((int(i) for i in target["buildids"] if ID_SHAPE.fullmatch(i)), default=0)


def download_ids(target):
    values = {"depot": target["steam"]["depot"], "manifest": target["steam"]["manifest"]}
    for name, value in [*values.items(), *(("buildid", i) for i in target["buildids"])]:
        if not ID_SHAPE.fullmatch(value):
            raise BootTestError(f"{name} {value!r} of build {target['label']} is not a plain id")
    return {**values, "buildid": str(_build_number(target))}


def verify_exe(target, server_dir):
    expected = target["steam"]["exe_sha256"]
    if not expected:
        raise BootTestError(
            f"build {target['label']} records a manifest but no exe_sha256 to check the download against"
        )
    exe = Path(server_dir) / EXE_NAME
    if not exe.is_file():
        raise BootTestError(f"{EXE_NAME} not found in the download")
    digest = hashlib.sha256()
    with exe.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise BootTestError(
            f"{EXE_NAME} does not match the exe_sha256 of build {target['label']} (got {digest.hexdigest()})"
        )


def hook_pattern(name):
    if name == "param_entity":
        return ENTITY_LINE
    if name in HOOKED_SITES:
        return re.compile(rf"hooked {name}\s+at [0-9a-f]+")
    raise BootTestError(f"mandatory site {name} has no known livemap.log line; teach boot_test.py its wording")


def mandatory_sites(builds, target):
    names = [p["site"] for p in builds["sigsets"][target["sigset"]] if p["mandatory"]]
    for name in names:
        hook_pattern(name)
    return names


def missing_hooks(log_text, names):
    return [name for name in names if not hook_pattern(name).search(log_text)]


def is_safe(line):
    return not UNSAFE.search(line)


def start_failures(log_text):
    return [line.strip() for line in log_text.splitlines() if FAILED_START in line and is_safe(line)]


def supervisor_lines(text):
    return [line for line in text.splitlines() if SUPERVISOR_EVENT.match(line) and is_safe(line)]


def make_key():
    return secrets.token_urlsafe(24)


def make_ini(key, port):
    return (
        "[livemap]\n"
        "Enabled=1\n"
        f"Port={port}\n"
        "Bind=0.0.0.0\n"
        f"Key={key}\n"
        "DetectPublicAddress=0\n"
        "AnnounceInChat=0\n"
        "UpdateMs=250\n"
        "Log=1\n"
        "LogDiagnostics=1\n"
    )


def _age_problem(state):
    age = (state.get("time") or {}).get("ageMs")
    if isinstance(age, int) and not isinstance(age, bool) and 0 <= age <= MAX_AGE_MS:
        return None
    return f"the time sample is too old or has no age (ageMs {age!r}, at most {MAX_AGE_MS})"


def state_problems(first, second):
    if not all(isinstance(state.get("time"), dict) for state in (first, second)):
        return ["time is null: the daytime hook has not seen the game clock"]
    problems = [problem for problem in map(_age_problem, (first, second)) if problem]
    if first["time"].get("raw") == second["time"].get("raw"):
        problems.append("the game clock stands still between two reads")
    return problems


def fetch_state(port, key):
    url = f"http://127.0.0.1:{port}/state?key={key}"
    try:
        with urllib.request.urlopen(url, timeout=STATE_TIMEOUT) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        raise BootTestError(f"the map answered HTTP {error.code}") from None
    except OSError as error:
        raise BootTestError(f"the map did not answer ({type(error).__name__})") from None
    try:
        state = json.loads(body)
    except ValueError:
        raise BootTestError("the map's /state is not JSON") from None
    if not isinstance(state, dict):
        raise BootTestError("the map's /state is not a JSON object")
    return state


def parse_status(text):
    match = STATUS_LINE.search(text)
    if not match:
        return None
    return match.group(1), int(match.group(2)) if match.group(2) else None


class Docker:
    def __init__(self, command=("docker",), call_timeout=CALL_TIMEOUT, run_timeout=PULL_TIMEOUT):
        self.command = tuple(command)
        self.call_timeout = call_timeout
        self.run_timeout = run_timeout

    def __call__(self, *args):
        timeout = self.run_timeout if args[0] == "run" else self.call_timeout
        try:
            result = subprocess.run(
                [*self.command, *args], capture_output=True, text=True, errors="replace", check=False, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise BootTestError(f"docker {args[0]} did not finish within {timeout} s") from None
        except OSError as error:
            raise BootTestError(f"docker could not run ({type(error).__name__})") from None
        return result.returncode, result.stdout + result.stderr


class Clock:
    def now(self):
        return time.monotonic()

    def sleep(self, seconds):
        time.sleep(seconds)


@dataclass(frozen=True)
class Setup:
    root: Path
    package: Path
    target: dict
    names: list
    image: str
    key: str
    ids: tuple


@dataclass(frozen=True)
class Tools:
    docker: Callable
    clock: object
    fetch: Callable
    say: Callable


def container_state(docker, name):
    code, text = docker("inspect", "-f", "{{.State.Status}}", name)
    return text.strip() if code == 0 else "missing"


def server_status(docker, name):
    return parse_status(docker("exec", name, "supervisorctl", "status", SERVER_PROGRAM)[1])


def query_probe(port, timeout=2):
    """Python source that exits 0 when the game answers an A2S info query on the port; it runs inside the container."""
    return (
        "import socket, sys\n"
        "request = b'\\xff\\xff\\xff\\xffTSource Engine Query\\x00'\n"
        "udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"udp.settimeout({timeout})\n"
        f"address = ('127.0.0.1', {port})\n"
        "udp.sendto(request, address)\n"
        "reply = udp.recv(1400)\n"
        "if reply[4:5] == b'A':\n"
        "    udp.sendto(request + reply[5:9], address)\n"
        "    reply = udp.recv(1400)\n"
        "sys.exit(0 if reply[4:5] == b'I' else 1)\n"
    )


def spawn_count(docker, name):
    code, text = docker("exec", name, "grep", "-c", "-F", f"spawned: '{SERVER_PROGRAM}'", SUPERVISOR_LOG)
    count = text.strip()
    if code not in (0, 1) or not COUNT_SHAPE.fullmatch(count):
        raise BootTestError("the supervisor log could not be read to count the server's starts")
    return int(count)


def require_single_start(docker, name):
    count = spawn_count(docker, name)
    if count != 1:
        raise BootTestError(f"the supervisor started the server {count} times, not once: it exited and was restarted")


def wait_answering(docker, name, clock, timeout):
    deadline = clock.now() + timeout
    probe = query_probe(QUERY_PORT)
    while docker("exec", name, "python3", "-c", probe)[0] != 0:
        if container_state(docker, name) != "running":
            raise BootTestError("the container stopped before the server answered its query port")
        if clock.now() >= deadline:
            raise BootTestError(f"the server did not answer its query port within {timeout} s")
        clock.sleep(POLL_SECONDS)


def wait_running(docker, name, clock, timeout):
    deadline = clock.now() + timeout
    while True:
        state = container_state(docker, name)
        if state != "running":
            raise BootTestError(f"the container is {state}, not running")
        status = server_status(docker, name)
        if status and status[0] == "RUNNING":
            return status[1]
        if status and status[0] == "FATAL":
            raise BootTestError("the server went FATAL before it reached RUNNING")
        if clock.now() >= deadline:
            raise BootTestError(
                f"the server was not RUNNING after {timeout} s (last state {status[0] if status else 'unreadable'})"
            )
        clock.sleep(POLL_SECONDS)


def hold_running(docker, name, clock, pid, seconds):
    start = clock.now()
    end = start + seconds
    while clock.now() < end:
        clock.sleep(min(SOAK_INTERVAL, end - clock.now()))
        where = f"{int(clock.now() - start)} s into the soak"
        state = container_state(docker, name)
        if state != "running":
            raise BootTestError(f"the container {state} {where}")
        status = server_status(docker, name)
        if not status or status[0] != "RUNNING":
            raise BootTestError(f"the server left RUNNING ({status[0] if status else 'unreadable'}) {where}")
        if status[1] != pid:
            raise BootTestError(f"the server restarted {where}")


def wait_fresh(fetch, clock, timeout):
    deadline = clock.now() + timeout
    while True:
        try:
            first = fetch()
            clock.sleep(READ_GAP_SECONDS)
            problems = state_problems(first, fetch())
        except BootTestError as error:
            problems = [str(error)]
        if not problems:
            return
        if clock.now() >= deadline:
            raise BootTestError("the map's data is not fresh: " + "; ".join(problems))
        clock.sleep(POLL_SECONDS)


def check_hooks(read_log, names, clock, timeout):
    deadline = clock.now() + timeout
    while True:
        text = read_log()
        failures = start_failures(text)
        if failures:
            raise BootTestError("the DLL did not start the map: " + "; ".join(failures))
        missing = missing_hooks(text, names)
        if not missing:
            return
        if clock.now() >= deadline:
            raise BootTestError("livemap.log does not list the mandatory hooks: " + ", ".join(missing))
        clock.sleep(POLL_SECONDS)


def check_package(package):
    if not (package / DLL_NAME).is_file() or not (package / "livemap").is_dir():
        raise BootTestError(f"the package has no {DLL_NAME} and livemap folder")


def reset_state(root):
    for name in RUNTIME_STATE:
        path = root / SERVER_DIR / name
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)


def install(setup):
    server = setup.root / SERVER_DIR
    shutil.copy2(setup.package / DLL_NAME, server / DLL_NAME)
    shutil.copytree(setup.package / "livemap", server / "livemap", dirs_exist_ok=True)
    (server / "livemap.ini").write_bytes(make_ini(setup.key, PORT).encode(ENCODING))


def start(docker, name, setup, publish):
    uid, gid = setup.ids
    args = ["run", "-d", "--name", name, "-e", f"PUID={uid}", "-e", f"PGID={gid}"]
    for setting in (
        "GAME_BRANCH=nonexistent",
        "SERVER_NAME=ci-boot-test",
        "SERVER_SLOT_COUNT=2",
        "WINEDLLOVERRIDES=iphlpapi=n,b",
    ):
        args += ["-e", setting]
    if publish:
        args += ["-p", f"127.0.0.1:{PORT}:{PORT}/tcp"]
    code, _ = docker(*args, "-v", f"{setup.root}:/opt/enshrouded", setup.image)
    if code != 0:
        raise BootTestError(f"docker run failed for {name} (exit {code})")


def read_log(root):
    try:
        return (root / SERVER_DIR / "livemap.log").read_text(encoding=ENCODING, errors="replace")
    except OSError:
        return ""


def diagnose(tools):
    for name in (BASELINE, WITH_DLL):
        code, text = tools.docker("logs", "--tail", "500", name)
        events = supervisor_lines(text) if code == 0 else []
        if events:
            tools.say(f"supervisor events of {name}:")
            for line in events[-LOG_TAIL:]:
                tools.say(f"  {line}")


def run_boot_test(setup, tools):
    say, docker, clock = tools.say, tools.docker, tools.clock
    say(f"::add-mask::{setup.key}")
    try:
        check_package(setup.package)
        (setup.root / "current_version").write_text(f"{_build_number(setup.target)}\n", encoding=ENCODING)
        say("baseline: the server without the DLL")
        start(docker, BASELINE, setup, publish=False)
        try:
            baseline_pid = wait_running(docker, BASELINE, clock, RUNNING_TIMEOUT)
            wait_answering(docker, BASELINE, clock, ANSWER_TIMEOUT)
            hold_running(docker, BASELINE, clock, baseline_pid, BASELINE_HOLD_SECONDS)
            require_single_start(docker, BASELINE)
        except BootTestError as error:
            raise BootTestError(f"baseline (no DLL): {error}") from None
        say(f"baseline reached RUNNING, answered its query port and ran {BASELINE_HOLD_SECONDS} s without a restart")
        docker("rm", "-f", BASELINE)
        reset_state(setup.root)
        install(setup)
        say("with the DLL: starting from a fresh world")
        start(docker, WITH_DLL, setup, publish=True)
        pid = wait_running(docker, WITH_DLL, clock, RUNNING_TIMEOUT)
        require_single_start(docker, WITH_DLL)
        say("with the DLL: RUNNING")
        check_hooks(lambda: read_log(setup.root), setup.names, clock, HOOKS_TIMEOUT)
        say("livemap.log lists the mandatory hooks: " + ", ".join(setup.names))
        wait_fresh(lambda: tools.fetch(PORT, setup.key), clock, FRESH_TIMEOUT)
        say(f"the map serves fresh data; watching for {SOAK_SECONDS} s")
        hold_running(docker, WITH_DLL, clock, pid, SOAK_SECONDS)
        wait_fresh(lambda: tools.fetch(PORT, setup.key), clock, FINAL_FRESH_TIMEOUT)
        require_single_start(docker, WITH_DLL)
        say(f"boot test passed: no crash or exit for {SOAK_SECONDS} s and the map still serves fresh data")
        return 0
    except BootTestError as error:
        say(annotation(str(error)))
        diagnose(tools)
        return 1
    finally:
        for name in (BASELINE, WITH_DLL):
            docker("rm", "-f", name)


def _load_builds(root):
    try:
        return json.loads((root / DATA_FILE).read_text(encoding=ENCODING))
    except (OSError, ValueError) as error:
        raise BootTestError(f"{DATA_FILE} could not be read as JSON: {type(error).__name__}") from None


def _target(root):
    ids = download_ids(pick_target(_load_builds(root)))
    print(f"boot test target: build {ids['buildid']}")
    github_output(f"{name}={value}" for name, value in ids.items())
    return 0


def _verify(root, server):
    verify_exe(pick_target(_load_builds(root)), server)
    print(f"{EXE_NAME} matches the exe_sha256 recorded in {DATA_FILE}")
    return 0


def _run(root, work, package):
    image = os.environ.get("BOOT_TEST_IMAGE")
    if not image:
        raise BootTestError("BOOT_TEST_IMAGE is not set")
    if not hasattr(os, "getuid"):
        raise BootTestError("the boot test runs on Linux")
    builds = _load_builds(root)
    target = pick_target(builds)
    download_ids(target)
    setup = Setup(
        root=work / "enshrouded",
        package=package,
        target=target,
        names=mandatory_sites(builds, target),
        image=image,
        key=make_key(),
        ids=(os.getuid(), os.getgid()),
    )
    return run_boot_test(setup, Tools(Docker(), Clock(), fetch_state, print))


def main(argv=None, root=None):
    argv = sys.argv[1:] if argv is None else argv
    root = Path.cwd() if root is None else Path(root)
    roots = [os.environ["RUNNER_TEMP"]] if os.environ.get("RUNNER_TEMP") else []
    commands = {
        ("target", 0): lambda: _target(root),
        ("verify-exe", 1): lambda: _verify(root, Path(safe_path(argv[1], roots))),
        ("run", 2): lambda: _run(root, Path(safe_path(argv[1], roots)), Path(safe_path(argv[2], roots))),
    }
    command = commands.get((argv[0], len(argv) - 1)) if argv else None
    if command is None:
        print(USAGE)
        return 2
    try:
        return command()
    except (BootTestError, ValueError) as error:
        print(annotation(str(error)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
