"""Tests for compat.yaml: the pins it shares with exe-capture.yaml, the artifact check run on bad outputs, and what
no step may do; ctest runs them with pytest."""

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENCODING = "utf-8"
WORKFLOWS = ROOT / ".github" / "workflows"
COMPAT = WORKFLOWS / "compat.yaml"
EXE_CAPTURE = WORKFLOWS / "exe-capture.yaml"
ARTIFACT_STEP = "artifact"
INPUT_EXPRESSION = r"\$\{\{[^}]*\binputs\."
BUILD_ID = "1001"
MANIFEST = "2002"
BASE_LABEL = "900"
GOOD_REPORT = {"result": "easy", "build_id": BUILD_ID, "manifest": MANIFEST, "base": {"label": BASE_LABEL}}
needs_linux_shell = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("bash") is None or shutil.which("jq") is None,
    reason="the step is a bash script for a Linux runner and reads JSON with jq",
)


def workflow():
    return COMPAT.read_text(encoding=ENCODING)


def steps():
    return re.split(r"^ {6}- ", workflow(), flags=re.MULTILINE)[1:]


def run_script(step):
    """The run script of one workflow step, cut out of the workflow text; None when it has no script."""
    block = re.search(r"^ {8}run: \|\n((?: {10}.*\n|\n)+)", step, re.MULTILINE)
    if block:
        return textwrap.dedent(block.group(1))
    inline = re.search(r"^ {8}run: (\S.*)$", step, re.MULTILINE)
    return inline.group(1) if inline else None


def artifact_check():
    step = next((text for text in steps() if re.search(rf"^ {{8}}id: {ARTIFACT_STEP}$", text, re.MULTILINE)), "")
    script = run_script(step)
    assert script, f"no step with id {ARTIFACT_STEP} and a run script"
    return script


def pinned_value(text, name):
    match = re.search(rf"^ +{name}: (\S+)$", text, re.MULTILINE)
    assert match, f"{name} is not set"
    return match.group(1)


def run_artifact_check(tmp_path, report=None, builds=b"{}", stray=None):
    runner_temp = tmp_path / "runner"
    out = runner_temp / "compat-out"
    out.mkdir(parents=True)
    (out / "report.json").write_text(json.dumps(report or GOOD_REPORT), encoding=ENCODING)
    (out / "builds.json").write_bytes(builds)
    if stray:
        (out / stray).write_bytes(b"MZ")
    env = {
        **os.environ,
        "RUNNER_TEMP": str(runner_temp),
        "BUILD_ID": BUILD_ID,
        "MANIFEST_GID": MANIFEST,
        "PREVIOUS_LABEL": BASE_LABEL,
    }
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", artifact_check()],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout


REFUSED = {
    "a stray file": ({"stray": "extra.bin"}, "wrong files for the easy result"),
    "a file over the size limit": ({"builds": json.dumps({"pad": "x" * 300_000}).encode()}, "is larger than"),
    "a file that is not JSON": ({"builds": b"MZ\x90\x00" + bytes(range(256))}, "is not a JSON object"),
    "a report about another build": ({"report": {**GOOD_REPORT, "build_id": "1002"}}, "is not about build"),
    "a report about another manifest": ({"report": {**GOOD_REPORT, "manifest": "2003"}}, "is not about build"),
    "a report against another base": ({"report": {**GOOD_REPORT, "base": {"label": "901"}}}, "is not about build"),
}


@pytest.mark.parametrize("name", ["DEPOTDOWNLOADER_URL", "DEPOTDOWNLOADER_SHA256"])
def test_the_downloader_is_pinned_to_the_same_release_as_the_exe_capture_workflow(name):
    assert pinned_value(workflow(), name) == pinned_value(EXE_CAPTURE.read_text(encoding=ENCODING), name)


@needs_linux_shell
def test_a_good_output_passes_the_artifact_check(tmp_path):
    assert run_artifact_check(tmp_path)[0] == 0


@needs_linux_shell
@pytest.mark.parametrize(("change", "message"), list(REFUSED.values()), ids=list(REFUSED))
def test_the_artifact_check_refuses(tmp_path, change, message):
    code, output = run_artifact_check(tmp_path, **change)
    assert code != 0
    assert message in output


@pytest.mark.parametrize("pattern", [r"actions/cache", r"^\s+cache:"])
def test_nothing_is_cached(pattern):
    assert not re.search(pattern, workflow(), re.MULTILINE)


def test_the_exes_and_the_registry_login_are_removed_even_after_a_failure():
    cleanup = [step for step in steps() if "rm -rf" in step]
    assert len(cleanup) == 1
    assert re.search(r"^ {8}if: always\(\)$", cleanup[0], re.MULTILINE)
    assert "docker logout" in cleanup[0]


def test_no_script_holds_an_input_expression():
    scripts = [run_script(step) for step in steps() if re.search(r"^ {8}run:", step, re.MULTILINE)]
    assert scripts
    assert all(scripts)
    assert not [script for script in scripts if re.search(INPUT_EXPRESSION, script)]
