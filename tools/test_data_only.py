"""Tests for data_only.py with real git repositories and the shipped schema; ctest runs them with pytest."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import data_only
import pytest
from data_only import DataOnlyError

ROOT = Path(__file__).resolve().parents[1]
ENCODING = "utf-8"
DATA = data_only.DATA_FILE
SCHEMA = data_only.SCHEMA_FILE
CODE = "src/main.cpp"
BOOT_TEST_TOOL = "tools/boot_test.py"
CLASSIFIER = "tools/data_only.py"
CI_WORKFLOW = ".github/workflows/ci-repo.yaml"
CLASSIFY = "classify"
VALIDATE = "validate"
COUNTS_AS_CODE = "data_only=false\nboot_test=true\n"
GIT = ("git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false")
README = "README.md"
BASE_FILES = {README: "x\n", DATA: "x\n", CODE: "x\n"}
PR_BRANCH = "topic"


def git(repo, *args):
    subprocess.run([*GIT, *args], cwd=repo, capture_output=True, text=True, check=True)


def write(repo, name, text):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=ENCODING)


def commit_all(repo, message):
    git(repo, "add", "--all")
    git(repo, "commit", "-q", "-m", message)


def init_repo(tmp_path, files):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for name, text in files.items():
        write(repo, name, text)
    commit_all(repo, "base")
    return repo


def touch(*names):
    def edit(repo):
        for name in names:
            write(repo, name, "changed\n")

    return edit


def make_merge(tmp_path, head, base=None, files=None):
    """The merge commit GitHub checks out for a pull request: the base branch first, the head second."""
    repo = init_repo(tmp_path, BASE_FILES if files is None else files)
    git(repo, "switch", "-q", "-c", PR_BRANCH)
    head(repo)
    commit_all(repo, "head")
    git(repo, "switch", "-q", "main")
    if base is not None:
        base(repo)
        commit_all(repo, "base moved")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", PR_BRANCH)
    return repo


@pytest.fixture
def real():
    return (
        json.loads((ROOT / DATA).read_text(encoding=ENCODING)),
        json.loads((ROOT / SCHEMA).read_text(encoding=ENCODING)),
    )


def edit(path, status="M", old="100644", new="100644"):
    return data_only.Change(path, status, old, new)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ([edit(DATA)], True),
        ([], False),
        ([edit(CODE)], False),
        ([edit(DATA), edit(CODE)], False),
        ([edit(DATA), edit(SCHEMA)], False),
        ([edit(SCHEMA)], False),
        ([edit(DATA + ".bak")], False),
        ([edit("Data/builds.json")], False),
        ([edit("./" + DATA)], False),
        ([edit(DATA), edit(DATA)], False),
        ([edit(DATA, new="100755")], False),
        ([edit(DATA, "T", "100644", "120000")], False),
        ([edit(DATA, "M", "120000", "120000")], False),
        ([edit(DATA, "A", "000000", "100644")], False),
        ([edit(DATA, "D", "100644", "000000")], False),
    ],
)
def test_only_a_plain_edit_of_builds_json_alone_is_data_only(changes, expected):
    assert data_only.is_data_only(changes) is expected


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        ([DATA], True),
        ([SCHEMA], True),
        ([CODE], True),
        (["src/deep/er.h"], True),
        ([BOOT_TEST_TOOL], True),
        ([CI_WORKFLOW], True),
        ([CLASSIFIER], True),
        (["CMakeLists.txt"], True),
        (["cmake/builds.cmake"], True),
        ([README, "web/index.html", "tools/render_map.py"], False),
        (["source/main.cpp", "database/x.json", "Data/builds.json"], False),
        (["cmakelists.txt", "cmake.txt", "xcmake/a.cmake"], False),
        ([], False),
        ([README, CODE], True),
    ],
)
def test_the_boot_test_runs_for_data_and_source_and_for_what_builds_or_runs_it(paths, expected):
    assert data_only.needs_boot_test(paths) is expected


def paths_of(changes):
    return [change.path for change in changes]


def test_a_branch_made_for_a_test_cannot_resolve_to_a_file_of_the_git_directory(tmp_path):
    repo = make_merge(tmp_path, touch(DATA))
    in_git_directory = {entry.name.lower() for entry in (repo / ".git").iterdir()}
    branches = [entry.name for entry in (repo / ".git" / "refs" / "heads").iterdir()]
    assert len(branches) == 2
    assert not [name for name in branches if name.lower() in in_git_directory]


def test_changed_files_lists_what_the_pull_request_changes_against_its_base(tmp_path):
    repo = make_merge(tmp_path, touch(DATA, CODE), base=touch(README))
    changes = data_only.changed_files(repo)
    assert sorted(paths_of(changes)) == [DATA, CODE]
    assert {change[1:] for change in changes} == {("M", "100644", "100644")}


def test_changed_files_keeps_unusual_names_whole(tmp_path):
    odd = "data/odd nameé.txt"
    repo = make_merge(tmp_path, touch(odd))
    assert paths_of(data_only.changed_files(repo)) == [odd]


def test_a_deleted_file_counts_as_a_change(tmp_path):
    repo = make_merge(tmp_path, lambda r: (r / CODE).unlink())
    assert data_only.changed_files(repo) == [edit(CODE, "D", "100644", "000000")]


def test_a_rename_lists_both_paths(tmp_path):
    moved = "src/builds.json"

    def rename(repo):
        (repo / "src").mkdir()
        git(repo, "mv", DATA, moved)

    repo = make_merge(tmp_path, rename, files={DATA: "same content " * 40})
    changed = data_only.changed_files(repo)
    assert sorted(paths_of(changed)) == [DATA, moved]
    assert not data_only.is_data_only(changed)


def test_a_plain_edit_of_builds_json_is_data_only(tmp_path):
    repo = make_merge(tmp_path, touch(DATA))
    assert data_only.is_data_only(data_only.changed_files(repo))


def test_a_mode_change_of_builds_json_is_not_data_only(tmp_path):
    def make_executable(repo):
        git(repo, "update-index", "--chmod=+x", DATA)
        (repo / DATA).chmod(0o755)

    repo = make_merge(tmp_path, make_executable)
    changes = data_only.changed_files(repo)
    assert paths_of(changes) == [DATA]
    assert not data_only.is_data_only(changes)


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need a privilege on Windows")
def test_a_symbolic_link_in_place_of_builds_json_is_not_data_only(tmp_path):
    def link(repo):
        (repo / DATA).unlink()
        os.symlink("../" + README, repo / DATA)

    repo = make_merge(tmp_path, link)
    changes = data_only.changed_files(repo)
    assert paths_of(changes) == [DATA]
    assert not data_only.is_data_only(changes)


def test_a_checkout_that_is_not_a_merge_commit_is_refused(tmp_path):
    repo = init_repo(tmp_path, BASE_FILES)
    write(repo, DATA, "two\n")
    commit_all(repo, "two")
    with pytest.raises(DataOnlyError, match="merge commit"):
        data_only.changed_files(repo)


def test_a_missing_git_checkout_is_an_error(tmp_path):
    with pytest.raises(DataOnlyError, match="git"):
        data_only.changed_files(tmp_path)


def test_the_shipped_builds_file_validates_against_the_shipped_schema(real):
    builds, schema = real
    assert data_only.schema_errors(builds, schema) == []


def first_build(builds):
    return builds["builds"][0]


def mutated(builds, edit):
    copied = copy.deepcopy(builds)
    edit(copied)
    return copied


@pytest.mark.parametrize(
    "edit",
    [
        lambda b: b.pop("builds"),
        lambda b: first_build(b).update(surprise=1),
        lambda b: first_build(b).update(size_of_image="0X1dcf000"),
        lambda b: first_build(b)["expected"].update(join_line="0x10"),
        lambda b: first_build(b)["steam"].pop("manifest"),
        lambda b: b["sigsets"]["launch"].pop(0),
    ],
    ids=["no builds", "unknown key", "hex shape", "join_line expected", "steam block", "mandatory site gone"],
)
def test_a_file_that_breaks_the_schema_is_reported(real, edit):
    builds, schema = real
    assert data_only.schema_errors(mutated(builds, edit), schema)


def set_buildid(builds, text):
    first_build(builds)["buildids"][0] = text


SHAPES = {
    "buildid": (set_buildid, "26430253"),
    "label": (lambda b, text: first_build(b).update(label=text), "abc"),
    "depot": (lambda b, text: first_build(b)["steam"].update(depot=text), "2278521"),
    "site": (lambda b, text: b["sigsets"]["launch"][0].update(site=text), "player_table"),
}


@pytest.mark.parametrize("char", ["\n", "\r", "\t", "\x00", "\x1b", "\x7f", "\x85", "\u2028"])
@pytest.mark.parametrize("field", SHAPES)
def test_a_non_printing_character_is_reported_even_where_a_pattern_passes_it(real, field, char):
    builds, schema = real
    edit, valid = SHAPES[field]
    assert data_only.schema_errors(mutated(builds, lambda b: edit(b, valid)), schema) == []
    errors = data_only.schema_errors(mutated(builds, lambda b: edit(b, valid + char)), schema)
    assert any("non-printing character" in error for error in errors)


ALIAS_BUILD_ID = "9000000001"
ALIAS_MANIFEST = "9000000002"


def alias_last_row(builds, manifest=ALIAS_MANIFEST):
    row = builds["builds"][-1]
    row["buildids"].append(ALIAS_BUILD_ID)
    row["steam"]["manifest"] = manifest


def test_a_known_build_added_as_an_alias_with_its_manifest_validates(real):
    builds, schema = real
    assert data_only.schema_errors(mutated(builds, alias_last_row), schema) == []


@pytest.mark.parametrize("manifest", ["0", "12x", "", "1" * 21, 7], ids=repr)
def test_an_alias_with_a_manifest_that_is_not_a_steam_id_is_reported(real, manifest):
    builds, schema = real
    assert data_only.schema_errors(mutated(builds, lambda b: alias_last_row(b, manifest)), schema)


def test_a_key_with_a_newline_is_reported_without_a_raw_newline(real):
    builds, schema = real
    errors = data_only.schema_errors(mutated(builds, lambda b: first_build(b).update({"x\ny": 1})), schema)
    assert any("non-printing" in error for error in errors)
    assert not any("\n" in error for error in errors)


def test_errors_name_where_the_file_is_wrong(real):
    builds, schema = real
    errors = data_only.schema_errors(mutated(builds, lambda b: first_build(b).update(surprise=1)), schema)
    assert any("builds/0" in error and "surprise" in error for error in errors)


def test_a_schema_that_is_itself_invalid_is_an_error(real):
    builds, schema = real
    with pytest.raises(DataOnlyError, match="schema"):
        data_only.schema_errors(builds, {**schema, "type": "not-a-type"})


def copy_shipped(root, *names):
    for name in names:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes((ROOT / name).read_bytes())


def test_validate_reads_both_files_from_the_root(tmp_path):
    copy_shipped(tmp_path, DATA, SCHEMA)
    assert data_only.validate(tmp_path) == []


@pytest.mark.parametrize("text", ["{", "", "[]\x00"])
def test_validate_rejects_a_file_that_is_not_json(tmp_path, text):
    copy_shipped(tmp_path, SCHEMA)
    write(tmp_path, DATA, text)
    with pytest.raises(DataOnlyError, match="not JSON"):
        data_only.validate(tmp_path)


def test_validate_rejects_a_missing_file(tmp_path):
    with pytest.raises(DataOnlyError, match="could not be read"):
        data_only.validate(tmp_path)


def run_main(args, repo, tmp_path, monkeypatch):
    output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    code = data_only.main(args, repo)
    return code, output.read_text(encoding=ENCODING) if output.exists() else ""


def test_classify_reports_true_for_a_data_only_change(tmp_path, monkeypatch, capsys):
    repo = make_merge(tmp_path, touch(DATA))
    assert run_main([CLASSIFY], repo, tmp_path, monkeypatch) == (0, "data_only=true\nboot_test=true\n")
    assert "data_only=true" in capsys.readouterr().out


def test_classify_reports_false_for_a_code_change_and_still_succeeds(tmp_path, monkeypatch):
    repo = make_merge(tmp_path, touch(DATA, CODE))
    assert run_main([CLASSIFY], repo, tmp_path, monkeypatch) == (0, COUNTS_AS_CODE)


def test_classify_reports_no_boot_test_for_a_change_outside_data_and_source(tmp_path, monkeypatch):
    repo = make_merge(tmp_path, touch(README))
    assert run_main([CLASSIFY], repo, tmp_path, monkeypatch) == (0, "data_only=false\nboot_test=false\n")


def test_classify_fails_when_it_cannot_tell(tmp_path, monkeypatch, capsys):
    code, output = run_main([CLASSIFY], tmp_path, tmp_path, monkeypatch)
    assert code == 1
    assert output == ""
    assert "::error::" in capsys.readouterr().out


def test_validate_command_passes_the_shipped_files(tmp_path, monkeypatch, capsys):
    assert run_main([VALIDATE], ROOT, tmp_path, monkeypatch)[0] == 0
    assert "validates" in capsys.readouterr().out


def test_validate_command_fails_on_a_broken_file(tmp_path, monkeypatch, capsys):
    copy_shipped(tmp_path, SCHEMA)
    write(tmp_path, DATA, "{}")
    assert run_main([VALIDATE], tmp_path, tmp_path, monkeypatch)[0] == 1
    assert "::error::" in capsys.readouterr().out


def test_an_annotation_cannot_start_a_second_workflow_command():
    line = data_only.annotation("bad\n::add-mask::x\r100%")
    assert "\n" not in line
    assert "\r" not in line
    assert line == "::error::bad%0A::add-mask::x%0D100%25"


def test_an_unknown_command_is_a_usage_error(tmp_path, monkeypatch, capsys):
    assert run_main(["frobnicate"], tmp_path, tmp_path, monkeypatch)[0] == 2
    assert "usage" in capsys.readouterr().out


def job_block(name):
    workflow = (ROOT / ".github" / "workflows" / "ci-repo.yaml").read_text(encoding=ENCODING)
    header = re.search(rf"^ {{2}}{re.escape(name)}:\n", workflow, re.MULTILINE)
    assert header, f"no {name} job in ci-repo.yaml"
    body = workflow[header.end() :]
    next_header = re.search(r"^ {2}[\w-]+:\n", body, re.MULTILINE)
    return body[: next_header.start()] if next_header else body


def step_script(job, step_id):
    """The run script of one workflow step, cut out of the workflow text."""
    steps = re.split(r"^ {6}- ", job_block(job), flags=re.MULTILINE)[1:]
    step = next((text for text in steps if re.search(rf"^ {{8}}id: {step_id}$", text, re.MULTILINE)), "")
    block = re.search(r"^ {8}run: \|\n((?: {10}.*\n|\n)+)", step, re.MULTILINE)
    assert block, f"no run script on step {step_id} of job {job}"
    return textwrap.dedent(block.group(1))


HEAD_CLASSIFIER = (
    "import os\n"
    'with open(os.environ["GITHUB_OUTPUT"], "a") as out:\n'
    '    out.write("data_only=true\\nboot_test=false\\n")\n'
)
CLASSIFY_STEP = ("changes", "classify")
needs_bash_and_posix = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None, reason="the step is a bash script for a Linux runner"
)


def run_step(script, repo, tmp_path):
    runner_temp = tmp_path / "runner"
    shim = runner_temp / "bin"
    shim.mkdir(parents=True)
    (shim / "python3").symlink_to(sys.executable)
    env = {**os.environ, "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}"}
    env.update(RUNNER_TEMP=str(runner_temp), GITHUB_OUTPUT=str(tmp_path / "github-output"))
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = Path(env["GITHUB_OUTPUT"])
    return result.returncode, output.read_text(encoding=ENCODING) if output.exists() else ""


def classify_pull_request(tmp_path, head, base_files):
    repo = make_merge(tmp_path, head, files=base_files)
    return run_step(step_script(*CLASSIFY_STEP), repo, tmp_path)


WITH_CLASSIFIER = {**BASE_FILES, CLASSIFIER: (ROOT / CLASSIFIER).read_text(encoding=ENCODING)}


@needs_bash_and_posix
def test_the_base_commits_classifier_sorts_a_data_only_pull_request(tmp_path):
    assert classify_pull_request(tmp_path, touch(DATA), WITH_CLASSIFIER) == (0, "data_only=true\nboot_test=true\n")


@needs_bash_and_posix
def test_the_step_runs_the_base_commits_classifier_when_the_pull_request_changes_it(tmp_path):
    def change_classifier_and_code(repo):
        write(repo, CLASSIFIER, HEAD_CLASSIFIER)
        write(repo, CODE, "changed\n")

    assert classify_pull_request(tmp_path, change_classifier_and_code, WITH_CLASSIFIER) == (0, COUNTS_AS_CODE)


@needs_bash_and_posix
def test_a_pull_request_that_adds_the_classifier_is_code_and_gets_the_boot_test(tmp_path):
    outcome = classify_pull_request(tmp_path, lambda r: write(r, CLASSIFIER, HEAD_CLASSIFIER), BASE_FILES)
    assert outcome == (0, COUNTS_AS_CODE)
