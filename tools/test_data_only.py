"""Tests for data_only.py with real git repositories and the shipped schema; ctest runs them with pytest."""

import copy
import json
import re
import subprocess
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
CI_WORKFLOW = ".github/workflows/ci-repo.yaml"
CLASSIFY = "classify"
VALIDATE = "validate"
GIT = ("git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false")
README = "README.md"
BASE_FILES = {README: "x\n", DATA: "x\n", CODE: "x\n"}


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
    git(repo, "switch", "-q", "-c", "head")
    head(repo)
    commit_all(repo, "head")
    git(repo, "switch", "-q", "main")
    if base is not None:
        base(repo)
        commit_all(repo, "base moved")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "head")
    return repo


@pytest.fixture
def real():
    return (
        json.loads((ROOT / DATA).read_text(encoding=ENCODING)),
        json.loads((ROOT / SCHEMA).read_text(encoding=ENCODING)),
    )


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        ([DATA], True),
        ([], False),
        ([CODE], False),
        ([DATA, CODE], False),
        ([DATA, SCHEMA], False),
        ([SCHEMA], False),
        ([DATA + ".bak"], False),
        (["Data/builds.json"], False),
        (["./" + DATA], False),
        ([DATA, DATA], False),
    ],
)
def test_only_a_change_to_builds_json_alone_is_data_only(paths, expected):
    assert data_only.is_data_only(paths) is expected


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        ([DATA], True),
        ([SCHEMA], True),
        ([CODE], True),
        (["src/deep/er.h"], True),
        ([BOOT_TEST_TOOL], True),
        ([CI_WORKFLOW], True),
        ([README, "web/index.html", "tools/render_map.py"], False),
        (["source/main.cpp", "database/x.json", "Data/builds.json"], False),
        ([], False),
        ([README, CODE], True),
    ],
)
def test_the_boot_test_runs_for_data_and_source_and_for_its_own_files(paths, expected):
    assert data_only.needs_boot_test(paths) is expected


def test_changed_paths_lists_what_the_pull_request_changes_against_its_base(tmp_path):
    repo = make_merge(tmp_path, touch(DATA, CODE), base=touch(README))
    assert sorted(data_only.changed_paths(repo)) == [DATA, CODE]


def test_changed_paths_keeps_unusual_names_whole(tmp_path):
    odd = "data/odd nameé.txt"
    repo = make_merge(tmp_path, touch(odd))
    assert data_only.changed_paths(repo) == [odd]


def test_a_deleted_file_counts_as_a_change(tmp_path):
    repo = make_merge(tmp_path, lambda r: (r / CODE).unlink())
    assert data_only.changed_paths(repo) == [CODE]


def test_a_rename_lists_both_paths(tmp_path):
    moved = "src/builds.json"

    def rename(repo):
        (repo / "src").mkdir()
        git(repo, "mv", DATA, moved)

    repo = make_merge(tmp_path, rename, files={DATA: "same content " * 40})
    changed = data_only.changed_paths(repo)
    assert sorted(changed) == [DATA, moved]
    assert not data_only.is_data_only(changed)


def test_a_checkout_that_is_not_a_merge_commit_is_refused(tmp_path):
    repo = init_repo(tmp_path, BASE_FILES)
    write(repo, DATA, "two\n")
    commit_all(repo, "two")
    with pytest.raises(DataOnlyError, match="merge commit"):
        data_only.changed_paths(repo)


def test_a_missing_git_checkout_is_an_error(tmp_path):
    with pytest.raises(DataOnlyError, match="git"):
        data_only.changed_paths(tmp_path)


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
    assert run_main([CLASSIFY], repo, tmp_path, monkeypatch) == (0, "data_only=false\nboot_test=true\n")


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
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow, re.MULTILINE | re.DOTALL)
    assert match, f"no {name} job in ci-repo.yaml"
    return match.group(1)


def test_the_data_only_check_runs_only_for_a_pull_request_the_classifier_calls_data_only():
    block = job_block("data-only")
    assert "needs: changes\n" in block
    assert "if: needs.changes.outputs.data_only == 'true'\n" in block
    assert "continue-on-error" not in block
    assert "always()" not in block


def test_the_classifier_job_reads_the_merge_commit_and_exposes_its_answer():
    block = job_block("changes")
    assert "if: github.event_name == 'pull_request'\n" in block
    assert "fetch-depth: 2\n" in block
    assert "\n          ref:" not in block
    assert "id: classify\n" in block
    assert "data_only: ${{ steps.classify.outputs.data_only }}\n" in block
    assert "boot_test: ${{ steps.classify.outputs.boot_test }}\n" in block
