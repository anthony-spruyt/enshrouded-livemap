"""Tests for paths.py and the --root option of the tools; ctest runs them as `python -m pytest tools/test_paths.py`."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

import pytest
from paths import add_root_option, check_paths, safe_path

TOOLS = Path(__file__).resolve().parent


@pytest.fixture
def tree(tmp_path, monkeypatch):
    root = os.path.realpath(tmp_path)
    os.makedirs(os.path.join(root, "inside", "deeper"))
    monkeypatch.chdir(os.path.join(root, "inside"))
    return root


def make_parser(*argv):
    ap = argparse.ArgumentParser(prog="tool")
    ap.add_argument("--out")
    add_root_option(ap)
    return ap, ap.parse_args(argv)


def run_tool(script, *args):
    return subprocess.run(
        [sys.executable, "-B", str(TOOLS / script), *args], capture_output=True, text=True, check=False
    )


def test_relative_path_in_working_directory_resolves(tree):
    assert safe_path("deeper/file.json") == os.path.join(tree, "inside", "deeper", "file.json")


def test_working_directory_itself_is_allowed(tree):
    assert safe_path(".") == os.path.join(tree, "inside")


def test_parent_of_working_directory_is_refused(tree):
    with pytest.raises(ValueError, match="outside"):
        safe_path("../other.json")


def test_sibling_with_shared_prefix_is_refused(tree):
    os.makedirs(os.path.join(tree, "inside-other"))
    with pytest.raises(ValueError, match="outside"):
        safe_path("../inside-other/file.json")


def test_absolute_path_outside_is_refused(tree):
    with pytest.raises(ValueError, match="outside"):
        safe_path(os.path.join(tree, "file.json"))


def test_symlink_leading_outside_is_refused(tree):
    try:
        os.symlink(tree, os.path.join(tree, "inside", "link"), target_is_directory=True)
    except OSError:
        pytest.skip("this account may not create symlinks")
    with pytest.raises(ValueError, match="outside"):
        safe_path("link/file.json")


def test_root_allows_paths_under_it(tree):
    target = os.path.join(tree, "file.json")
    assert safe_path(target, roots=[tree]) == target


def test_path_under_any_of_several_roots_is_allowed(tree):
    first, second = os.path.join(tree, "first"), os.path.join(tree, "second")
    target = os.path.join(second, "file.json")
    assert safe_path(target, roots=[first, second]) == target


def test_path_outside_every_root_is_refused(tree):
    first, second = os.path.join(tree, "first"), os.path.join(tree, "second")
    with pytest.raises(ValueError, match="outside"):
        safe_path(os.path.join(tree, "third", "file.json"), roots=[first, second])


def test_working_directory_stays_allowed_with_a_root(tree):
    target = os.path.join(tree, "inside", "file.json")
    assert safe_path(target, roots=[os.path.join(tree, "elsewhere")]) == target


def test_filesystem_root_as_root_allows_any_path_on_it(tree):
    target = os.path.join(tree, "file.json")
    assert safe_path(target, roots=[os.path.abspath(os.sep)]) == target


def test_absent_optional_argument_stays_none(tree):
    assert safe_path(None) is None


def test_root_option_is_repeatable_and_defaults_to_empty():
    assert make_parser()[1].root == []
    assert make_parser("--root", "a", "--root", "b")[1].root == ["a", "b"]


def test_check_paths_resolves_the_named_arguments(tree):
    ap, args = make_parser("--out", "deeper/file.json")
    check_paths(ap, args, "out")
    assert args.out == os.path.join(tree, "inside", "deeper", "file.json")


def test_check_paths_accepts_a_path_under_a_given_root(tree):
    target = os.path.join(tree, "elsewhere", "file.json")
    ap, args = make_parser("--out", target, "--root", os.path.join(tree, "elsewhere"))
    check_paths(ap, args, "out")
    assert args.out == target


def test_check_paths_ends_a_refused_path_with_a_usage_error(tree, capsys):
    ap, args = make_parser("--out", os.path.join(tree, "file.json"))
    with pytest.raises(SystemExit) as exit_info:
        check_paths(ap, args, "out")
    assert exit_info.value.code == 2
    assert "outside" in capsys.readouterr().err


# The tools whose imports are the standard library only, so the test needs no extra packages.
REFUSED_CALLS = [
    ("extract_items.py", ["--server", "{outside}", "--out", "out.h"]),
    ("extract_pois.py", ["--server", "{outside}", "--out", "out.json"]),
    ("research/framedump.py", ["{outside}", "ids.json", "0"]),
    ("research/pathfind.py", ["{outside}", "0", "0-1"]),
    ("research/setdiff.py", ["{outside}", "{outside}", "0"]),
]


@pytest.mark.parametrize(("script", "args"), REFUSED_CALLS)
def test_tool_refuses_a_path_outside_with_a_usage_error(tree, script, args):
    outside = os.path.join(tree, "file.bin")
    result = run_tool(script, *(a.format(outside=outside) for a in args))
    assert result.returncode == 2
    assert "outside" in result.stderr
    assert "Traceback" not in result.stderr


def framedump_call(tree, *roots):
    first, second = os.path.join(tree, "first"), os.path.join(tree, "second")
    os.makedirs(first)
    os.makedirs(second)
    frames = Path(first, "frames.bin")
    frames.write_bytes(b"")
    ids = Path(second, "ids.json")
    ids.write_text('{"ids": {}}', encoding="utf-8")
    options = [a for root in roots for a in ("--root", os.path.join(tree, root))]
    return run_tool("research/framedump.py", str(frames), str(ids), "0", *options)


def test_tool_accepts_paths_under_each_of_several_roots(tree):
    result = framedump_call(tree, "first", "second")
    assert result.returncode == 1
    assert result.stderr.strip() == "address not in any frame"


def test_tool_refuses_a_path_under_none_of_the_given_roots(tree):
    result = framedump_call(tree, "first")
    assert result.returncode == 2
    assert "ids.json" in result.stderr
