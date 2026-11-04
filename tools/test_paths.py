"""Tests for paths.safe_path; ctest runs them as `python -m pytest tools/test_paths.py`."""

import os

import pytest
from paths import safe_path


@pytest.fixture
def tree(tmp_path, monkeypatch):
    root = os.path.realpath(tmp_path)
    os.makedirs(os.path.join(root, "inside", "deeper"))
    monkeypatch.chdir(os.path.join(root, "inside"))
    return root


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


def test_explicit_root_allows_paths_under_it(tree):
    target = os.path.join(tree, "file.json")
    assert safe_path(target, root=tree) == target


def test_explicit_root_refuses_paths_outside_it(tree):
    with pytest.raises(ValueError, match="outside"):
        safe_path(os.path.join(tree, "file.json"), root=os.path.join(tree, "inside"))


def test_filesystem_root_as_root_allows_any_path_on_it(tree):
    target = os.path.join(tree, "file.json")
    assert safe_path(target, root=os.path.abspath(os.sep)) == target


def test_absent_optional_argument_stays_none(tree):
    assert safe_path(None) is None
