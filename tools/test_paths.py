"""Tests for paths.safe_path: python3 -m unittest discover -s tools -p "test_*.py"."""

import os
import tempfile
import unittest

from paths import safe_path


class SafePathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        os.makedirs(os.path.join(self.root, "inside", "deeper"))
        self.cwd = os.getcwd()
        os.chdir(os.path.join(self.root, "inside"))

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def test_relative_path_in_working_directory_resolves(self):
        self.assertEqual(safe_path("deeper/file.json"), os.path.join(self.root, "inside", "deeper", "file.json"))

    def test_working_directory_itself_is_allowed(self):
        self.assertEqual(safe_path("."), os.path.join(self.root, "inside"))

    def test_parent_of_working_directory_is_refused(self):
        with self.assertRaises(ValueError):
            safe_path("../other.json")

    def test_sibling_with_shared_prefix_is_refused(self):
        os.makedirs(os.path.join(self.root, "inside-other"))
        with self.assertRaises(ValueError):
            safe_path("../inside-other/file.json")

    def test_absolute_path_outside_is_refused(self):
        with self.assertRaises(ValueError):
            safe_path(os.path.join(self.root, "file.json"))

    def test_symlink_leading_outside_is_refused(self):
        os.symlink(self.root, os.path.join(self.root, "inside", "link"))
        with self.assertRaises(ValueError):
            safe_path("link/file.json")

    def test_explicit_root_allows_paths_under_it(self):
        target = os.path.join(self.root, "file.json")
        self.assertEqual(safe_path(target, root=self.root), target)

    def test_explicit_root_refuses_paths_outside_it(self):
        with self.assertRaises(ValueError):
            safe_path(os.path.join(self.root, "file.json"), root=os.path.join(self.root, "inside"))

    def test_filesystem_root_as_root_allows_any_path_on_it(self):
        target = os.path.join(self.root, "file.json")
        self.assertEqual(safe_path(target, root=os.path.abspath(os.sep)), target)

    def test_absent_optional_argument_stays_none(self):
        self.assertIsNone(safe_path(None))


if __name__ == "__main__":
    unittest.main()
