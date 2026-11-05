"""Sorts a pull request by the files it changes, and checks data/builds.json against its schema.

Run it from the repository root: `classify` needs the pull request's merge commit checked out with its two parents
and writes data_only=true|false (only data/builds.json changed) and boot_test=true|false (the boot test must run)
to $GITHUB_OUTPUT; `validate` needs jsonschema (tools/requirements-test.txt). ctest runs test_data_only.py.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

DATA_FILE = "data/builds.json"
SCHEMA_FILE = "data/builds.schema.json"
BOOT_TEST_DIRS = ("data/", "src/")
BOOT_TEST_FILES = ("tools/boot_test.py", ".github/workflows/ci-repo.yaml")
USAGE = "usage: data_only.py classify|validate"


class DataOnlyError(Exception):
    pass


def is_data_only(paths):
    return list(paths) == [DATA_FILE]


def needs_boot_test(paths):
    return any(path.startswith(BOOT_TEST_DIRS) or path in BOOT_TEST_FILES for path in paths)


def github_output(lines):
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("".join(line + "\n" for line in lines))


def _git(root, *args):
    try:
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    except OSError as error:
        raise DataOnlyError(f"git {args[0]} could not run: {error}") from error
    if result.returncode != 0:
        raise DataOnlyError(f"git {args[0]} failed")
    return result.stdout


def changed_paths(root):
    parents = _git(root, "rev-list", "--parents", "-n", "1", "HEAD").split()
    if len(parents) != 3:
        raise DataOnlyError("HEAD is not a merge commit; check out the pull request merge ref with fetch-depth 2")
    listing = _git(root, "diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD")
    return [os.fsdecode(name) for name in listing.split(b"\0") if name]


def schema_errors(builds, schema):
    # Imported here so classify runs without the third-party install.
    import jsonschema

    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as error:
        raise DataOnlyError(f"the schema is not a valid schema: {error.message}") from error
    found = jsonschema.Draft202012Validator(schema).iter_errors(builds)
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '(root)'}: {error.message}"
        for error in sorted(found, key=lambda e: [str(part) for part in e.absolute_path])
    ]


def _load(root, name):
    try:
        text = (root / name).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise DataOnlyError(f"{name} could not be read: {error}") from error
    try:
        return json.loads(text)
    except ValueError as error:
        raise DataOnlyError(f"{name} is not JSON: {error}") from error


def validate(root):
    return schema_errors(_load(root, DATA_FILE), _load(root, SCHEMA_FILE))


def annotation(message):
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::error::{escaped}"


def _classify(root):
    paths = changed_paths(root)
    flags = [
        f"data_only={'true' if is_data_only(paths) else 'false'}",
        f"boot_test={'true' if needs_boot_test(paths) else 'false'}",
    ]
    print(*flags, sep="\n")
    github_output(flags)
    return 0


def _validate(root):
    errors = validate(root)
    for error in errors:
        print(annotation(f"{DATA_FILE} {error}"))
    if errors:
        return 1
    print(f"{DATA_FILE} validates against {SCHEMA_FILE}")
    return 0


def main(argv=None, root=None):
    argv = sys.argv[1:] if argv is None else argv
    root = Path.cwd() if root is None else Path(root)
    commands = {"classify": _classify, "validate": _validate}
    if len(argv) != 1 or argv[0] not in commands:
        print(USAGE)
        return 2
    try:
        return commands[argv[0]](root)
    except DataOnlyError as error:
        print(annotation(str(error)))
        return 1


if __name__ == "__main__":
    sys.exit(main())
