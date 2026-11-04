"""Resolve path arguments and refuse one outside the working directory and the --root folders."""

import os


def safe_path(path, roots=()):
    if path is None:
        return None
    resolved = os.path.realpath(path)
    for base in (os.path.realpath(b) for b in (os.getcwd(), *roots)):
        # A filesystem root (/ or C:\) already ends in the separator.
        prefix = base if base.endswith(os.sep) else base + os.sep
        if resolved == base or resolved.startswith(prefix):
            return resolved
    raise ValueError(f"{path} is outside the working directory and every --root")


def add_root_option(ap):
    ap.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help="a folder path arguments may be inside, besides the working directory (repeatable)",
    )


def checked(ap, path, roots):
    try:
        resolved = safe_path(path, roots)
    except ValueError as e:
        ap.error(str(e))
    return resolved
