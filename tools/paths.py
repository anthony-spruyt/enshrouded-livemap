"""Resolve a path argument and refuse one that leaves the working directory (or an explicit root)."""

import os


def safe_path(path, root=None):
    if path is None:
        return None
    base = os.path.realpath(root if root is not None else os.getcwd())
    resolved = os.path.realpath(path)
    # A filesystem root (/ or C:\) already ends in the separator.
    prefix = base if base.endswith(os.sep) else base + os.sep
    if resolved == base or resolved.startswith(prefix):
        return resolved
    raise ValueError(f"{path} is outside {base}")
