"""File discovery: git-aware, binary-safe, size-capped."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import (Config, CONFIG_FILENAME, DEFAULT_EXCLUDED_DIRS,
                     KEY_FILENAME, MAP_FILENAME)

# The config file holds allowlist policy (org domains, waived values);
# scanning or scrubbing it would rewrite the policy itself.
_ALWAYS_SKIP = {KEY_FILENAME, MAP_FILENAME, CONFIG_FILENAME}


def is_git_repo(root: Path) -> bool:
    return (root / ".git").exists()


def _git_files(root: Path) -> list[Path] | None:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, capture_output=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return [root / p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]


def _walk_files(root: Path) -> list[Path]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDED_DIRS]
        for name in filenames:
            result.append(Path(dirpath) / name)
    return result


def looks_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def iter_scannable(root: Path, config: Config,
                   explicit: list[Path] | None = None) -> list[Path]:
    """Return files to scan, honoring .gitignore, excludes, size and binary skips."""
    if explicit:
        candidates: list[Path] = []
        for p in explicit:
            candidates.extend(_walk_files(p) if p.is_dir() else [p])
    else:
        candidates = _git_files(root) if is_git_repo(root) else None
        if candidates is None:
            candidates = _walk_files(root)

    selected = []
    for path in candidates:
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in _ALWAYS_SKIP:
            continue
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = path.as_posix()
        if config.is_path_excluded(rel):
            continue
        try:
            if path.stat().st_size > config.max_file_size:
                continue
        except OSError:
            continue
        if looks_binary(path):
            continue
        selected.append(path)
    return sorted(selected)
