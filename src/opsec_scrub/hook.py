"""Pre-push hook installer."""
from __future__ import annotations

import os
import stat
from pathlib import Path

HOOK_BODY = """#!/bin/sh
# Installed by opsec-scrub. Blocks a push when the working tree
# contains infrastructure leakage or credentials.
opsec-scrub scan
status=$?
if [ "$status" -ne 0 ]; then
  echo ""
  echo "push blocked by opsec-scrub: fix the findings, waive them"
  echo "(scrub:ok / .opsec-scrub.toml), or run 'opsec-scrub scrub --write'."
fi
exit "$status"
"""


def install_hook(root: Path, force: bool = False) -> Path:
    hooks_dir = root / ".git" / "hooks"
    if not hooks_dir.is_dir():
        raise RuntimeError("not a git repository (no .git/hooks directory)")
    hook_path = hooks_dir / "pre-push"
    if hook_path.exists() and not force:
        raise RuntimeError(
            f"{hook_path} already exists; re-run with --force to replace it")
    hook_path.write_text(HOOK_BODY)
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path
