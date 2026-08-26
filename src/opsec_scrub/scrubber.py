"""Scrub engine: apply deterministic replacements to file text."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .config import Config, KEY_FILENAME, MAP_FILENAME
from .detectors import scan_text
from .findings import Finding
from .pseudonym import Pseudonymizer, load_or_create_key

_RE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
    r".*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)


class ScrubRefused(RuntimeError):
    pass


def _tracked_by_git(root: Path, name: str) -> bool:
    try:
        out = subprocess.run(["git", "ls-files", "--", name],
                             cwd=root, capture_output=True, check=True)
        return bool(out.stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        return False


def ensure_local_only(root: Path) -> None:
    """Guarantee key and map can never be committed.

    Refuses to scrub if either file is already tracked by git, and
    appends both to .gitignore otherwise.
    """
    for name in (KEY_FILENAME, MAP_FILENAME):
        if _tracked_by_git(root, name):
            raise ScrubRefused(
                f"{name} is tracked by git. Untrack it (git rm --cached {name}) "
                "and clean history before scrubbing; this file must never be committed.")
    gitignore = root / ".gitignore"
    existing = gitignore.read_text() if gitignore.is_file() else ""
    lines = {ln.strip() for ln in existing.splitlines()}
    missing = [n for n in (KEY_FILENAME, MAP_FILENAME) if n not in lines]
    if missing:
        block = existing
        if block and not block.endswith("\n"):
            block += "\n"
        block += "# opsec-scrub local state: never commit\n"
        block += "".join(n + "\n" for n in missing)
        gitignore.write_text(block)


def build_pseudonymizer(root: Path) -> Pseudonymizer:
    ensure_local_only(root)
    key = load_or_create_key(root / KEY_FILENAME)
    return Pseudonymizer(key, root / MAP_FILENAME)


def scrub_text(path: str, text: str, config: Config,
               ps: Pseudonymizer) -> tuple[str, list[Finding]]:
    """Return (new_text, applied_findings)."""
    # Private key blocks span lines; collapse them first so no key
    # material survives a scrub even outside the header line.
    text = _RE_KEY_BLOCK.sub("[REDACTED:secret-private-key]", text)

    findings = scan_text(path, text, config)
    if not findings:
        return text, []

    lines = text.split("\n")
    for f in findings:
        f.replacement = ps.replacement_for(f.kind, f.category, f.value)
    # Apply right-to-left within each line so spans stay valid.
    for f in sorted(findings, key=lambda f: (f.line_no, -f.start)):
        line = lines[f.line_no - 1]
        lines[f.line_no - 1] = line[:f.start] + f.replacement + line[f.end:]
    return "\n".join(lines), findings
