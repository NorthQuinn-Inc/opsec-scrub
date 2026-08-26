"""Command-line interface."""
from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .detectors import scan_text
from .files import iter_scannable
from .findings import Finding, SEV_RANK, SEVERITIES
from .hook import install_hook
from .scrubber import ScrubRefused, build_pseudonymizer, scrub_text

_COLORS = {"low": "\033[36m", "medium": "\033[33m",
           "high": "\033[31m", "critical": "\033[35;1m"}
_RESET = "\033[0m"


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _print_findings(findings: list[Finding], show: bool, color: bool) -> None:
    for f in sorted(findings, key=lambda f: (f.path, f.line_no, f.start)):
        value = f.value if show else f.masked()
        sev = f.severity.upper()
        if color:
            sev = _COLORS[f.severity] + sev + _RESET
        print(f"{f.path}:{f.line_no}: [{sev}] {f.category}  {value}  ({f.message})")


def _summary(findings: list[Finding]) -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]]
    return ", ".join(parts) if parts else "clean"


def _collect(root: Path, config, paths: list[str]) -> list[tuple[Path, str, list[Finding]]]:
    explicit = [Path(p) for p in paths] if paths else None
    results = []
    for path in iter_scannable(root, config, explicit):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
            continue
        rel = _rel(path, root)
        results.append((path, text, scan_text(rel, text, config)))
    return results


def cmd_scan(args) -> int:
    root = Path(args.root).resolve()
    config = load_config(root, Path(args.config) if args.config else None)
    scanned = _collect(root, config, args.paths)
    findings = [f for _, _, fs in scanned for f in fs]

    if args.json:
        payload = [{
            "path": f.path, "line": f.line_no, "col": f.start + 1,
            "category": f.category, "severity": f.severity,
            "value": f.value if args.show else f.masked(),
            "message": f.message,
        } for f in findings]
        print(json.dumps({"version": __version__, "findings": payload,
                          "files_scanned": len(scanned)}, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        _print_findings(findings, args.show, color)
        print(f"\n{len(scanned)} files scanned: {_summary(findings)}")
        if findings and not args.show:
            print("(values masked; use --show to reveal locally)")

    threshold = SEV_RANK[config.fail_on]
    return 1 if any(SEV_RANK[f.severity] >= threshold for f in findings) else 0


def cmd_scrub(args) -> int:
    root = Path(args.root).resolve()
    config = load_config(root, Path(args.config) if args.config else None)
    try:
        ps = build_pseudonymizer(root)
    except ScrubRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    explicit = [Path(p) for p in args.paths] if args.paths else None
    total = 0
    changed_files = 0
    rotate_needed = False
    for path in iter_scannable(root, config, explicit):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
            continue
        rel = _rel(path, root)
        new_text, applied = scrub_text(rel, text, config, ps)
        if new_text == text:
            continue
        changed_files += 1
        total += len(applied)
        rotate_needed |= any(f.kind == "secret" for f in applied)
        if args.write:
            path.write_text(new_text, encoding="utf-8")
            print(f"scrubbed {rel} ({len(applied)} replacements)")
        else:
            diff = difflib.unified_diff(
                text.splitlines(keepends=True), new_text.splitlines(keepends=True),
                fromfile=f"a/{rel}", tofile=f"b/{rel}")
            sys.stdout.writelines(diff)
    ps.save()

    mode = "applied" if args.write else "previewed (dry run; use --write to apply)"
    print(f"\n{total} replacements in {changed_files} files {mode}")
    if rotate_needed:
        print("NOTE: credentials were redacted. Rotate them now; scrubbing the "
              "working tree does not clean git history.")
    return 0


def cmd_install_hook(args) -> int:
    root = Path(args.root).resolve()
    try:
        hook_path = install_hook(root, force=args.force)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"pre-push hook installed at {hook_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="opsec-scrub",
        description="Find and deterministically pseudonymize infrastructure "
                    "leakage before a repo goes public.")
    parser.add_argument("--version", action="version",
                        version=f"opsec-scrub {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("paths", nargs="*",
                        help="files or directories (default: whole repo)")
    common.add_argument("--root", default=".",
                        help="repo root (default: current directory)")
    common.add_argument("--config", help="path to .opsec-scrub.toml")

    p_scan = sub.add_parser("scan", parents=[common],
                            help="report findings; exit 1 if any at/above fail_on")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.add_argument("--show", action="store_true",
                        help="print full matched values instead of masking")
    p_scan.add_argument("--no-color", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_scrub = sub.add_parser("scrub", parents=[common],
                             help="replace findings with deterministic placeholders")
    p_scrub.add_argument("--write", action="store_true",
                         help="apply changes in place (default: unified-diff preview)")
    p_scrub.set_defaults(func=cmd_scrub)

    p_hook = sub.add_parser("install-hook",
                            help="install a pre-push hook that runs 'scan'")
    p_hook.add_argument("--root", default=".")
    p_hook.add_argument("--force", action="store_true",
                        help="replace an existing pre-push hook")
    p_hook.set_defaults(func=cmd_install_hook)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
