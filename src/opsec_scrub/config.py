"""Configuration loading (.opsec-scrub.toml) and allowlist logic."""
from __future__ import annotations

import fnmatch
import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILENAME = ".opsec-scrub.toml"
KEY_FILENAME = ".opsec-scrub.key"
MAP_FILENAME = ".opsec-scrub.map.json"

DEFAULT_EXCLUDED_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
    "build", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
}
DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB


@dataclass
class Config:
    root: Path
    org_domains: list[str] = field(default_factory=list)
    disabled_checks: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    fail_on: str = "low"
    allow_ips: set[str] = field(default_factory=set)
    allow_cidrs: list = field(default_factory=list)
    allow_domains: list[str] = field(default_factory=list)
    allow_emails: set[str] = field(default_factory=set)
    allow_values: set[str] = field(default_factory=set)

    # ------------------------------------------------------------------
    def is_check_disabled(self, category: str) -> bool:
        return any(category == d or category.startswith(d.rstrip("*"))
                   for d in self.disabled_checks)

    def is_allowed(self, kind: str, value: str) -> bool:
        if value in self.allow_values:
            return True
        if kind in ("ipv4", "ipv6"):
            if value in self.allow_ips:
                return True
            try:
                addr = ipaddress.ip_address(value)
                return any(addr in net for net in self.allow_cidrs)
            except ValueError:
                return False
        if kind == "hostname":
            low = value.lower()
            return any(low == d or low.endswith("." + d)
                       for d in self.allow_domains)
        if kind == "email":
            return value.lower() in self.allow_emails
        return False

    def is_path_excluded(self, rel_posix: str) -> bool:
        for pattern in self.exclude_globs:
            if fnmatch.fnmatch(rel_posix, pattern):
                return True
            # "tests/**" should also match files directly under "tests/"
            if pattern.endswith("/**") and rel_posix.startswith(pattern[:-2]):
                return True
        return False


def load_config(root: Path, explicit: Path | None = None) -> Config:
    cfg = Config(root=root)
    path = explicit if explicit else root / CONFIG_FILENAME
    if not path.is_file():
        return cfg
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    cfg.org_domains = [d.lower().lstrip(".") for d in data.get("org_domains", [])]
    cfg.disabled_checks = list(data.get("disable", []))
    cfg.exclude_globs = list(data.get("exclude", []))
    cfg.max_file_size = int(data.get("max_file_size", DEFAULT_MAX_FILE_SIZE))
    cfg.fail_on = str(data.get("fail_on", "low"))

    allow = data.get("allow", {})
    cfg.allow_ips = set(allow.get("ips", []))
    cfg.allow_cidrs = [ipaddress.ip_network(c, strict=False)
                       for c in allow.get("cidrs", [])]
    cfg.allow_domains = [d.lower().lstrip(".") for d in allow.get("domains", [])]
    cfg.allow_emails = {e.lower() for e in allow.get("emails", [])}
    cfg.allow_values = set(allow.get("values", []))
    return cfg
