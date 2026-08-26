"""Deterministic pseudonymization.

Every real value maps to a stable placeholder inside IETF documentation
space, so scrubbed output is internally consistent (the same real IP
becomes the same placeholder in every file, every run) while revealing
nothing. Placeholders are derived with HMAC-SHA256 under a per-project
key, so the mapping cannot be recomputed or guessed without the key.

Security model:
- The key (.opsec-scrub.key) and the mapping (.opsec-scrub.map.json)
  never leave the machine: both are created with mode 0600 and are
  force-added to .gitignore before any scrub runs.
- Secrets are NEVER pseudonymized. A credential is replaced with a
  plain [REDACTED:...] marker that is not derived from the value in
  any way, and the finding tells you to rotate it: scrubbing a working
  tree does not clean git history.

Placeholder spaces (all sanctioned for documentation use):
- IPv4  -> TEST-NET-1/2/3 (RFC 5737)
- IPv6  -> 2001:db8::/32 (RFC 3849)
- hosts -> *.example.com (RFC 2606), each DNS label pseudonymized so
           service names in subdomains do not leak
- MAC   -> locally administered space (02:xx:...)
- users -> user-<token>
- email -> user-<token>@example.com
"""
from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import os
import secrets as _secrets
from pathlib import Path

_V4_POOLS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_V4_POOL_SIZE = 3 * 256
_MAX_PROBES = 4096


class PoolExhausted(RuntimeError):
    pass


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def load_or_create_key(path: Path) -> bytes:
    if path.is_file():
        key = bytes.fromhex(path.read_text().strip())
        if len(key) < 16:
            raise ValueError(f"{path} is too short to be a valid key")
        return key
    key = _secrets.token_bytes(32)
    _write_private(path, key.hex().encode() + b"\n")
    return key


class Pseudonymizer:
    def __init__(self, key: bytes, map_path: Path | None = None):
        self._key = key
        self._map_path = map_path
        self._tables: dict[str, dict[str, str]] = {}
        self._dirty = False
        if map_path and map_path.is_file():
            self._tables = json.loads(map_path.read_text())

    # -- persistence ----------------------------------------------------
    def save(self) -> None:
        if self._map_path and self._dirty:
            _write_private(
                self._map_path,
                json.dumps(self._tables, indent=1, sort_keys=True).encode(),
            )

    # -- core -----------------------------------------------------------
    def _digest(self, kind: str, value: str, salt: int) -> bytes:
        msg = f"{kind}:{salt}:{value}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def _assign(self, kind: str, value: str, generate) -> str:
        table = self._tables.setdefault(kind, {})
        if value in table:
            return table[value]
        used = set(table.values())
        for salt in range(_MAX_PROBES):
            candidate = generate(self._digest(kind, value, salt))
            if candidate not in used:
                table[value] = candidate
                self._dirty = True
                return candidate
        raise PoolExhausted(
            f"placeholder pool exhausted for kind '{kind}' "
            f"({len(used)} values already mapped)")

    # -- generators -----------------------------------------------------
    def ipv4(self, value: str) -> str:
        def gen(d: bytes) -> str:
            idx = int.from_bytes(d[:4], "big") % _V4_POOL_SIZE
            pool = _V4_POOLS[idx // 256]
            return str(pool[idx % 256])
        return self._assign("ipv4", value, gen)

    def ipv6(self, value: str) -> str:
        def gen(d: bytes) -> str:
            groups = [f"{int.from_bytes(d[i:i + 2], 'big'):x}" for i in (0, 2, 4, 6)]
            return "2001:db8:" + ":".join(groups) + "::1"
        return self._assign("ipv6", value, gen)

    def _label(self, label: str) -> str:
        def gen(d: bytes) -> str:
            return "x" + d.hex()[:6]
        return self._assign("label", label.lower(), gen)

    def hostname(self, value: str) -> str:
        """Pseudonymize every DNS label except the TLD; anchor under example.com.

        docs.acme.example maps to xAAAAAA.xBBBBBB.example.com while
        acme.example maps to xBBBBBB.example.com, so parent/child
        relationships between hostnames survive scrubbing.
        """
        labels = [p for p in value.lower().split(".") if p]
        prefix = labels[:-1] if len(labels) >= 2 else labels
        return ".".join(self._label(p) for p in prefix) + ".example.com"

    def username(self, value: str) -> str:
        def gen(d: bytes) -> str:
            return "user-" + d.hex()[:6]
        return self._assign("username", value, gen)

    def email(self, value: str) -> str:
        def gen(d: bytes) -> str:
            return "user-" + d.hex()[:6] + "@example.com"
        return self._assign("email", value, gen)

    def mac(self, value: str) -> str:
        def gen(d: bytes) -> str:
            octets = ["02"] + [f"{b:02x}" for b in d[:5]]
            return ":".join(octets)
        return self._assign("mac", value.lower(), gen)

    def account(self, value: str) -> str:
        def gen(d: bytes) -> str:
            return f"{int.from_bytes(d[:8], 'big') % 10 ** 12:012d}"
        return self._assign("account", value, gen)

    def netid(self, value: str) -> str:
        def gen(d: bytes) -> str:
            return d.hex()[:16]
        return self._assign("netid", value.lower(), gen)

    # -- dispatch -------------------------------------------------------
    def replacement_for(self, kind: str, category: str, value: str) -> str:
        if kind == "secret":
            return f"[REDACTED:{category}]"
        handler = getattr(self, kind, None)
        if handler is None:
            return f"[REDACTED:{category}]"
        return handler(value)
