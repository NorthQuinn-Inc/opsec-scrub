"""Finding model and severity handling."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """One detected item at a specific location in a file."""

    path: str
    line_no: int  # 1-based
    start: int    # 0-based column offset within the line
    end: int      # exclusive
    category: str  # e.g. "ipv4-private", "secret-aws-access-key"
    kind: str      # scrub family: ipv4, ipv6, hostname, username, email, mac, secret, account, netid
    value: str     # the exact matched text (never printed unmasked by default)
    severity: str
    message: str
    replacement: str | None = field(default=None)

    def masked(self) -> str:
        return mask_value(self.value)


def mask_value(value: str) -> str:
    """Mask a matched value for safe display in terminals and CI logs.

    Scanner output is itself a leak vector (CI logs are often widely
    readable), so by default we never echo the full matched value.
    """
    n = len(value)
    if n <= 6:
        return "*" * n
    keep = 2 if n < 12 else 3
    return value[:keep] + "*" * min(n - 2 * keep, 12) + value[-keep:]
