"""Detection engine.

Line-oriented detectors for infrastructure leakage and credentials.
Every candidate match is validated (e.g. via the ipaddress module)
before it becomes a finding, and findings on a line carrying the
inline waiver comment ``scrub:ok`` are suppressed.

Design notes, security first:
- Values placed in IETF documentation space are allowed by default
  (TEST-NET-1/2/3, 2001:db8::/32, example.com, locally administered
  MACs). This is what makes scrub output scan-clean by construction.
- Detectors favor precision over recall for noisy classes (generic
  hostnames are only flagged for configured org domains and known
  internal TLDs), and favor recall for high-cost classes (any
  private, CGNAT, or public IP is flagged).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Callable, Iterable

from .findings import Finding, SEV_RANK

INLINE_WAIVER = "scrub:ok"

# ---------------------------------------------------------------------------
# IP address helpers
# ---------------------------------------------------------------------------

_DOC_NETS_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")  # scrub:ok range definition
_DOC_NET_V6 = ipaddress.ip_network("2001:db8::/32")

# Trailing lookahead permits a sentence-ending dot ("... at 192.0.2.5.")
# but rejects a longer dotted chain ("1.2.3.4.5" is a version, not an IP).
_RE_IPV4 = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?!\w)(?!\.\d)")
# Candidate first, then strict validation through the ipaddress module.
_RE_IPV6 = re.compile(
    r"(?<![\w:.])([0-9A-Fa-f:]*[0-9A-Fa-f]:[0-9A-Fa-f:]+|::)(?![\w:])"
)
_RE_MAC = re.compile(
    r"(?<![\w:.-])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?![\w:.-])"
)


def _classify_v4(addr: ipaddress.IPv4Address):
    if any(addr in net for net in _DOC_NETS_V4):
        return None  # sanctioned documentation space
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    if addr == ipaddress.IPv4Address("255.255.255.255"):
        return None
    if addr in _CGNAT:
        return ("ipv4-cgnat", "high",
                "CGNAT-range address (overlay networks such as Tailscale live here)")
    if addr.is_link_local:
        return ("ipv4-linklocal", "low", "Link-local address")
    if addr.is_private:
        return ("ipv4-private", "high",
                "RFC 1918 private address reveals internal topology")
    if addr.is_reserved:
        return ("ipv4-reserved", "low", "Reserved-range address")
    return ("ipv4-public", "high", "Public IP address")


def _classify_v6(addr: ipaddress.IPv6Address):
    if addr in _DOC_NET_V6 or addr.is_loopback or addr.is_unspecified:
        return None
    if addr.is_multicast:
        return None
    if addr.is_link_local:
        return ("ipv6-linklocal", "low", "Link-local IPv6 address")
    if addr.is_private:
        return ("ipv6-ula", "high", "Unique-local IPv6 address reveals internal topology")
    return ("ipv6-public", "high", "Public IPv6 address")


def _detect_ipv4(line: str):
    for m in _RE_IPV4.finditer(line):
        try:
            addr = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        cls = _classify_v4(addr)
        if cls:
            cat, sev, msg = cls
            yield (m.start(1), m.end(1), cat, "ipv4", m.group(1), sev, msg)


def _detect_ipv6(line: str):
    for m in _RE_IPV6.finditer(line):
        text = m.group(1)
        if ":" not in text or len(text) < 3:
            continue
        # Require at least one multi-digit hex group; kills prose like "a::b"
        # while keeping every realistic address (fe80::1 has "fe80"). scrub:ok
        if not re.search(r"[0-9A-Fa-f]{2}", text):
            continue
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            continue
        cls = _classify_v6(addr)
        if cls:
            cat, sev, msg = cls
            yield (m.start(1), m.end(1), cat, "ipv6", text, sev, msg)


def _detect_mac(line: str):
    for m in _RE_MAC.finditer(line):
        text = m.group(1)
        first = int(text[0:2], 16)
        if first & 0x02:  # locally administered: sanctioned placeholder space
            continue
        if text.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        yield (m.start(1), m.end(1), "mac-address", "mac", text, "medium",
               "Hardware MAC address (OUI identifies the vendor and device)")


# ---------------------------------------------------------------------------
# Hostnames
# ---------------------------------------------------------------------------

_INTERNAL_TLDS = (
    "local", "internal", "corp", "lan", "intra", "intranet", "private",
    "home", "home\\.arpa",
)
_RE_INTERNAL_HOST = re.compile(
    r"(?i)(?<![\w.-])((?:[a-z0-9_-]+\.)+(?:" + "|".join(_INTERNAL_TLDS) + r"))(?![\w-])"
)
_RE_TSNET = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)+ts\.net)(?![\w-])")


def _detect_hostnames(line: str, org_domains: tuple[str, ...]):
    for m in _RE_INTERNAL_HOST.finditer(line):
        yield (m.start(1), m.end(1), "hostname-internal", "hostname",
               m.group(1), "high", "Internal hostname reveals naming scheme and services")
    for m in _RE_TSNET.finditer(line):
        yield (m.start(1), m.end(1), "hostname-tailnet", "hostname",
               m.group(1), "high", "Tailscale tailnet hostname")
    for dom in org_domains:
        pat = re.compile(
            r"(?i)(?<![\w.-])((?:[a-z0-9_-]+\.)*" + re.escape(dom) + r")(?![\w-])"
        )
        for m in pat.finditer(line):
            yield (m.start(1), m.end(1), "hostname-org", "hostname",
                   m.group(1), "high",
                   "Configured organization domain (subdomains reveal your stack)")


# ---------------------------------------------------------------------------
# Filesystem paths / usernames
# ---------------------------------------------------------------------------

_SAFE_USERNAMES = {
    "user", "username", "example", "runner", "yourname", "your-user",
    "johndoe", "jdoe", "alice", "bob", "vagrant", "ubuntu", "ec2-user",
}
_RE_HOME = re.compile(r"/(?:home|Users)/([A-Za-z][\w.-]{0,31})(?=[/\s\"'`:,)\]]|$)")
_RE_WINHOME = re.compile(r"(?i)[A-Z]:\\Users\\([^\\/\s\"'`]{1,64})")


def _username_ok(name: str) -> bool:
    low = name.lower()
    return low in _SAFE_USERNAMES or low.startswith("user-")


def _detect_home_paths(line: str):
    for regex in (_RE_HOME, _RE_WINHOME):
        for m in regex.finditer(line):
            name = m.group(1)
            if _username_ok(name):
                continue
            if not re.search(r"[A-Za-z]", name):
                continue  # "C:\Users\..." style prose, not a username
            yield (m.start(1), m.end(1), "path-home-username", "username",
                   name, "medium", "Home directory path reveals a real username")


# ---------------------------------------------------------------------------
# Email addresses
# ---------------------------------------------------------------------------

_RE_EMAIL = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w-])"
)
_SAFE_EMAIL_DOMAIN_SUFFIXES = (
    "example.com", "example.net", "example.org",
    "users.noreply.github.com",
)


def _detect_emails(line: str):
    for m in _RE_EMAIL.finditer(line):
        addr = m.group(1)
        domain = addr.rsplit("@", 1)[1].lower()
        if any(domain == s or domain.endswith("." + s)
               for s in _SAFE_EMAIL_DOMAIN_SUFFIXES):
            continue
        yield (m.start(1), m.end(1), "email-address", "email",
               addr, "medium", "Email address")


# ---------------------------------------------------------------------------
# Credentials and cloud identifiers
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("secret-private-key",
     re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
     "Private key material"),
    ("secret-aws-access-key",
     re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
     "AWS access key ID"),
    ("secret-github-token",
     re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
     "GitHub token"),
    ("secret-slack-token",
     re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
     "Slack token"),
    ("secret-anthropic-key",
     re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"),
     "Anthropic API key"),
    ("secret-jwt",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
     "JSON Web Token"),
    ("secret-wireguard-key",
     re.compile(r"(?im)^\s*PrivateKey\s*=\s*([A-Za-z0-9+/]{42,44}=)"),
     "WireGuard private key"),
)

_PLACEHOLDER_HINTS = (
    "example", "changeme", "change-me", "placeholder", "redacted", "xxxx",
    "your", "<", ">", "$", "{", "%", "todo", "dummy", "sample", "insert",
    "...", "***", "hunter2",
)
_RE_GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|"
    r"access[_-]?token|private[_-]?key|client[_-]?secret)\b\s*[:=]>?\s*[\"']?"
    r"([^\s\"',;]{8,})"
)

_RE_AWS_ARN = re.compile(r"\barn:aws[\w-]*:[\w-]+:[\w-]*:(\d{12}):")
_RE_ZEROTIER = re.compile(r"\b([0-9a-f]{16})\b")


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(h in low for h in _PLACEHOLDER_HINTS)


def _detect_secrets(line: str):
    for category, pattern, label in _SECRET_PATTERNS:
        for m in pattern.finditer(line):
            yield (m.start(1), m.end(1), category, "secret", m.group(1),
                   "critical", label)
    for m in _RE_GENERIC_ASSIGNMENT.finditer(line):
        value = m.group(1)
        if _looks_placeholder(value):
            continue
        yield (m.start(1), m.end(1), "secret-assignment", "secret", value,
               "critical", "Credential-like assignment")


def _detect_cloud(line: str):
    for m in _RE_AWS_ARN.finditer(line):
        yield (m.start(1), m.end(1), "infra-aws-account", "account",
               m.group(1), "medium", "AWS account ID inside an ARN")
    if "zerotier" in line.lower():
        for m in _RE_ZEROTIER.finditer(line):
            yield (m.start(1), m.end(1), "infra-zerotier-network", "netid",
                   m.group(1), "medium", "ZeroTier network ID")


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def scan_line(line: str, org_domains: tuple[str, ...] = ()) -> list[tuple]:
    """Run all detectors on one line and resolve overlapping spans."""
    raw: list[tuple] = []
    raw.extend(_detect_secrets(line))
    raw.extend(_detect_ipv6(line))
    raw.extend(_detect_ipv4(line))
    raw.extend(_detect_hostnames(line, org_domains))
    raw.extend(_detect_mac(line))
    raw.extend(_detect_home_paths(line))
    raw.extend(_detect_emails(line))
    raw.extend(_detect_cloud(line))
    return _dedupe_spans(raw)


def _dedupe_spans(items: list[tuple]) -> list[tuple]:
    """Drop overlapping matches, preferring higher severity then longer span."""
    items.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    kept: list[tuple] = []
    for item in items:
        start, end = item[0], item[1]
        clash = next((k for k in kept if start < k[1] and end > k[0]), None)
        if clash is None:
            kept.append(item)
            continue
        better = (SEV_RANK[item[5]], end - start) > (
            SEV_RANK[clash[5]], clash[1] - clash[0])
        if better:
            kept.remove(clash)
            kept.append(item)
    kept.sort(key=lambda t: t[0])
    return kept


def scan_text(path: str, text: str, config) -> list[Finding]:
    """Scan full text of one file; returns filtered findings."""
    findings: list[Finding] = []
    org = tuple(config.org_domains)
    for line_no, line in enumerate(text.splitlines(), start=1):
        if INLINE_WAIVER in line:
            continue
        for start, end, category, kind, value, severity, message in scan_line(line, org):
            if config.is_check_disabled(category):
                continue
            if config.is_allowed(kind, value):
                continue
            findings.append(Finding(
                path=path, line_no=line_no, start=start, end=end,
                category=category, kind=kind, value=value,
                severity=severity, message=message,
            ))
    return findings
