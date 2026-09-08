# opsec-scrub

**Pre-publication sanitizer for security repos.** Finds and
deterministically pseudonymizes the infrastructure leakage that secret
scanners miss: real IPs, internal hostnames, home-directory usernames,
MAC addresses, overlay-network fingerprints, cloud account IDs, and
credentials.

Zero runtime dependencies. Python 3.11+. Apache-2.0.

## Why this exists

Secret scanners (Gitleaks, TruffleHog, and friends) hunt credentials.
They will not blink at any of this:

```text
Sensor forwards to 10.0.0.22, backup collector 10.0.0.23.    # scrub:ok
Tailscale peer 100.64.0.14 (box.example.ts.net)              # scrub:ok
Runbook lives in /home/analyst/runbooks/soc.md               # scrub:ok
host core.fileserver.corp  wifi ap mac e8:9f:80:aa:bb:01     # scrub:ok
```

(The `scrub:ok` markers are this repo's own inline waivers; these
deliberately leaky example lines are how this README passes its own
scan gate in CI.)

**Every identifier in this repository's examples, tests, and fixtures is
synthetic.** Nothing here corresponds to real infrastructure. The values are
chosen to sit inside the ranges the detectors actually flag, so the examples
still demonstrate real findings and still require their `scrub:ok` waivers.

Yet for anyone publishing detection content, IR writeups, runbooks, or
sanitized configs, those lines are the leak: internal topology, overlay
network membership, naming schemes, usernames, and hardware identity.
`opsec-scrub` treats infrastructure identifiers as first-class findings
and blocks the push before they go public.

Run it alongside a secret scanner, not instead of one. It carries
high-signal credential patterns too, but credentials are not its
specialty; leakage is.

## Install

```bash
pip install .
```

No runtime dependencies are pulled in; the tool is standard library
only, by design. What you audit is what runs.

## Quick start

```bash
cd your-repo

# Report leakage (exit 1 if anything is found; CI-friendly)
opsec-scrub scan

# Preview replacements as a unified diff, then apply
opsec-scrub scrub
opsec-scrub scrub --write

# Block risky pushes from now on
opsec-scrub install-hook
```

Example scan output (values are masked; scanner output is itself a leak
vector in shared CI logs, so nothing is echoed in full without `--show`):

```text
deploy-notes.md:2: [HIGH] ipv4-private  10*****22  (RFC 1918 private address reveals internal topology)
deploy-notes.md:4: [HIGH] hostname-tailnet  box************net  (Tailscale tailnet hostname)
deploy-notes.md:7: [CRITICAL] secret-assignment  9f8************a98  (Credential-like assignment)
```

## Deterministic pseudonymization

`scrub` does not blank values out; it maps them, stably, into IETF
documentation space:

| Real value                | Becomes                          | Space                     |
| ------------------------- | -------------------------------- | ------------------------- |
| any IPv4 (private/public) | `192.0.2.x` / `198.51.100.x` / `203.0.113.x` | RFC 5737 TEST-NET |
| any IPv6                  | `2001:db8:...`                   | RFC 3849                  |
| hostname                  | `xa1b2c3.example.com`            | RFC 2606, per-label       |
| home-dir username         | `user-a1b2c3`                    |                           |
| email                     | `user-a1b2c3@example.com`        |                           |
| MAC address               | `02:xx:xx:xx:xx:xx`              | locally administered      |
| credential                | `[REDACTED:category]`            | never derived from value  |

The same real value maps to the same placeholder in every file, on
every run, so scrubbed documents stay internally consistent and
correlatable: readers can still follow "this host talked to that host"
without learning either hostname. DNS labels are pseudonymized
individually, so `docs.acme.example` and `wiki.acme.example` visibly
share a parent after scrubbing while the service names in your
subdomains leak nothing.

Placeholders are derived with HMAC-SHA256 under a per-project key.
Because everything lands in documentation space, **scrubbed output
re-scans clean by construction**, which is enforced in the test suite
and in CI.

Two local state files make this work, and both are created with mode
0600 and force-added to `.gitignore` before any scrub runs (`scrub`
refuses to operate if either is already tracked by git):

- `.opsec-scrub.key` is the HMAC key.
- `.opsec-scrub.map.json` is the real-to-placeholder map, which doubles
  as your local audit trail of what was replaced.

Credentials are the exception to pseudonymization: a matched credential
is replaced with a static `[REDACTED:...]` marker that is not a
function of the secret in any way, and the tool reminds you to rotate
it. Scrubbing a working tree does not clean git history; if a secret
was ever committed, rotate it and rewrite history with
`git filter-repo` or BFG.

## Configuration

Optional, via `.opsec-scrub.toml` at the repo root:

```toml
# Flag your own domains (subdomains reveal your stack)
org_domains = ["acme-widgets.test"]

# Paths to skip (gitignored paths are already skipped)
exclude = ["tests/**", "third_party/**"]

# Findings that are deliberate and publishable
[allow]
ips = ["198.18.0.1"]          # scrub:ok benchmarking range used in docs
cidrs = ["198.18.0.0/15"]     # scrub:ok
domains = ["status.example"]  # suffix match
emails = ["press@acme-widgets.test"]  # scrub:ok
values = []                   # exact-match escape hatch for any finding

# fail_on: minimum severity that makes `scan` exit non-zero
# (low | medium | high | critical)
fail_on = "low"

# Disable whole categories if you must
disable = ["email-address"]
```

Single findings can be waived inline with a comment on the same line:

```text
peer 203.0.113.7 is our documented example  # scrub:ok
```

## What it detects

| Category | Severity | Notes |
| --- | --- | --- |
| `ipv4-private`, `ipv6-ula` | high | RFC 1918 / ULA reveal internal topology |
| `ipv4-public`, `ipv6-public` | high | your egress and edge |
| `ipv4-cgnat` | high | 100.64/10, where Tailscale overlays live |
| `ipv4-linklocal`, `ipv6-linklocal` | low | |
| `hostname-internal` | high | `*.corp`, `*.internal`, `*.lan`, `*.local`, ... |
| `hostname-tailnet` | high | `*.ts.net` |
| `hostname-org` | high | your configured domains, any subdomain |
| `path-home-username` | medium | `/home/...`, `/Users/...`, `C:\Users\...` |
| `mac-address` | medium | universally administered only |
| `email-address` | medium | `example.*` and GitHub noreply exempt |
| `infra-aws-account` | medium | 12-digit account ID inside ARNs |
| `infra-zerotier-network` | medium | 16-hex network ID in ZeroTier context |
| `secret-*` | critical | private key blocks, AWS/GitHub/Slack/Anthropic tokens, JWTs, WireGuard keys, credential-like assignments |

Values already in documentation space (TEST-NET, `2001:db8::/32`,
`example.com`, locally administered MACs, loopback) are never flagged.
That is the sanctioned place for examples, and it is where `scrub`
puts things.

## CI gate

```yaml
- name: opsec-scrub gate
  run: |
    pip install opsec-scrub
    opsec-scrub scan
```

`scan` exits 1 when findings meet the `fail_on` threshold and 0
otherwise. `--json` emits machine-readable output for tooling.

This repository runs that exact gate on itself; the source you are
reading scans clean.

## Limitations, stated plainly

- Line-oriented: a value split across lines, encoded, or embedded in a
  binary is not detected. Binaries and files over 5 MiB are skipped.
- A dotted quad that is really a version number
  ("upgraded to 2.44.101.9") is indistinguishable from an IP; <!-- scrub:ok -->
  waive it inline exactly the way this source line does.
- Public hostname detection is deliberately opt-in (configured
  `org_domains` plus known-internal TLDs); a random third-party FQDN in
  prose is not flagged.
- Working tree only. History is out of scope: if it was ever committed,
  treat it as disclosed, rotate, and rewrite history.
- A determined reader can sometimes infer facts from structure alone
  (how many hosts, which talks to which). That trade is intentional;
  it is what keeps scrubbed documents useful.

## License

Apache-2.0. Copyright 2026 NorthQuinn Inc.
