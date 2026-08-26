# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private
vulnerability reporting on this repository (Security tab, "Report a
vulnerability"). Do not open a public issue for a security report.

We aim to acknowledge reports within 72 hours.

## Scope notes for reporters

Reports we consider especially valuable:

- Detector bypasses: a value in a flagged class (private/public/CGNAT IPs,
  internal hostnames, credentials) that the scanner provably misses.
- Scrub escapes: input where `scrub --write` leaves the original sensitive
  value recoverable in the output file.
- State handling: any path where `.opsec-scrub.key` or
  `.opsec-scrub.map.json` could be committed, disclosed, or created with
  unsafe permissions.
- Output leaks: any code path that prints an unmasked matched value
  without `--show`.

## Design guarantees this project intends to hold

- Zero runtime dependencies; the standard library only.
- The pseudonym key and mapping never leave the machine and are written
  with mode 0600.
- Credential values are never transformed into derived output; they are
  replaced with static `[REDACTED:...]` markers.
- Scrubbed output re-scans clean (enforced by tests and CI).
