"""opsec-scrub: pre-publication sanitizer for security repos.

Finds and deterministically pseudonymizes infrastructure leakage that
secret scanners miss: real IPs, internal hostnames, home-directory
usernames, MAC addresses, overlay-network fingerprints, and credentials.

Copyright 2026 NorthQuinn Inc. Licensed under the Apache License 2.0.
"""

__version__ = "0.1.0"
