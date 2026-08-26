# All "sensitive" values in this file are synthetic test fixtures using
# documentation ranges where possible and fabricated identifiers elsewhere.
from pathlib import Path

import pytest

from opsec_scrub.config import Config
from opsec_scrub.detectors import scan_line, scan_text

CFG = Config(root=Path("."))


def cats(line, org=()):
    return [t[2] for t in scan_line(line, tuple(org))]


# --- IPv4 -----------------------------------------------------------------

def test_private_ip_flagged():
    assert cats("server at 10.1.2.3 responded") == ["ipv4-private"]
    assert cats("bind 192.168.44.7:8080") == ["ipv4-private"]
    assert cats("net 172.16.0.9") == ["ipv4-private"]

def test_public_ip_flagged():
    assert cats("dns 8.8.8.8") == ["ipv4-public"]

def test_cgnat_flagged():
    assert cats("peer 100.64.0.4") == ["ipv4-cgnat"]

def test_documentation_ips_allowed():
    assert cats("use 192.0.2.10 and 198.51.100.7 and 203.0.113.99") == []

def test_loopback_and_special_allowed():
    assert cats("listen 127.0.0.1 and 0.0.0.0 and 255.255.255.255") == []

def test_invalid_octets_ignored():
    assert cats("999.999.999.999 is not an ip") == []

def test_version_string_not_matched_when_dotted_further():
    assert cats("release 1.2.3.4.5 shipped") == []

def test_ip_before_sentence_period_flagged():
    assert cats("collector is 10.0.0.23.") == ["ipv4-private"]
    assert cats("collector is 10.0.0.23. Next sentence.") == ["ipv4-private"]


# --- IPv6 -----------------------------------------------------------------

def test_ipv6_public_flagged():
    assert cats("addr 2607:f8b0:4004:c07::66") == ["ipv6-public"]

def test_ipv6_ula_flagged():
    assert cats("ula fd12:3456:789a::1") == ["ipv6-ula"]

def test_ipv6_documentation_allowed():
    assert cats("doc 2001:db8::1 sample") == []

def test_ipv6_loopback_allowed():
    assert cats("home ::1 here") == []

def test_cpp_scope_operator_not_matched():
    assert cats("std::vector<std::string> names;") == []

def test_timestamp_not_matched():
    assert cats("event at 12:30:45 UTC") == []


# --- MAC ------------------------------------------------------------------

def test_universal_mac_flagged():
    assert cats("iface 00:00:5e:00:53:56") == ["mac-address"]

def test_locally_administered_mac_allowed():
    assert cats("iface 02:00:00:aa:bb:cc") == []


# --- hostnames ------------------------------------------------------------

def test_internal_tld_flagged():
    assert cats("ping fileserver.corp now") == ["hostname-internal"]
    assert cats("host db01.internal down") == ["hostname-internal"]

def test_tailnet_hostname_flagged():
    assert cats("ssh box.example.ts.net") == ["hostname-tailnet"]

def test_org_domain_flagged_with_config():
    assert cats("grafana.acme-widgets.test is up",
                org=["acme-widgets.test"]) == ["hostname-org"]

def test_org_domain_not_flagged_without_config():
    assert cats("grafana.acme-widgets.test is up") == []

def test_example_domains_never_flagged():
    assert cats("see docs.example.com and example.org") == []


# --- paths / usernames ----------------------------------------------------

def test_home_username_flagged():
    assert cats("log at /home/analyst/app.log") == ["path-home-username"]
    assert cats(r"C:\Users\analyst\data") == ["path-home-username"]
    assert cats("in /Users/analyst/Library") == ["path-home-username"]

def test_safe_usernames_allowed():
    assert cats("/home/user/app and /home/runner/work") == []
    assert cats("/home/user-a1b2c3/app") == []


# --- emails ---------------------------------------------------------------

def test_email_flagged():
    assert cats("contact ops@acme-widgets.test") == ["email-address"]

def test_example_email_allowed():
    assert cats("contact someone@example.com") == []


# --- secrets --------------------------------------------------------------

def test_aws_key_flagged():
    line = "key = AKIA" + "IOSFODNN7EXAMPLE"
    assert "secret-aws-access-key" in cats(line)

def test_github_token_flagged():
    line = "token: ghp_" + "a1B2c3D4e5F6g7H8i9J0a1B2c3D4e5F6g7H8"
    assert "secret-github-token" in cats(line)

def test_private_key_header_flagged():
    assert cats("-----BEGIN OPENSSH PRIVATE KEY-----") == ["secret-private-key"]

def test_generic_assignment_flagged():
    assert cats('password = "tr0ub4dor&3-xyzzy"') == ["secret-assignment"]

def test_placeholder_assignment_allowed():
    assert cats('password = "<your-password-here>"') == []
    assert cats("api_key = ${API_KEY}") == []
    assert cats("password = [REDACTED:secret-assignment]") == []

def test_wireguard_private_key_flagged():
    line = "PrivateKey = " + "a" * 43 + "="
    assert "secret-wireguard-key" in cats(line)


# --- cloud ----------------------------------------------------------------

def test_aws_account_in_arn_flagged():
    assert "infra-aws-account" in cats("arn:aws:iam::123456789012:role/x")

def test_zerotier_id_needs_context():
    assert cats("join zerotier network 89e92ceee59c4507") == ["infra-zerotier-network"]
    assert cats("hash 89e92ceee59c4507 alone") == []


# --- waivers / config -----------------------------------------------------

def test_inline_waiver_suppresses():
    text = "peer 10.9.9.9  # scrub:ok known-good doc value\nother 10.9.9.8\n"
    findings = scan_text("f", text, CFG)
    assert len(findings) == 1 and findings[0].line_no == 2

def test_config_allowlists():
    cfg = Config(root=Path("."))
    cfg.allow_ips = {"10.1.1.1"}
    import ipaddress
    cfg.allow_cidrs = [ipaddress.ip_network("172.16.5.0/24")]
    cfg.allow_domains = ["acme-widgets.test"]
    cfg.org_domains = ["acme-widgets.test"]
    text = "a 10.1.1.1\nb 172.16.5.77\nc app.acme-widgets.test\nd 10.2.2.2\n"
    findings = scan_text("f", text, cfg)
    assert [f.value for f in findings] == ["10.2.2.2"]

def test_disabled_check():
    cfg = Config(root=Path("."))
    cfg.disabled_checks = ["email-address"]
    assert scan_text("f", "mail ops@acme-widgets.test\n", cfg) == []


# --- overlap resolution ---------------------------------------------------

def test_overlapping_spans_resolved():
    # An IPv6 address should not additionally produce MAC-ish findings.
    found = cats("addr 2607:f8b0:aa:bb:cc:dd:ee:ff")
    assert found.count("ipv6-public") == 1 and "mac-address" not in found
