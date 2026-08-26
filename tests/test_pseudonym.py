import ipaddress

from opsec_scrub.pseudonym import Pseudonymizer

KEY_A = b"k" * 32
KEY_B = b"j" * 32


def test_deterministic_same_key():
    a, b = Pseudonymizer(KEY_A), Pseudonymizer(KEY_A)
    assert a.ipv4("10.1.2.3") == b.ipv4("10.1.2.3")
    assert a.hostname("web.acme.test") == b.hostname("web.acme.test")
    assert a.username("analyst") == b.username("analyst")


def test_different_key_different_output():
    a, b = Pseudonymizer(KEY_A), Pseudonymizer(KEY_B)
    assert a.ipv4("10.1.2.3") != b.ipv4("10.1.2.3")


def test_ipv4_lands_in_documentation_space():
    ps = Pseudonymizer(KEY_A)
    for ip in ("10.0.0.1", "8.8.4.4", "100.64.0.2", "169.254.0.5"):
        out = ipaddress.ip_address(ps.ipv4(ip))
        assert any(out in ipaddress.ip_network(n) for n in
                   ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def test_ipv6_lands_in_documentation_space():
    ps = Pseudonymizer(KEY_A)
    out = ipaddress.ip_address(ps.ipv6("2607:f8b0::1"))
    assert out in ipaddress.ip_network("2001:db8::/32")


def test_distinct_inputs_distinct_outputs():
    ps = Pseudonymizer(KEY_A)
    outs = {ps.ipv4(f"10.0.{i}.{j}") for i in range(6) for j in range(50)}
    assert len(outs) == 300  # collision probing keeps mappings injective


def test_hostname_structure_preserved():
    ps = Pseudonymizer(KEY_A)
    parent = ps.hostname("acme.test")
    child = ps.hostname("web.acme.test")
    assert parent.endswith(".example.com")
    assert child.endswith("." + parent.removesuffix(".example.com") + ".example.com")


def test_mac_is_locally_administered():
    ps = Pseudonymizer(KEY_A)
    out = ps.mac("00:00:5e:00:53:56")
    assert int(out[0:2], 16) & 0x02


def test_secret_replacement_never_derived():
    ps = Pseudonymizer(KEY_A)
    assert ps.replacement_for("secret", "secret-aws-access-key", "AKIA" + "Q" * 16) \
        == "[REDACTED:secret-aws-access-key]"


def test_map_persistence_across_instances(tmp_path):
    map_path = tmp_path / "map.json"
    first = Pseudonymizer(KEY_A, map_path)
    v1 = first.ipv4("10.5.5.5")
    first.save()
    assert oct(map_path.stat().st_mode & 0o777) == "0o600"
    second = Pseudonymizer(KEY_A, map_path)
    assert second.ipv4("10.5.5.5") == v1
