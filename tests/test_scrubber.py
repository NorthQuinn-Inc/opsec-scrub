from pathlib import Path

import pytest

from opsec_scrub.config import Config, KEY_FILENAME, MAP_FILENAME
from opsec_scrub.detectors import scan_text
from opsec_scrub.pseudonym import Pseudonymizer
from opsec_scrub.scrubber import ScrubRefused, build_pseudonymizer, scrub_text

KEY = b"k" * 32

SAMPLE = """\
server 10.20.30.40 talks to 10.20.30.41
again 10.20.30.40 from /home/analyst/run.sh
host core.fileserver.corp mac 00:00:5e:00:53:56
password = "tr0ub4dor&3-xyzzy"
"""


def cfg():
    return Config(root=Path("."))


def test_scrub_replaces_consistently():
    ps = Pseudonymizer(KEY)
    out, applied = scrub_text("f", SAMPLE, cfg(), ps)
    assert len(applied) == 7
    first = ps.ipv4("10.20.30.40")
    assert out.count(first) == 2          # same real IP, same placeholder
    assert "10.20.30.40" not in out
    assert "analyst" not in out
    assert "corp" not in out
    assert "[REDACTED:secret-assignment]" in out


def test_scrub_idempotent_and_scan_clean():
    ps = Pseudonymizer(KEY)
    out, _ = scrub_text("f", SAMPLE, cfg(), ps)
    # Scrubbed output must be clean by construction...
    assert scan_text("f", out, cfg()) == []
    # ...and a second scrub must be a no-op.
    out2, applied2 = scrub_text("f", out, cfg(), ps)
    assert out2 == out and applied2 == []


def test_private_key_block_fully_removed():
    text = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "c3ludGhldGljLXRlc3QtZml4dHVyZS1ub3QtYS1yZWFsLWtleQ==\n"
            "-----END OPENSSH PRIVATE KEY-----\n")
    ps = Pseudonymizer(KEY)
    out, _ = scrub_text("f", text, cfg(), ps)
    assert "c3ludGhldGlj" not in out and "BEGIN" not in out
    assert "[REDACTED:secret-private-key]" in out


def test_build_pseudonymizer_gitignores_state(tmp_path):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    build_pseudonymizer(tmp_path)
    gitignore = (tmp_path / ".gitignore").read_text()
    assert KEY_FILENAME in gitignore and MAP_FILENAME in gitignore
    assert oct((tmp_path / KEY_FILENAME).stat().st_mode & 0o777) == "0o600"


def test_scrub_refused_when_key_tracked(tmp_path):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / KEY_FILENAME).write_text("deadbeef" * 8 + "\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", KEY_FILENAME], check=True)
    with pytest.raises(ScrubRefused):
        build_pseudonymizer(tmp_path)
