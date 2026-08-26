import json
import subprocess

import pytest

from opsec_scrub.cli import main
from opsec_scrub.findings import mask_value


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "notes.md").write_text(
        "the box at 10.44.55.66 serves /home/analyst/site\n")
    (tmp_path / "clean.md").write_text("doc host 192.0.2.7 is fine\n")
    return tmp_path


def test_scan_exit_codes(repo, capsys):
    assert main(["scan", "--root", str(repo)]) == 1
    (repo / "notes.md").write_text("doc host 192.0.2.7\n")
    assert main(["scan", "--root", str(repo)]) == 0


def test_scan_masks_by_default(repo, capsys):
    main(["scan", "--root", str(repo)])
    out = capsys.readouterr().out
    assert "10.44.55.66" not in out
    assert mask_value("10.44.55.66") in out


def test_scan_json(repo, capsys):
    main(["scan", "--root", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_scanned"] == 2
    assert {f["category"] for f in payload["findings"]} == \
        {"ipv4-private", "path-home-username"}


def test_scrub_write_then_scan_clean(repo, capsys):
    assert main(["scrub", "--root", str(repo), "--write"]) == 0
    text = (repo / "notes.md").read_text()
    assert "10.44.55.66" not in text and "analyst" not in text
    assert main(["scan", "--root", str(repo)]) == 0


def test_scrub_dry_run_leaves_files(repo, capsys):
    before = (repo / "notes.md").read_text()
    assert main(["scrub", "--root", str(repo)]) == 0
    assert (repo / "notes.md").read_text() == before
    assert "+++" in capsys.readouterr().out  # emitted a diff preview


def test_config_file_never_scanned_or_scrubbed(repo):
    (repo / ".opsec-scrub.toml").write_text(
        'org_domains = ["acme-widgets.test"]\n')
    (repo / "notes.md").write_text("edge grafana.acme-widgets.test\n")
    (repo / "clean.md").write_text("nothing here\n")
    assert main(["scrub", "--root", str(repo), "--write"]) == 0
    # Policy file untouched; content pseudonymized; rescan clean.
    assert "acme-widgets.test" in (repo / ".opsec-scrub.toml").read_text()
    assert "acme-widgets" not in (repo / "notes.md").read_text()
    assert main(["scan", "--root", str(repo)]) == 0


def test_fail_on_threshold(repo):
    (repo / ".opsec-scrub.toml").write_text('fail_on = "critical"\n')
    assert main(["scan", "--root", str(repo)]) == 0  # high < critical


def test_install_hook(repo, capsys):
    assert main(["install-hook", "--root", str(repo)]) == 0
    hook = repo / ".git" / "hooks" / "pre-push"
    assert hook.exists() and hook.stat().st_mode & 0o111
    assert main(["install-hook", "--root", str(repo)]) == 2  # refuses overwrite
    assert main(["install-hook", "--root", str(repo), "--force"]) == 0
