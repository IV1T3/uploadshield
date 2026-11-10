"""``uploadshield scan``: verdicts, walking directories, and files that are not files."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.cli.conftest import SAMPLES, Cli
from tests.support import corpus


def test_each_file_gets_its_verdict(cli: Cli, samples: Path) -> None:
    run = cli("scan", samples, "--json")
    assert run.status == 1
    assert run.verdicts() == {name: verdict for name, (_, verdict) in SAMPLES.items()}
    summary = run.json()["summary"]
    assert summary["files"] == len(SAMPLES)
    assert (summary["clean"], summary["dangerous"]) == (4, 5)
    assert (summary["refused"], summary["not_verified"]) == (1, 1)


def test_clean_files_exit_zero(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "a.png").write_bytes(corpus.png())
    (tmp_path / "b.pdf").write_bytes(corpus.pdf())
    run = cli("scan", tmp_path)
    assert run.status == 0
    assert "2 files in" in run.out
    assert "2 clean" in run.out


def test_human_output(cli: Cli, samples: Path) -> None:
    out = cli("scan", samples).out
    assert out.startswith(f"{samples}/\n")  # files are listed under their directory
    assert "\u2713 ok.png" in out
    assert "\u2717 js.pdf" in out
    assert "pdf_active_content" in out
    assert "JavaScript" in out  # the detail that matters
    assert "! photo.png" in out
    assert "? backup.gz" in out
    assert "contents cannot be inspected" in out
    assert "\x1b[" not in out  # not a terminal: no colour
    assert "uploadshield explain <code>" in out


def test_quiet_shows_only_findings(cli: Cli, samples: Path) -> None:
    out = cli("scan", samples, "--quiet").out
    assert "ok.png" not in out
    assert "js.pdf" in out
    assert "11 files in" in out  # the summary still counts everything


def test_directories_are_walked_in_sorted_order(cli: Cli, tmp_path: Path) -> None:
    for relative in ("b/z.txt", "b/a.txt", "a.txt", "c/d/e.txt"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"text\n")
    files = cli("scan", tmp_path, "--json").json()["files"]
    assert [Path(f["path"]).relative_to(tmp_path).as_posix() for f in files] == [
        "a.txt",
        "b/a.txt",
        "b/z.txt",
        "c/d/e.txt",
    ]


def test_exclude_prunes_names_and_paths(cli: Cli, samples: Path) -> None:
    (samples / "logs").mkdir()
    (samples / "logs" / "shell.php").write_bytes(corpus.PHP_SHELL)
    run = cli("scan", samples, "--exclude", "logs", "--exclude", "*.pdf", "--json")
    names = run.verdicts()
    assert "js.pdf" not in names
    assert "ok.pdf" not in names
    assert list(names).count("shell.php") == 1  # the one in logs/ was pruned
    assert "macro.docx" in names


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need privileges")
def test_symbolic_links(cli: Cli, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "shell.php").write_bytes(corpus.PHP_SHELL)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ok.png").write_bytes(corpus.png())
    (tree / "link.php").symlink_to(outside / "shell.php")
    (tree / "dir").symlink_to(outside)
    (tree / "loop").symlink_to(tree)

    default = cli("scan", tree, "--json").json()
    skipped = {Path(f["path"]).name: f.get("skipped") for f in default["files"]}
    assert skipped == {
        "dir": "symbolic link",
        "link.php": "symbolic link",
        "loop": "symbolic link",
        "ok.png": None,
    }
    followed = cli("scan", tree, "--follow-symlinks", "--json").json()
    by_path = {Path(f["path"]).relative_to(tree).as_posix(): f for f in followed["files"]}
    assert by_path["dir/shell.php"]["verdict"] == "dangerous"
    assert by_path["link.php"]["verdict"] == "dangerous"
    assert by_path["loop"]["skipped"] == "directory cycle"
    # Links named on the command line are always followed.
    assert cli("scan", tree / "link.php", "--json").verdicts() == {"link.php": "dangerous"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_special_files_are_skipped_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "ok.png").write_bytes(corpus.png())
    # A FIFO without a writer would block a plain open() forever: run in a subprocess.
    done = subprocess.run(
        [sys.executable, "-m", "uploadshield", "scan", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "pipe  skipped: not a regular file" in done.stdout
    assert "1 skipped" in done.stdout


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="root reads everything")
def test_unreadable_files_are_not_verified(cli: Cli, tmp_path: Path) -> None:
    secret = tmp_path / "secret.pdf"
    secret.write_bytes(corpus.pdf())
    secret.chmod(0)
    try:
        run = cli("scan", tmp_path, "--json")
    finally:
        secret.chmod(0o600)
    (entry,) = run.json()["files"]
    assert entry["verdict"] == "not_verified"
    assert "ermission" in entry["error"]
    assert run.status == 1


def test_standard_input(cli: Cli) -> None:
    assert cli("scan", "-", "--name", "cat.png", stdin=corpus.PHP_SHELL).status == 1
    assert cli("scan", "-", "--name", "a.png", stdin=corpus.png()).status == 0
    refused = cli("scan", "-", stdin=b"x")
    assert refused.status == 2
    assert "needs --name" in refused.err


def test_usage_problems_exit_two_before_scanning(cli: Cli, samples: Path) -> None:
    missing = cli("scan", samples, samples / "nope")
    assert missing.status == 2
    assert "no such file or directory" in missing.err
    assert missing.out == ""
    assert cli("scan", samples, "--name", "x.png").status == 2  # --name needs one file
    assert cli("scan", "-", "-", "--name", "x").status == 2


def test_missing_extras_are_named(cli: Cli, samples: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *a: None if name == "magika" else real(name, *a)
    )
    run = cli("scan", samples, "--magika")
    assert run.status == 2
    assert "uploadshield[magika]" in run.err
    assert "uv add" in run.err


def test_lines_show_what_decided_the_verdict(cli: Cli, samples: Path) -> None:
    human = cli("scan", samples / "cat.png").out
    assert "type_not_allowed" in human
    assert "extension_mismatch" not in human  # a lesser finding of a dangerous file
    (entry,) = cli("scan", samples / "cat.png", "--json").json()["files"]
    assert {"type_not_allowed", "extension_mismatch"} <= {e["code"] for e in entry["errors"]}


def test_python_dash_m_does_not_import_from_the_scanned_directory(tmp_path: Path) -> None:
    # A folder of uploads may contain a planted package named like a dependency.
    planted = tmp_path / "PIL"
    planted.mkdir()
    (planted / "__init__.py").write_text(
        "import pathlib\npathlib.Path(__file__).with_name('ran').write_text('x')\n"
    )
    (tmp_path / "photo.png").write_bytes(corpus.png())
    done = subprocess.run(
        [sys.executable, "-m", "uploadshield", "scan", "photo.png"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert not (planted / "ran").exists()


def test_inactive_checks_are_announced(
    cli: Cli, samples: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *a: None if name == "PIL" else real(name, *a)
    )
    human = cli("scan", samples / "ok.png")
    assert "image does nothing without the images extra" in human.err
    assert 'uvx --from "uploadshield[images]"' in human.err
    data = cli("scan", samples / "ok.png", "--json").json()
    assert any("images extra" in w for w in data["warnings"])
