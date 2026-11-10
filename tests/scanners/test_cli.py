"""The scanner flags of ``uploadshield scan``: clamd and YARA, checked before scanning."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from tests.support import corpus
from uploadshield.cli import main

pytest.importorskip("yara")


def run(capsys: pytest.CaptureFixture[str], *argv: object) -> tuple[int, str, str]:
    status = main([str(a) for a in argv])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def test_clamav(capsys: pytest.CaptureFixture[str], clamd: str, tmp_path: Path) -> None:
    (tmp_path / "eicar.txt").write_bytes(corpus.EICAR)
    (tmp_path / "ok.txt").write_bytes(b"hello\n")
    status, out, _ = run(capsys, "scan", tmp_path, "--clamav", clamd)
    assert status == 1
    assert "malware_detected" in out
    assert "1 clean, 1 dangerous" in out


def test_unreachable_clamd_stops_before_scanning(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    status, out, err = run(capsys, "scan", tmp_path, "--clamav", f"tcp://127.0.0.1:{port}")
    assert status == 2
    assert "clamd does not answer" in err
    assert out == ""


def test_yara(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text('rule webshell { strings: $e = "eval(base64_decode" condition: $e }')
    target = tmp_path / "files"
    target.mkdir()
    (target / "a.txt").write_bytes(b"x eval(base64_decode('...'))")
    status, out, _ = run(capsys, "scan", target, "--yara", rules)
    assert status == 1
    assert "signature_match" in out
    assert "webshell" in out
    broken = tmp_path / "broken.yar"
    broken.write_text("rule broken {")
    status, _, err = run(capsys, "scan", target, "--yara", broken)
    assert status == 2
    assert "YARA rules do not compile" in err
