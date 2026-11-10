"""ClamAV against a fake clamd speaking the real INSTREAM protocol, and real YARA."""

from __future__ import annotations

import socket
import socketserver
import threading
from pathlib import Path

import pytest

from tests.support import corpus
from tests.support.clamd import FakeClamd
from uploadshield import Upload, presets, validate
from uploadshield.checks import ClamAV, YaraRules
from uploadshield.checks.scanners import ClamdError, _connect, clamd_ping


def scan(data: bytes, name: str, check: ClamAV | YaraRules) -> tuple[str, ...]:
    policy = presets.DEFAULT.extend(checks=[check])
    return validate(Upload.from_bytes(data, name), policy).codes


def test_clamav_clean_and_infected(clamd: str) -> None:
    assert scan(b"hello", "a.txt", ClamAV(address=clamd, chunk_size=2)) == ()
    infected = validate(
        Upload.from_bytes(b"prefix " + corpus.EICAR, "a.txt"),
        presets.DEFAULT.extend(checks=[ClamAV(address=clamd)]),
    )
    assert infected.codes == ("malware_detected",)
    assert infected.violations[0].details["signature"] == "Win.Test.EICAR_HDB-1"


def test_clamav_unreachable_fails_closed_unless_fail_open() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # nothing listens here afterwards
    address = f"tcp://127.0.0.1:{port}"
    assert scan(b"hello", "a.txt", ClamAV(address=address, timeout=1)) == ("scanner_unavailable",)
    assert scan(b"hello", "a.txt", ClamAV(address=address, timeout=1, fail_open=True)) == ()


def test_clamav_error_reply(clamd: str) -> None:
    FakeClamd.reply_override = b"INSTREAM size limit exceeded. ERROR\x00"
    assert scan(b"hello", "a.txt", ClamAV(address=clamd)) == ("scanner_unavailable",)


def test_clamav_unix_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)  # keep the socket path short (AF_UNIX limit is ~104 bytes)
    server = socketserver.ThreadingUnixStreamServer("clamd.sock", FakeClamd)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert scan(corpus.EICAR, "a.txt", ClamAV(address="clamd.sock")) == ("malware_detected",)
        absolute = f"unix://{Path('clamd.sock').resolve()}"
        if len(absolute) < 100:
            assert scan(b"ok", "a.txt", ClamAV(address=absolute)) == ()
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("address", ["tcp://nohost", "http://x:1", "tcp://:3310"])
def test_clamav_bad_addresses(address: str) -> None:
    with pytest.raises(ClamdError):
        _connect(address, 1)


def test_clamd_ping(clamd: str) -> None:
    assert clamd_ping(clamd) is True
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    assert clamd_ping(f"tcp://127.0.0.1:{port}", timeout=1) is False
    assert clamd_ping("ftp://nowhere") is False
