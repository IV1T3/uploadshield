"""A fake clamd that speaks the real INSTREAM protocol (and finds EICAR)."""

from __future__ import annotations

import socketserver
import struct
import threading
from collections.abc import Iterator

import pytest

from tests.support import corpus


class FakeClamd(socketserver.BaseRequestHandler):
    reply_override: bytes | None = None

    def handle(self) -> None:
        command = b""
        while not command.endswith(b"\x00"):
            command += self.request.recv(1)
        if command == b"zPING\x00":
            self.request.sendall(b"PONG\x00")
            return
        assert command == b"zINSTREAM\x00"
        payload = b""
        while True:
            (size,) = struct.unpack(">I", self._recv_exact(4))
            if size == 0:
                break
            payload += self._recv_exact(size)
        if self.reply_override is not None:
            reply = self.reply_override
        elif corpus.EICAR in payload:
            reply = b"stream: Win.Test.EICAR_HDB-1 FOUND\x00"
        else:
            reply = b"stream: OK\x00"
        self.request.sendall(reply)

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.request.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data


@pytest.fixture
def clamd() -> Iterator[str]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeClamd)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"tcp://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()
    FakeClamd.reply_override = None
