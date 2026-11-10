"""External malware scanners: ClamAV (clamd) and YARA signatures."""

from __future__ import annotations

import functools
import logging
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from uploadshield.core.check import Check
from uploadshield.core.types import MiB
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["ClamAV", "ClamdError", "YaraRules", "clamd_ping", "clamd_scan"]

logger = logging.getLogger("uploadshield")


# --------------------------------------------------------------------------- #
# ClamAV
# --------------------------------------------------------------------------- #


class ClamdError(Exception):
    """clamd could not be reached or answered with an error."""


def _connect(address: str, timeout: float) -> socket.socket:
    parts = urlsplit(address)
    if parts.scheme == "tcp":
        if not parts.hostname or not parts.port:
            raise ClamdError(f"Invalid clamd address {address!r}; use tcp://host:port")
        return socket.create_connection((parts.hostname, parts.port), timeout=timeout)
    if parts.scheme == "unix":
        path = parts.path
    elif not parts.scheme:
        path = address
    else:
        raise ClamdError(f"Unsupported clamd address scheme {parts.scheme!r}")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except OSError:
        sock.close()
        raise
    return sock


def clamd_ping(address: str, *, timeout: float = 5.0) -> bool:
    """Whether a clamd answers ``PING`` at ``address`` (to fail early, before scanning)."""
    try:
        with _connect(address, timeout) as sock:
            sock.sendall(b"zPING\x00")
            reply = b""
            while not reply.endswith(b"\x00") and len(reply) < 64:
                data = sock.recv(64)
                if not data:
                    break
                reply += data
    except (OSError, ClamdError):
        return False
    return reply.rstrip(b"\x00").strip() == b"PONG"


def clamd_scan(file: InspectedFile, address: str, *, timeout: float, chunk_size: int) -> str | None:
    """Stream ``file`` to clamd (``INSTREAM``); return the signature name or ``None``."""
    with _connect(address, timeout) as sock:
        sock.sendall(b"zINSTREAM\x00")
        for chunk in file.iter_chunks(chunk_size):
            sock.sendall(struct.pack(">I", len(chunk)) + chunk)
        sock.sendall(struct.pack(">I", 0))
        reply = b""
        while not reply.endswith(b"\x00"):
            data = sock.recv(4096)
            if not data:
                break
            reply += data
    answer = reply.rstrip(b"\x00").decode("utf-8", "replace").strip()
    # "stream: OK" | "stream: Eicar-Signature FOUND" | "... ERROR"
    status = answer.split(":", 1)[-1].strip()
    if status == "OK":
        return None
    if status.endswith(" FOUND"):
        return status.removesuffix(" FOUND").strip()
    raise ClamdError(answer or "empty reply from clamd")


@dataclass(frozen=True, slots=True)
class ClamAV(Check):
    """Scan the file with a running ``clamd`` daemon.

    ``address`` is ``unix:///path/to/clamd.sock`` or ``tcp://host:3310``.  If the
    daemon is unreachable the file is refused (``fail_open=False``), because silently
    skipping the scan would turn an outage into a bypass.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "clamav"

    address: str = "unix:///var/run/clamav/clamd.ctl"
    timeout: float = 30.0
    fail_open: bool = False
    chunk_size: int = 256 * 1024

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        try:
            signature = clamd_scan(
                file, self.address, timeout=self.timeout, chunk_size=self.chunk_size
            )
        except (OSError, ClamdError) as exc:
            # An outage is expected operational noise: log without a traceback.
            logger.error("ClamAV scan failed for %r: %s", file.name, exc)  # noqa: TRY400
            if not self.fail_open:
                yield self.violation(
                    Code.SCANNER_UNAVAILABLE,
                    "The file could not be scanned for malware.",
                    error=str(exc),
                )
            return
        if signature:
            yield self.violation(
                Code.MALWARE_DETECTED, "The file was identified as malware.", signature=signature
            )


# --------------------------------------------------------------------------- #
# YARA
# --------------------------------------------------------------------------- #

_RULE_SUFFIXES = (".yar", ".yara")


def _rule_files(paths: tuple[str, ...]) -> dict[str, str]:
    files: dict[str, str] = {}
    for entry in paths:
        path = Path(entry)
        candidates = (
            sorted(p for p in path.iterdir() if p.suffix.lower() in _RULE_SUFFIXES)
            if path.is_dir()
            else [path]
        )
        for candidate in candidates:
            namespace = candidate.stem
            while namespace in files:
                namespace += "_"
            files[namespace] = str(candidate)
    return files


@functools.cache
def _compiled(paths: tuple[str, ...], source: str | None) -> Any:
    import yara

    if source is not None:
        return yara.compile(source=source)
    files = _rule_files(paths)
    if not files:
        raise ValueError(f"No YARA rule files found in {paths!r}")
    return yara.compile(filepaths=files)


@dataclass(frozen=True, slots=True)
class YaraRules(Check):
    """Match the file against YARA rules (``uv add "uploadshield[yara]"``).

    ``rules`` lists rule files and/or directories (``*.yar``/``*.yara``); ``source``
    accepts inline rule text.  Rules are compiled once per process and cached.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "yara"
    requires = ("yara",)

    rules: tuple[str, ...] = ()
    source: str | None = None
    timeout: int = 30
    max_bytes: int = 256 * MiB

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(str(p) for p in self.rules))
        if not self.rules and self.source is None:
            raise ValueError("YaraRules needs rule paths or inline source")

    def compile(self) -> Any:
        """Compile (or fetch the cached) rules; raises on syntax errors."""
        return _compiled(self.rules, self.source)

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        matches = self.compile().match(data=file.read(self.max_bytes), timeout=self.timeout)
        if matches:
            yield self.violation(
                Code.SIGNATURE_MATCH,
                "The file matches a known malicious signature.",
                rules=sorted({m.rule for m in matches}),
            )
