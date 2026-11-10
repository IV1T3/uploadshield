"""Framework-agnostic representation of an uploaded file."""

from __future__ import annotations

import hashlib
import io
import logging
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
from typing import IO, TYPE_CHECKING, Any, cast

from .types import FileType, MiB, types_for_extension

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

    from .sniffing import Sniffer

__all__ = ["HEAD_SIZE", "ContentTooLargeError", "InspectedFile", "Upload"]

logger = logging.getLogger("uploadshield")

#: Bytes read from the start of a file for signature and text detection.
HEAD_SIZE = 8 * 1024
_CHUNK_SIZE = 1 * MiB


class ContentTooLargeError(Exception):
    """Raised when a check asks for more content than it is allowed to buffer."""


@dataclass(frozen=True, slots=True)
class Upload:
    """The raw facts about an upload, as provided by the web framework.

    ``name`` and ``declared_type`` are client-controlled and therefore untrusted.
    """

    stream: IO[bytes]
    name: str
    size: int | None = None
    declared_type: str | None = None
    field: str | None = None

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        name: str,
        *,
        declared_type: str | None = None,
        field: str | None = None,
    ) -> Upload:
        return cls(io.BytesIO(data), name, len(data), declared_type, field)


class InspectedFile:
    """A read-only, lazily analysed view over an :class:`Upload`.

    Facts that several checks need (head bytes, detected type, hashes, container
    listings) are computed at most once.  The underlying stream position is restored
    after every read so the application can still consume the file afterwards.
    """

    def __init__(self, upload: Upload, sniffer: Sniffer) -> None:
        self.upload = upload
        self.name = upload.name or ""
        self.field = upload.field
        self.declared_type = upload.declared_type
        self._sniffer = sniffer
        self._stream = _ensure_seekable(upload.stream)
        self._owns_stream = self._stream is not upload.stream
        self._origin = self._stream.tell()
        self.size = upload.size if upload.size is not None else self._measure()
        self._head = b""
        #: Scratch space so checks can share expensive parse results.
        self.cache: dict[str, Any] = {}

    def __repr__(self) -> str:
        return f"<InspectedFile {self.name!r} size={self.size}>"

    @property
    def stream(self) -> IO[bytes]:
        """The seekable stream (a private copy if the upload's stream was not seekable)."""
        return self._stream

    def close(self) -> None:
        """Release the private copy made for non-seekable streams, if any."""
        if self._owns_stream:
            self._stream.close()

    # -- raw access -------------------------------------------------------------------

    @contextmanager
    def open(self) -> Generator[IO[bytes], None, None]:
        """Yield the stream positioned at the start; restore the position afterwards."""
        try:
            self._stream.seek(0)
            yield self._stream
        finally:
            self._stream.seek(self._origin)

    def head(self, n: int = HEAD_SIZE) -> bytes:
        if len(self._head) < n and len(self._head) < self.size:
            with self.open() as fh:
                self._head = fh.read(max(n, HEAD_SIZE))
        return self._head[:n]

    def tail(self, n: int) -> bytes:
        with self.open() as fh:
            fh.seek(max(0, self.size - n))
            return fh.read(n)

    def read(self, limit: int) -> bytes:
        """Return the whole content, refusing to buffer more than ``limit`` bytes."""
        if self.size > limit:
            raise ContentTooLargeError(f"{self.size} bytes exceeds the buffer limit of {limit}")
        with self.open() as fh:
            return fh.read(limit + 1)[:limit]

    def iter_chunks(self, chunk_size: int = _CHUNK_SIZE) -> Iterator[bytes]:
        with self.open() as fh:
            while chunk := fh.read(chunk_size):
                yield chunk

    # -- derived facts ----------------------------------------------------------------

    @cached_property
    def extensions(self) -> tuple[str, ...]:
        """Every dot-separated suffix, lowercased: ``"a.tar.GZ"`` -> ``(".tar", ".gz")``."""
        stem = self.name.lstrip(".")
        parts = stem.split(".")[1:]
        return tuple(f".{p.lower()}" for p in parts if p)

    @property
    def extension(self) -> str:
        """The final extension (``""`` if there is none)."""
        return self.extensions[-1] if self.extensions else ""

    @cached_property
    def detected_type(self) -> FileType | None:
        """The type proven by the file's content, or ``None`` if unidentifiable.

        A crashing sniffer is logged and treated as "unidentifiable", which every
        allow-list rejects (fail closed).
        """
        try:
            return self._sniffer.sniff(self)
        except Exception:
            logger.exception("Sniffer %r crashed on %r", self._sniffer, self.name)
            return None

    @cached_property
    def file_type(self) -> FileType | None:
        """The detected type, narrowed by the extension where content cannot decide.

        Content proves ``text/plain``; a ``.csv`` name may narrow it to ``text/csv``.
        The extension can only ever *refine* the detected type, never contradict it.
        """
        detected = self.detected_type
        if detected is None or not self.extension:
            return detected
        for candidate in types_for_extension(self.extension):
            if candidate.parent == detected.mime:
                return candidate
        return detected

    @cached_property
    def sha256(self) -> str:
        digest = hashlib.sha256()
        for chunk in self.iter_chunks():
            digest.update(chunk)
        return digest.hexdigest()

    # -- internals --------------------------------------------------------------------

    def _measure(self) -> int:
        end = self._stream.seek(0, io.SEEK_END)
        self._stream.seek(self._origin)
        return end


def _ensure_seekable(stream: IO[bytes]) -> IO[bytes]:
    if stream.seekable():
        return stream
    spooled = tempfile.SpooledTemporaryFile(max_size=8 * MiB)  # noqa: SIM115 - returned to caller
    shutil.copyfileobj(stream, spooled)
    spooled.seek(0)
    return cast("IO[bytes]", spooled)
