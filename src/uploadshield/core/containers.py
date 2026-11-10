"""Shared, cached access to container formats (ZIP) used by several checks.

The central directory is parsed once per upload and kept in ``InspectedFile.cache``
together with an index of member offsets.  Every helper below then costs only the
member it reads: documents with thousands of parts are walked in linear time.
"""

from __future__ import annotations

import bisect
import struct
import zipfile
import zlib
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    import re

    from .upload import InspectedFile

__all__ = ["ZIP_ERRORS", "zip_entries", "zip_head", "zip_member", "zip_read", "zip_search"]

ZIP_ERRORS = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    OSError,
    ValueError,
    EOFError,
    NotImplementedError,
    KeyError,
    RuntimeError,
    zlib.error,
    struct.error,
)

_LOCAL_HEADER = 30
_CHUNK = 1024 * 1024


class _Archive:
    """An open ZIP over the upload's stream, its members by name and an offset index."""

    def __init__(self, stream: IO[bytes]) -> None:
        self.zip = zipfile.ZipFile(stream)
        self.entries = self.zip.infolist()
        self.by_name = {e.filename: e for e in self.entries}
        self.offsets = sorted(e.header_offset for e in self.entries)

    def overlaps(self, info: zipfile.ZipInfo) -> bool:
        """Whether another member starts inside ``info``'s data (overlapping-entry bombs)."""
        end = info.header_offset + _LOCAL_HEADER + len(info.filename.encode()) + info.compress_size
        index = bisect.bisect_right(self.offsets, info.header_offset)
        duplicate_start = index >= 2 and self.offsets[index - 2] == info.header_offset
        return duplicate_start or (index < len(self.offsets) and self.offsets[index] < end)


def _archive(file: InspectedFile) -> _Archive | None:
    key = "zip.archive"
    if key not in file.cache:
        try:
            with file.open() as fh:
                file.cache[key] = _Archive(fh)
        except ZIP_ERRORS:
            file.cache[key] = None
    return file.cache[key]


def zip_entries(file: InspectedFile) -> list[zipfile.ZipInfo] | None:
    """The central-directory listing, or ``None`` if the file is not a readable ZIP."""
    archive = _archive(file)
    return archive.entries if archive is not None else None


def _member(file: InspectedFile, member: str) -> tuple[_Archive, zipfile.ZipInfo] | None:
    archive = _archive(file)
    if archive is None or (info := archive.by_name.get(member)) is None:
        return None
    return None if archive.overlaps(info) else (archive, info)


def zip_member(file: InspectedFile, member: str) -> zipfile.ZipInfo | None:
    """A member that can be read safely (exists, does not overlap another one)."""
    found = _member(file, member)
    return found[1] if found is not None else None


def _read(file: InspectedFile, member: str, length: int) -> bytes | None:
    if (found := _member(file, member)) is None:
        return None
    archive, info = found
    try:
        with file.open(), archive.zip.open(info) as stream:
            return stream.read(length)
    except ZIP_ERRORS:
        return None


def zip_head(file: InspectedFile, member: str, length: int) -> bytes | None:
    """The first ``length`` uncompressed bytes of a member (``None`` if unreadable)."""
    return _read(file, member, length)


def zip_search(
    file: InspectedFile, member: str, pattern: re.Pattern[bytes], *, overlap: int = 4096
) -> bool:
    """Whether ``pattern`` occurs in a member, streamed in chunks (members may be large)."""
    if (found := _member(file, member)) is None:
        return False
    archive, info = found
    carry = b""
    try:
        with file.open(), archive.zip.open(info) as stream:
            while chunk := stream.read(_CHUNK):
                window = carry + chunk
                if pattern.search(window):
                    return True
                carry = window[-overlap:]
    except ZIP_ERRORS:
        return False
    return False


def zip_read(file: InspectedFile, member: str, limit: int) -> bytes | None:
    """Read one member, decompressing at most ``limit`` bytes.

    Returns ``None`` if the member is missing, unreadable, larger than ``limit``, or
    overlaps another entry (such archives are refused by ``ArchiveSafety``; reading
    them would also make :mod:`zipfile` emit warnings).
    """
    data = _read(file, member, limit + 1)
    return None if data is None or len(data) > limit else data
