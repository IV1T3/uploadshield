"""Safety of ZIP containers - plain archives and ZIP-based formats (OOXML, ODF, EPUB)."""

from __future__ import annotations

import bz2
import io
import re
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import IO, TYPE_CHECKING, NoReturn

from uploadshield.core.check import Check
from uploadshield.core.containers import ZIP_ERRORS
from uploadshield.core.types import GiB, MiB
from uploadshield.core.violations import Code, Violation

from .basic import DANGEROUS_EXTENSIONS, DANGEROUS_NAMES, extension_segments

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["ArchiveSafety"]

_DRIVE = re.compile(r"^[a-zA-Z]:")
_LOCAL_HEADER = b"PK\x03\x04"
_LOCAL_HEADER_SIZE = 30
_READ_CHUNK = 1 * MiB
_INFLATE_CHUNK = 1 * MiB


def _dangerous_member(name: str) -> bool:
    """A member that servers would execute or obey once the archive is extracted."""
    basename = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return basename in DANGEROUS_NAMES or bool(
        set(extension_segments(basename)) & DANGEROUS_EXTENSIONS
    )


def _unsafe_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return (
        normalized.startswith("/")
        or bool(_DRIVE.match(normalized))
        or ".." in PurePosixPath(normalized).parts
        or "\x00" in name
    )


class _Stop(Exception):  # noqa: N818 - control flow, not an error
    """The walk found enough to refuse the archive."""


@dataclass(frozen=True, slots=True)
class ArchiveSafety(Check):
    """Refuse ZIP bombs, path traversal ("zip slip"), symlinks, encrypted members, and
    members that servers would execute or obey once extracted (``shell.php``,
    ``.htaccess``; ``check_member_names=False`` to allow them).

    Sizes are *measured*, not taken from the headers (OWASP: "secure ZIP size
    calculation"): every member is inflated as a stream - nothing is stored - and must
    expand to exactly the size and CRC its header declares.  A header that understates
    the size is refused as soon as the extra byte appears, so lying archives cost no more
    than they claim.  Archives inside archives (``42.zip``, documents embedded in
    documents) are walked the same way up to ``max_depth`` levels, sharing one entry
    and byte budget.

    The cheap declared-size checks still run first, from the central directory alone:
    entry count, total size, compression ratio and *overlapping entries* (the trick
    behind non-recursive bombs).  ``verify_sizes=False`` restores that header-only mode.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "archive"

    max_entries: int = 10_000
    max_uncompressed_bytes: int = 1 * GiB
    max_ratio: int = 100
    ratio_threshold_bytes: int = 10 * MiB
    allow_encrypted: bool = False
    verify_sizes: bool = True
    check_member_names: bool = True
    max_depth: int = 3
    max_nested_bytes: int = 64 * MiB

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and file.file_type.container == "zip"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        walk = _Walk(self)
        try:
            with file.open() as fh:
                try:
                    zf = zipfile.ZipFile(fh)
                except ZIP_ERRORS:
                    walk.stop(Code.ARCHIVE_CORRUPT, "The archive is damaged or unreadable.")
                walk.archive(zf, fh, file.size, depth=0, prefix="")
        except _Stop:
            pass
        yield from walk.found


@dataclass
class _Walk:
    check: ArchiveSafety
    found: list[Violation] = field(default_factory=list)
    entries: int = 0
    declared: int = 0
    inflated: int = 0

    def note(self, code: Code, message: str, **details: object) -> None:
        """Record a violation and keep walking (more problems may follow)."""
        self.found.append(self.check.violation(code, message, **details))

    def stop(self, code: Code, message: str, **details: object) -> NoReturn:
        """Record a violation that ends the walk: nothing after it can be trusted."""
        self.note(code, message, **details)
        raise _Stop

    def archive(
        self, zf: zipfile.ZipFile, fh: IO[bytes], size: int, *, depth: int, prefix: str
    ) -> None:
        check = self.check
        entries = zf.infolist()
        self.entries += len(entries)
        declared = sum(e.file_size for e in entries)
        self.declared += declared
        compressed = sum(e.compress_size for e in entries)
        overlapping = compressed + _LOCAL_HEADER_SIZE * len(entries) > size
        ratio = declared / max(compressed, 1)
        if (
            self.entries > check.max_entries
            or self.declared > check.max_uncompressed_bytes
            or overlapping
            or (declared > check.ratio_threshold_bytes and ratio > check.max_ratio)
        ):
            self.stop(
                Code.ARCHIVE_BOMB,
                "The archive expands to an unsafe size.",
                entries=self.entries,
                uncompressed=self.declared,
                ratio=round(ratio, 1),
                overlapping=overlapping,
                archive=prefix or None,
            )

        unsafe = [prefix + e.filename for e in entries if _unsafe_path(e.filename)]
        links = [prefix + e.filename for e in entries if stat.S_ISLNK(e.external_attr >> 16)]
        if unsafe or links:
            self.note(
                Code.ARCHIVE_UNSAFE_PATH,
                "The archive contains unsafe paths or links.",
                paths=(unsafe + links)[:10],
            )
        if check.check_member_names and (
            dangerous := [
                prefix + e.filename
                for e in entries
                if not e.is_dir() and _dangerous_member(e.filename)
            ]
        ):
            self.note(
                Code.ARCHIVE_DANGEROUS_MEMBER,
                "The archive contains files that servers could execute.",
                members=dangerous[:10],
            )
        encrypted = [e for e in entries if e.flag_bits & 0x1]
        if encrypted and not check.allow_encrypted:
            self.note(
                Code.ARCHIVE_ENCRYPTED,
                "Encrypted archives cannot be checked and are not allowed.",
            )
            return  # their contents cannot be measured
        if not check.verify_sizes:
            return
        for info in entries:
            if info.is_dir() or info.flag_bits & 0x1:
                continue
            self.member(zf, fh, info, depth=depth, prefix=prefix)

    def member(
        self, zf: zipfile.ZipFile, fh: IO[bytes], info: zipfile.ZipInfo, *, depth: int, prefix: str
    ) -> None:
        check = self.check
        name = prefix + info.filename
        could_nest = info.file_size <= check.max_nested_bytes
        limit = min(info.file_size, self.remaining()) + 1
        measured = _inflate(zf, fh, info, limit=limit, keep=could_nest)
        if measured is None:
            self.stop(Code.ARCHIVE_CORRUPT, "The archive is damaged or unreadable.", member=name)
        actual, crc, data = measured
        self.inflated += actual
        if actual > info.file_size or self.inflated > check.max_uncompressed_bytes:
            self.stop(
                Code.ARCHIVE_BOMB,
                "The archive expands to an unsafe size.",
                member=name,
                declared=info.file_size,
                measured_at_least=actual,
            )
        if actual != info.file_size or crc != info.CRC:
            self.stop(Code.ARCHIVE_CORRUPT, "The archive is damaged or unreadable.", member=name)
        if data is None:
            if not could_nest and _starts_as_zip(zf, fh, info):
                self.stop(
                    Code.ARCHIVE_BOMB,
                    "The archive contains an archive too large to inspect.",
                    member=name,
                )
            return
        if depth + 1 > check.max_depth:
            self.stop(
                Code.ARCHIVE_BOMB, "The archive contains too many nested archives.", member=name
            )
        nested = io.BytesIO(data)
        try:
            inner = zipfile.ZipFile(nested)
        except ZIP_ERRORS:
            return  # starts like a ZIP but is none: an ordinary member
        with inner:
            self.archive(inner, nested, len(data), depth=depth + 1, prefix=f"{name}/")

    def remaining(self) -> int:
        return self.check.max_uncompressed_bytes - self.inflated


def _starts_as_zip(zf: zipfile.ZipFile, fh: IO[bytes], info: zipfile.ZipInfo) -> bool:
    measured = _inflate(zf, fh, info, limit=len(_LOCAL_HEADER), keep=True)
    return measured is not None and measured[2] is not None


def _data_offset(fh: IO[bytes], info: zipfile.ZipInfo) -> int | None:
    if info.header_offset < 0:  # a damaged central directory
        return None
    fh.seek(info.header_offset)
    header = fh.read(_LOCAL_HEADER_SIZE)
    if len(header) < _LOCAL_HEADER_SIZE or not header.startswith(_LOCAL_HEADER):
        return None
    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    # Extractors that follow the local header must see the name that was checked:
    # a local "config.php" behind a central "config.txt" is refused like zipfile does.
    local_name = fh.read(name_length)
    encoding = "utf-8" if info.flag_bits & 0x800 else "cp437"
    if local_name.decode(encoding, "replace") != info.orig_filename:
        return None
    return info.header_offset + _LOCAL_HEADER_SIZE + name_length + extra_length


def _compressed(fh: IO[bytes], start: int, length: int) -> Iterator[bytes]:
    fh.seek(start)
    while length > 0:
        chunk = fh.read(min(_READ_CHUNK, length))
        if not chunk:
            raise EOFError("truncated member")
        length -= len(chunk)
        yield chunk


def _output(
    zf: zipfile.ZipFile, fh: IO[bytes], info: zipfile.ZipInfo, start: int
) -> Iterator[bytes]:
    """The member's uncompressed bytes, in bounded pieces, decompressed lazily."""
    chunks = _compressed(fh, start, info.compress_size)
    if info.compress_type == zipfile.ZIP_STORED:
        yield from chunks
    elif info.compress_type == zipfile.ZIP_DEFLATED:
        inflate = zlib.decompressobj(-zlib.MAX_WBITS)
        for chunk in chunks:
            yield inflate.decompress(chunk, _INFLATE_CHUNK)
            while inflate.unconsumed_tail:
                yield inflate.decompress(inflate.unconsumed_tail, _INFLATE_CHUNK)
        yield inflate.flush()
    elif info.compress_type == zipfile.ZIP_BZIP2:
        unbzip = bz2.BZ2Decompressor()
        for chunk in chunks:
            yield unbzip.decompress(chunk, _INFLATE_CHUNK)
            while not unbzip.eof and not unbzip.needs_input:
                yield unbzip.decompress(b"", _INFLATE_CHUNK)
    else:  # LZMA and others: zipfile reads at most the declared size (CRC-checked)
        with zf.open(info) as stream:
            while piece := stream.read(_INFLATE_CHUNK):
                yield piece


def _inflate(
    zf: zipfile.ZipFile, fh: IO[bytes], info: zipfile.ZipInfo, *, limit: int, keep: bool
) -> tuple[int, int, bytes | None] | None:
    """Stream one member: ``(size, crc32, data)``; ``None`` if it cannot be read.

    Decompression stops once ``limit`` bytes came out (callers pass one byte more than
    the member may have), so a lying header is caught without inflating the rest.
    ``data`` is kept only if ``keep`` is set *and* the member starts like a ZIP.
    """
    size, crc = 0, 0
    kept: bytearray | None = bytearray() if keep else None
    try:
        start = _data_offset(fh, info)
        if start is None:
            return None
        for piece in _output(zf, fh, info, start):
            size += len(piece)
            crc = zlib.crc32(piece, crc)
            if kept is not None:
                kept += piece
                if len(kept) >= len(_LOCAL_HEADER) and not kept.startswith(_LOCAL_HEADER):
                    kept = None  # not an archive: nothing to keep
            if size >= limit:
                break
    except (*ZIP_ERRORS, EOFError):
        return None
    return size, crc, bytes(kept) if kept is not None else None
