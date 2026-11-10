"""Safety of archives: ZIP containers (plain archives and ZIP-based formats such as OOXML,
ODF and EPUB) and tar archives, plain or compressed with gzip, bzip2 or xz."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import stat
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import IO, TYPE_CHECKING, NoReturn, Self, cast

from uploadshield.core.check import Check
from uploadshield.core.containers import ZIP_ERRORS
from uploadshield.core.types import GiB, MiB
from uploadshield.core.violations import Code, Violation

from .basic import DANGEROUS_EXTENSIONS, DANGEROUS_NAMES, extension_segments

if TYPE_CHECKING:
    from collections.abc import Iterator
    from tarfile import TarFile

    from uploadshield.core.types import FileType
    from uploadshield.core.upload import InspectedFile

__all__ = ["ArchiveSafety"]

_DRIVE = re.compile(r"^[a-zA-Z]:")
_LOCAL_HEADER = b"PK\x03\x04"
_LOCAL_HEADER_SIZE = 30
_READ_CHUNK = 1 * MiB
_INFLATE_CHUNK = 1 * MiB
#: Enough of a stream to tell which archive it starts ("ustar" sits at offset 257).
_SNIFF_BYTES = 512
#: The formats opened besides ZIP containers, by the MIME type detected from content.
_FORMATS = {
    "application/x-tar": "tar",
    "application/gzip": "gzip",
    "application/x-bzip2": "bzip2",
    "application/x-xz": "xz",
}
#: What reading a damaged tar archive or compressed stream raises.
_STREAM_ERRORS = (*ZIP_ERRORS, tarfile.TarError, lzma.LZMAError)


def _dangerous_member(name: str) -> bool:
    """A member that servers would execute or obey once the archive is extracted.

    Judged as extractors write it: tarfile stores a *regular* member named
    ``shell.php/`` as the file ``shell.php`` (Windows also drops a trailing ``\\``).
    """
    basename = name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
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


def _special(member: tarfile.TarInfo) -> bool:
    """Links, devices and FIFOs: extracting them writes outside the archive's files."""
    return member.issym() or member.islnk() or member.isdev()


def _format(file_type: FileType | None) -> str | None:
    if file_type is None:
        return None
    return "zip" if file_type.container == "zip" else _FORMATS.get(file_type.mime)


def _archive_kind(head: bytes) -> str | None:
    """The format of the archive that ``head`` starts, among those this check opens."""
    if head.startswith(_LOCAL_HEADER):
        return "zip"
    if head.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    if head.startswith(b"BZh") and head[3:4].isdigit() and head[3:4] != b"0":
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if _tar_header_at(head, 0):  # what tar readers check; the "ustar" magic is optional
        return "tar"
    return None


def _tar_header_at(data: bytes, start: int) -> bool:
    """Whether tar readers accept the 512 bytes at ``start`` as a header: its checksum
    field holds the block's sum.  Old (V7) archives have no ``ustar`` magic, and GNU tar
    skips data until it finds such a block, so the checksum is what counts."""
    if len(data) < start + 512:
        return False
    digits = data[start + 148 : start + 156].split(b"\x00", 1)[0].strip(b" ")
    if not digits or digits.strip(b"01234567"):  # cheap: most blocks fail here
        return False
    block = data[start : start + 512]
    unsigned = 256 + sum(block[:148]) + sum(block[156:])  # the field counts as spaces
    signed = 256 + sum(struct.unpack_from("148b8x356b", block))
    return int(digits, 8) in (unsigned, signed)


def _decompressor(kind: str, fh: IO[bytes]) -> io.BufferedIOBase:
    if kind == "gzip":
        return gzip.GzipFile(fileobj=fh, mode="rb")
    if kind == "bzip2":
        return bz2.BZ2File(fh)
    return lzma.LZMAFile(fh, format=lzma.FORMAT_XZ)


def _at(member: str | None) -> dict[str, str]:
    """The ``member`` detail, for violations that concern a member, not the upload."""
    return {"member": member} if member else {}


class _Stop(Exception):  # noqa: N818 - control flow, not an error
    """The walk found enough to refuse the archive."""


class _DamagedHeader(tarfile.ReadError):
    """A tar header that cannot be read: another extractor may read a member there."""


#: tarfile's signals for a zero block and for the end of the stream.  Not in
#: ``tarfile.__all__`` (nor in typeshed), but unchanged since Python 3.2.
_END_OF_HEADERS: tuple[type[Exception], ...] = (
    tarfile.EOFHeaderError,  # ty: ignore[unresolved-attribute]
    tarfile.EmptyHeaderError,  # ty: ignore[unresolved-attribute]
)
_HEADER_ERROR = tarfile.HeaderError


class _Header(tarfile.TarInfo):
    """Tar headers, read so that only zero blocks are skipped.

    The walk reads with ``ignore_zeros`` to find members hidden after an
    end-of-archive marker; tarfile would then also skip *damaged* headers without a
    word, and a lenient extractor may extract a member from one.  Those end the walk.
    """

    __slots__ = ()

    @classmethod
    def fromtarfile(cls, tarfile: TarFile) -> Self:
        try:
            return super().fromtarfile(tarfile)
        except _END_OF_HEADERS:
            raise  # a zero block, or the end of the stream
        except _HEADER_ERROR as exc:
            raise _DamagedHeader(str(exc)) from None


@dataclass(frozen=True, slots=True)
class ArchiveSafety(Check):
    """Refuse archive bombs, path traversal ("zip slip"), links, encrypted members, and
    members that servers would execute or obey once extracted (``shell.php``,
    ``.htaccess``; ``check_member_names=False`` to allow them).

    It opens ZIP containers (plain archives, OOXML, ODF, EPUB, JAR, APK) and tar
    archives, plain or compressed with gzip, bzip2 or xz; a gzip, bzip2 or xz file that
    holds no archive is measured like a member, and refused if a tar header hides
    further in (tar skips to it).  Tar is recognised by its header checksum, as tar
    readers do, so old archives without the ``ustar`` magic count.  7-Zip and RAR are
    not opened
    (:data:`~uploadshield.checks.UNINSPECTED_ARCHIVES`).

    Sizes are *measured*, not taken from the headers (OWASP: "secure ZIP size
    calculation"): every member is inflated as a stream - nothing is stored - and must
    expand to exactly the size and CRC its header declares.  A header that understates
    the size is refused as soon as the extra byte appears, so lying archives cost no more
    than they claim.  Compressed tar archives are measured as they decompress, against
    the same budget and ratio.  Archives inside archives (``42.zip``, documents embedded
    in documents, ``site.zip`` inside ``backup.tar.gz``) are walked the same way up to
    ``max_depth`` levels, sharing one entry and byte budget.

    For ZIP, the cheap declared-size checks still run first, from the central directory
    alone: entry count, total size, compression ratio and *overlapping entries* (the
    trick behind non-recursive bombs).  ``verify_sizes=False`` restores that header-only
    mode for ZIP; tar archives keep their headers inside the stream, so they are always
    read through.  Tar members hidden behind an end-of-archive marker are judged too, as
    ``tar --ignore-zeros`` would extract them; a damaged tar header is refused.
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
        return _format(file.file_type) is not None

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        kind = _format(file.file_type)
        if kind is None:
            return
        walk = _Walk(self)
        try:
            with file.open() as fh:
                walk.open(fh, kind, file.size, depth=0, prefix="")
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

    def open(
        self,
        fh: IO[bytes],
        kind: str,
        size: int,
        *,
        depth: int,
        prefix: str,
        member: str | None = None,
        inner: bool = False,
    ) -> None:
        """Walk an archive of ``kind``: the upload, or one found ``inner`` another."""
        try:
            if kind == "zip":
                try:
                    zf = zipfile.ZipFile(fh)
                except ZIP_ERRORS:
                    if inner:
                        return  # starts like a ZIP but is none: an ordinary member
                    raise
                with zf:
                    self.archive(zf, fh, size, depth=depth, prefix=prefix)
            elif kind == "tar":
                self.tar(fh, depth=depth, prefix=prefix)
            else:
                self.stream(fh, kind, size, depth=depth, prefix=prefix)
        except _STREAM_ERRORS:
            self.stop(Code.ARCHIVE_CORRUPT, "The archive is damaged or unreadable.", **_at(member))

    def nested(
        self, data: bytes, kind: str, *, depth: int, prefix: str, member: str | None
    ) -> None:
        """Walk an archive found inside another one, at nesting level ``depth``."""
        if depth > self.check.max_depth:
            self.stop(
                Code.ARCHIVE_BOMB, "The archive contains too many nested archives.", **_at(member)
            )
        stream = io.BytesIO(data)
        self.open(stream, kind, len(data), depth=depth, prefix=prefix, member=member, inner=True)

    def tar(self, stream: IO[bytes], *, depth: int, prefix: str) -> None:
        """Walk a tar archive member by member, in one pass, as an extractor reads it.

        ``ignore_zeros`` reads on past end-of-archive markers, the way
        ``tar --ignore-zeros`` extracts, so that no member can hide behind one; a damaged
        header ends the walk instead (:class:`_Header`).
        """
        check = self.check
        unsafe: list[str] = []
        dangerous: list[str] = []
        try:
            with tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True, tarinfo=_Header) as tf:
                for info in tf:
                    if info.size < 0:  # a size that would send the reader backwards
                        raise tarfile.HeaderError("negative member size")
                    self.entries += 1
                    self.declared += info.size  # sparse members count at their full size
                    if (
                        self.entries > check.max_entries
                        or self.declared > check.max_uncompressed_bytes
                    ):
                        self.stop(
                            Code.ARCHIVE_BOMB,
                            "The archive expands to an unsafe size.",
                            entries=self.entries,
                            uncompressed=self.declared,
                            archive=prefix.removesuffix("/") or None,
                        )
                    name = prefix + info.name
                    if _unsafe_path(info.name) or _special(info):
                        unsafe.append(name)
                    if info.isdir():
                        continue
                    if check.check_member_names and _dangerous_member(info.name):
                        dangerous.append(name)
                    if not _special(info):
                        self.tar_member(tf, info, depth=depth, name=name)
        finally:
            # Reported even when the walk stops early: every one of them was seen.
            if unsafe:
                self.note(
                    Code.ARCHIVE_UNSAFE_PATH,
                    "The archive contains unsafe paths or links.",
                    paths=unsafe[:10],
                )
            if dangerous:
                self.note(
                    Code.ARCHIVE_DANGEROUS_MEMBER,
                    "The archive contains files that servers could execute.",
                    members=dangerous[:10],
                )

    def tar_member(
        self, tf: tarfile.TarFile, info: tarfile.TarInfo, *, depth: int, name: str
    ) -> None:
        """Walk a tar member that is itself an archive; skip any other member's data."""
        reader = tf.extractfile(info)
        if reader is None:
            return
        head = reader.read(_SNIFF_BYTES)
        kind = _archive_kind(head)
        if kind is None:
            return
        if info.size > self.check.max_nested_bytes:
            self.stop(
                Code.ARCHIVE_BOMB,
                "The archive contains an archive too large to inspect.",
                member=name,
            )
        data = head + reader.read(info.size - len(head))
        self.nested(data, kind, depth=depth + 1, prefix=f"{name}/", member=name)

    def stream(self, fh: IO[bytes], kind: str, size: int, *, depth: int, prefix: str) -> None:
        """A gzip, bzip2 or xz stream: measured as it decompresses, and walked when it
        holds an archive.  A tar inside is the same archive (``.tar.gz``); any other
        archive inside is nested one level deeper.

        tar readers skip data until they find a header, so ``tar -xzf`` extracts a tar
        archive hidden behind anything else: content that is not walked as tar must not
        hold a header block anywhere.
        """
        label = prefix.removesuffix("/") or None
        with _decompressor(kind, fh) as raw:
            out = _Output(self, raw, compressed=size, archive=label)
            inner = _archive_kind(out.peek(_SNIFF_BYTES))
            if inner == "tar":
                self.tar(cast("IO[bytes]", out), depth=depth, prefix=prefix)
            elif inner is not None:
                data = out.read_up_to(self.check.max_nested_bytes + 1)
                if len(data) > self.check.max_nested_bytes:
                    self.stop(
                        Code.ARCHIVE_BOMB,
                        "The archive contains an archive too large to inspect.",
                        **_at(label),
                    )
                self.hidden_tar(data, end=len(data), offset=0, label=label)
                self.nested(data, inner, depth=depth + 1, prefix=prefix, member=label)
            else:
                offset, rest = 0, b""  # read to the end, measuring it
                while chunk := out.read(_INFLATE_CHUNK):
                    data = rest + chunk
                    end = len(data) - len(data) % 512
                    self.hidden_tar(data, end=end, offset=offset, label=label)
                    offset, rest = offset + end, data[end:]

    def hidden_tar(self, data: bytes, *, end: int, offset: int, label: str | None) -> None:
        """Refuse a tar header among the 512-byte blocks of ``data[:end]``."""
        for start in range(0, end - end % 512, 512):
            if _tar_header_at(data, start):
                self.stop(
                    Code.ARCHIVE_CORRUPT,
                    "The archive is damaged or unreadable.",
                    **_at(label),
                    tar_header_at=offset + start,
                )

    def inflate(self, count: int, *, produced: int, compressed: int, archive: str | None) -> None:
        """Count decompressed bytes; refuse once the budget or the ratio is exceeded."""
        check = self.check
        self.inflated += count
        if self.inflated > check.max_uncompressed_bytes or (
            produced > check.ratio_threshold_bytes and produced > check.max_ratio * compressed
        ):
            self.stop(
                Code.ARCHIVE_BOMB,
                "The archive expands to an unsafe size.",
                archive=archive,
                measured_at_least=produced,
            )

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
            if not could_nest and _starts_as_archive(zf, fh, info):
                self.stop(
                    Code.ARCHIVE_BOMB,
                    "The archive contains an archive too large to inspect.",
                    member=name,
                )
            return
        if kind := _archive_kind(data):  # always set: only archives are kept
            self.nested(data, kind, depth=depth + 1, prefix=f"{name}/", member=name)

    def remaining(self) -> int:
        return self.check.max_uncompressed_bytes - self.inflated


def _starts_as_archive(zf: zipfile.ZipFile, fh: IO[bytes], info: zipfile.ZipInfo) -> bool:
    measured = _inflate(zf, fh, info, limit=_SNIFF_BYTES, keep=True)
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
    ``data`` is kept only if ``keep`` is set *and* the member starts like an archive.
    """
    size, crc = 0, 0
    kept: bytearray | None = bytearray() if keep else None
    sniffed = False
    try:
        start = _data_offset(fh, info)
        if start is None:
            return None
        for piece in _output(zf, fh, info, start):
            size += len(piece)
            crc = zlib.crc32(piece, crc)
            if kept is not None:
                kept += piece
                if not sniffed and len(kept) >= _SNIFF_BYTES:
                    sniffed = True
                    if _archive_kind(bytes(kept[:_SNIFF_BYTES])) is None:
                        kept = None  # not an archive: nothing to keep
            if size >= limit:
                break
    except (*ZIP_ERRORS, EOFError):
        return None
    if kept is not None and not sniffed and _archive_kind(bytes(kept)) is None:
        kept = None  # a short member that is no archive
    return size, crc, bytes(kept) if kept is not None else None


class _Output:
    """A decompressed stream, counted against the walk's budget as it is read."""

    def __init__(
        self, walk: _Walk, source: io.BufferedIOBase, *, compressed: int, archive: str | None
    ) -> None:
        self._walk = walk
        self._source = source
        self._compressed = compressed
        self._archive = archive
        self._pending = b""
        self.produced = 0

    def peek(self, size: int) -> bytes:
        """The next ``size`` bytes (fewer at the end), left to be read again."""
        while len(self._pending) < size and (chunk := self._pull(size - len(self._pending))):
            self._pending += chunk
        return self._pending

    def read(self, size: int) -> bytes:
        if self._pending:
            taken = self._pending[:size]
            self._pending = self._pending[len(taken) :]
            return taken
        return self._pull(size)

    def read_up_to(self, size: int) -> bytes:
        parts: list[bytes] = []
        wanted = size
        while wanted > 0 and (chunk := self.read(wanted)):
            parts.append(chunk)
            wanted -= len(chunk)
        return b"".join(parts)

    def _pull(self, size: int) -> bytes:
        chunk = self._source.read(min(size, _INFLATE_CHUNK))
        self.produced += len(chunk)
        self._walk.inflate(
            len(chunk), produced=self.produced, compressed=self._compressed, archive=self._archive
        )
        return chunk
