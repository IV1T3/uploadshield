"""Content-based file type detection ("sniffing").

The only trustworthy evidence about an upload is its bytes.  A :class:`Sniffer` maps
content to a registered :class:`~uploadshield.core.types.FileType` or returns
``None`` when the content cannot be positively identified - unidentified content is
never guessed from the client-supplied name or ``Content-Type``.

Short magic numbers (``BM``, ``MZ``, ...) are verified with additional header fields so
that ordinary text does not get misclassified as a binary format.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ._deconstruct import Deconstructible
from .containers import zip_entries, zip_read
from .types import FileType, get_type

if TYPE_CHECKING:
    from .upload import InspectedFile

__all__ = ["BuiltinSniffer", "ChainedSniffer", "MagicSniffer", "Sniffer", "is_binary"]


@runtime_checkable
class Sniffer(Protocol):
    """Anything that can identify a file's type from its content."""

    def sniff(self, file: InspectedFile) -> FileType | None: ...


# --------------------------------------------------------------------------- #
# Text / binary classification (after the WHATWG MIME Sniffing Standard)
# --------------------------------------------------------------------------- #

#: Bytes that never occur in text (WHATWG "binary data byte").
_BINARY_BYTES = bytes([*range(0x00, 0x09), 0x0B, *range(0x0E, 0x1B), *range(0x1C, 0x20)])
_TEXT_BYTES = bytes(b for b in range(256) if b not in _BINARY_BYTES)

#: Tag openings that make browsers render a resource as HTML.
_HTML_OPENERS = re.compile(
    rb"^(?:<!doctype\s+html|<html|<head|<script|<iframe|<h1|<div|<font|<table|<a|<style"
    rb"|<title|<b|<body|<br|<p|<!--)(?:[\s>]|$)",
)
_WHITESPACE = b" \t\r\n\f"
_ELEMENT_NAME = re.compile(rb"<([a-z_][a-z0-9_.:-]*)")
_DOCTYPE_NAME = re.compile(rb"<!doctype\s+([a-z_][a-z0-9_.:-]*)")


def _root_element(text: bytes) -> tuple[bytes | None, bytes | None]:
    """Return ``(doctype_name, root_element_name)`` of a markup document head."""
    doctype: bytes | None = None
    rest = text.lstrip(_WHITESPACE)
    while rest.startswith(b"<?") or rest.startswith(b"<!"):
        if rest.startswith(b"<!--"):
            end = rest.find(b"-->")
            skip = end + 3
        elif rest.startswith(b"<?"):
            end = rest.find(b"?>")
            skip = end + 2
        else:
            if match := _DOCTYPE_NAME.match(rest):
                doctype = match.group(1)
            end = rest.find(b">")
            skip = end + 1
        if end == -1:
            return doctype, None
        rest = rest[skip:].lstrip(_WHITESPACE)
    match = _ELEMENT_NAME.match(rest)
    root = match.group(1).rsplit(b":", 1)[-1] if match else None
    return doctype, root


def is_binary(data: bytes) -> bool:
    """Whether ``data`` contains bytes that never appear in text."""
    return bool(data.translate(None, _TEXT_BYTES))


def _decode_text_head(head: bytes) -> bytes | None:
    """Return a lowercase, BOM-free, ASCII-compatible view of a text head or ``None``."""
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        codec = "utf-16-le" if head.startswith(b"\xff\xfe") else "utf-16-be"
        body = head[2:]
        body = body[: len(body) - (len(body) % 2)]
        try:
            text = body.decode(codec)
        except UnicodeDecodeError:
            return None
        encoded = text.encode("utf-8", "replace")
        return None if is_binary(encoded) else encoded.lower()
    head = head.removeprefix(b"\xef\xbb\xbf")
    return None if is_binary(head) else head.lower()


def _classify_text(head: bytes) -> str | None:
    text = _decode_text_head(head)
    if text is None:
        return None
    start = text.lstrip(_WHITESPACE)
    if start.startswith((b"<?php", b"<?=")):
        return "application/x-httpd-php"
    if start.startswith(b"#!"):
        return "application/x-sh"
    if not start.startswith(b"<"):
        return "text/plain"
    doctype, root = _root_element(start)
    if b"svg" in (doctype, root):
        return "image/svg+xml"
    if b"html" in (doctype, root) or _HTML_OPENERS.match(start):
        return "text/html"
    if start.startswith(b"<?xml"):
        return "application/xml"
    return "text/plain"


# --------------------------------------------------------------------------- #
# Binary signatures
# --------------------------------------------------------------------------- #

_PREFIXES: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"%PDF-", "application/pdf"),
    (b"{\\rtf", "application/rtf"),
    (b"%!PS", "application/postscript"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"\x1f\x8b\x08", "application/gzip"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"fLaC", "audio/flac"),
    (b"OggS\x00", "audio/ogg"),
    (b"\x7fELF", "application/x-elf"),
    (b"\x00asm", "application/wasm"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
    (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    (b"\x00\x00\x01\xba", "video/mpeg"),
    (b"\x00\x00\x01\xb3", "video/mpeg"),
)

_RIFF_FORMS = {b"WEBP": "image/webp", b"WAVE": "audio/wav", b"AVI ": "video/x-msvideo"}

_FTYP_BRANDS = {
    b"avif": "image/avif",
    b"avis": "image/avif",
    b"heic": "image/heic",
    b"heix": "image/heic",
    b"heim": "image/heic",
    b"heis": "image/heic",
    b"hevc": "image/heic",
    b"hevx": "image/heic",
    b"M4A ": "audio/mp4",
    b"M4B ": "audio/mp4",
    b"qt  ": "video/quicktime",
    b"3gp4": "video/3gpp",
    b"3gp5": "video/3gpp",
    b"3gp6": "video/3gpp",
    b"3g2a": "video/3gpp",
    b"isom": "video/mp4",
    b"iso2": "video/mp4",
    b"iso4": "video/mp4",
    b"iso5": "video/mp4",
    b"iso6": "video/mp4",
    b"mp41": "video/mp4",
    b"mp42": "video/mp4",
    b"avc1": "video/mp4",
    b"dash": "video/mp4",
    b"M4V ": "video/mp4",
    b"MSNV": "video/mp4",
    b"f4v ": "video/mp4",
}

_BMP_DIB_HEADER_SIZES = {12, 40, 52, 56, 64, 108, 124}


def _sniff_bmp(head: bytes) -> str | None:
    if len(head) < 18 or head[:2] != b"BM":
        return None
    reserved = head[6:10]
    (dib_size,) = struct.unpack_from("<I", head, 14)
    return "image/bmp" if reserved == b"\x00" * 4 and dib_size in _BMP_DIB_HEADER_SIZES else None


def _sniff_ico(head: bytes) -> str | None:
    if len(head) < 22 or head[:4] != b"\x00\x00\x01\x00":
        return None
    (count,) = struct.unpack_from("<H", head, 4)
    reserved = head[9]
    (planes,) = struct.unpack_from("<H", head, 10)
    size, offset = struct.unpack_from("<II", head, 14)
    if count and reserved == 0 and planes in (0, 1) and size and offset >= 6 + 16 * count:
        return "image/vnd.microsoft.icon"
    return None


def _sniff_riff(head: bytes) -> str | None:
    if head[:4] != b"RIFF" or len(head) < 12:
        return None
    return _RIFF_FORMS.get(head[8:12])


def _sniff_ftyp(head: bytes) -> str | None:
    if len(head) < 12 or head[4:8] != b"ftyp":
        return None
    (box_size,) = struct.unpack_from(">I", head, 0)
    brands = [head[8:12]]
    end = min(box_size, len(head))
    brands += [head[i : i + 4] for i in range(16, end - 3, 4)]
    # AVIF/HEIC files often use the generic 'mif1' major brand; look at compatibles.
    for brand in brands:
        if brand in (b"avif", b"avis"):
            return "image/avif"
    for brand in brands:
        if brand in _FTYP_BRANDS:
            return _FTYP_BRANDS[brand]
    return None


def _sniff_ebml(head: bytes) -> str | None:
    if head[:4] != b"\x1a\x45\xdf\xa3":
        return None
    window = head[:4096]
    if b"webm" in window:
        return "video/webm"
    if b"matroska" in window:
        return "video/x-matroska"
    return None


def _sniff_tar(head: bytes) -> str | None:
    return "application/x-tar" if head[257:262] == b"ustar" else None


def _sniff_bzip2(head: bytes) -> str | None:
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[3:4] != b"0":
        block = head[4:10]
        if block in (b"\x31\x41\x59\x26\x53\x59", b"\x17\x72\x45\x38\x50\x90"):
            return "application/x-bzip2"
    return None


def _sniff_id3_or_mpeg_audio(head: bytes) -> str | None:
    if head[:3] == b"ID3" and len(head) >= 10 and head[3] in (2, 3, 4) and head[4] != 0xFF:
        return "audio/mpeg"
    if len(head) < 4 or head[0] != 0xFF or (head[1] & 0xE0) != 0xE0:
        return None
    version = (head[1] >> 3) & 0x03
    layer = (head[1] >> 1) & 0x03
    bitrate = head[2] >> 4
    sample_rate = (head[2] >> 2) & 0x03
    if layer == 0 and (head[1] & 0xF6) == 0xF0:  # ADTS (AAC) shares the sync word
        return "audio/aac"
    if version == 1 or layer == 0 or bitrate in (0, 0x0F) or sample_rate == 0x03:
        return None
    return "audio/mpeg"


def _sniff_cafebabe(head: bytes) -> str | None:
    if head[:4] != b"\xca\xfe\xba\xbe" or len(head) < 8:
        return None
    (value,) = struct.unpack_from(">I", head, 4)
    # Mach-O universal binaries store a small architecture count here; Java class
    # files store (minor << 16 | major) where major >= 45.
    return "application/x-mach-binary" if value < 45 else "application/java-vm"


def _sniff_mz(head: bytes, file: InspectedFile) -> str | None:
    if head[:2] != b"MZ":
        return None
    if len(head) >= 0x40:
        (pe_offset,) = struct.unpack_from("<I", head, 0x3C)
        if pe_offset + 4 <= min(file.size, 1 << 20):
            window = file.head(pe_offset + 4)
            if window[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                return "application/vnd.microsoft.portable-executable"
    # A DOS "MZ" executable without a PE header is still an executable, unless the
    # content is plainly text that merely starts with the letters "MZ".
    return "application/vnd.microsoft.portable-executable" if is_binary(head) else None


_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_ODF_MIMETYPES = {
    mime.encode(): mime
    for mime in (
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
        "application/epub+zip",
    )
}

_OOXML_MAIN_PARTS = (
    (
        b"application/vnd.ms-word.document.macroenabled.main+xml",
        "application/vnd.ms-word.document.macroenabled.12",
    ),
    (
        b"application/vnd.ms-excel.sheet.macroenabled.main+xml",
        "application/vnd.ms-excel.sheet.macroenabled.12",
    ),
    (
        b"application/vnd.ms-powerpoint.presentation.macroenabled.main+xml",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    ),
    (
        b"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (
        b"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (
        b"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
)


def _sniff_zip(head: bytes, file: InspectedFile) -> str | None:
    if head[:4] not in _ZIP_SIGNATURES:
        return None
    entries = zip_entries(file)
    if not entries:
        return "application/zip"
    names = {e.filename for e in entries}
    if entries[0].filename == "mimetype":
        declared = (zip_read(file, "mimetype", 256) or b"").strip()
        if declared in _ODF_MIMETYPES:
            return _ODF_MIMETYPES[declared]
    if "[Content_Types].xml" in names:
        content_types = (zip_read(file, "[Content_Types].xml", 1 << 20) or b"").lower()
        for marker, mime in _OOXML_MAIN_PARTS:
            if marker in content_types:
                return mime
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return "application/vnd.android.package-archive"
    if "META-INF/MANIFEST.MF" in names:
        return "application/java-archive"
    return "application/zip"


_HeadDetector = Callable[[bytes], "str | None"]
_FileDetector = Callable[[bytes, "InspectedFile"], "str | None"]

_HEAD_DETECTORS: tuple[_HeadDetector, ...] = (
    _sniff_riff,
    _sniff_ftyp,
    _sniff_ebml,
    _sniff_bmp,
    _sniff_ico,
    _sniff_bzip2,
    _sniff_id3_or_mpeg_audio,
    _sniff_cafebabe,
    _sniff_tar,
)
_FILE_DETECTORS: tuple[_FileDetector, ...] = (_sniff_zip, _sniff_mz)


@dataclass(frozen=True, slots=True)
class BuiltinSniffer(Deconstructible):
    """Pure-Python signature sniffer covering the formats in the type registry."""

    _deconstruct_module = "uploadshield.core.sniffing"

    def sniff(self, file: InspectedFile) -> FileType | None:
        head = file.head()
        if not head:
            return None
        mime = self._sniff_mime(head, file)
        return get_type(mime) if mime else None

    @staticmethod
    def _sniff_mime(head: bytes, file: InspectedFile) -> str | None:
        for prefix, mime in _PREFIXES:
            if head.startswith(prefix):
                return mime
        # A UTF-16 BOM (FF FE) doubles as an MPEG audio frame sync; text wins.
        if head.startswith((b"\xff\xfe", b"\xfe\xff")) and (text := _classify_text(head)):
            return text
        for file_detector in _FILE_DETECTORS:
            if mime := file_detector(head, file):
                return mime
        for detector in _HEAD_DETECTORS:
            if mime := detector(head):
                return mime
        return _classify_text(head)


@dataclass(frozen=True, slots=True)
class MagicSniffer(Deconstructible):
    """Identify types with libmagic (``uv add "uploadshield[magic]"``).

    Best used as a fallback after :class:`BuiltinSniffer` via :class:`ChainedSniffer`.
    Results that do not map to a registered type are treated as unidentified.
    """

    _deconstruct_module = "uploadshield.core.sniffing"
    head_size: int = 64 * 1024

    def sniff(self, file: InspectedFile) -> FileType | None:
        import magic

        mime = magic.from_buffer(file.head(self.head_size), mime=True)
        return get_type(mime) if isinstance(mime, str) else None


@dataclass(frozen=True, slots=True)
class ChainedSniffer(Deconstructible):
    """Try several sniffers in order; the first positive identification wins."""

    _deconstruct_module = "uploadshield.core.sniffing"
    sniffers: tuple[Sniffer, ...]

    def sniff(self, file: InspectedFile) -> FileType | None:
        for sniffer in self.sniffers:
            if (found := sniffer.sniff(file)) is not None:
                return found
        return None
