"""Script-capable markup (SVG) and code or polyglot payloads hidden in media files."""

from __future__ import annotations

import html
import re
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from uploadshield.core.check import Check
from uploadshield.core.types import GiB, MiB
from uploadshield.core.upload import ContentTooLargeError
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["EmbeddedContent", "SvgActiveContent"]

# "<" cannot occur inside an XML attribute value, so "<[^<]*" spans a whole start tag -
# also when an attribute value contains ">" - and the scan stays linear.
_SVG_RULES: dict[str, re.Pattern[str]] = {
    "script element": re.compile(r"<\s*(?:[a-z0-9_-]+:)?script\b"),
    "script URI": re.compile(r"(?:java|vb)script:|data:text/html"),
    "foreignObject": re.compile(r"<\s*(?:[a-z0-9_-]+:)?foreignobject\b"),
    "embedded document": re.compile(r"<\s*(?:iframe|embed|object|frame)\b"),
    "entity declaration": re.compile(r"<!entity|<!doctype[^<]*\["),
    "XSLT stylesheet": re.compile(r"<\?xml-stylesheet"),
    "external resource": re.compile(r"href\s*=\s*[\"']?\s*(?:https?:)?//"),
    "href animation": re.compile(
        r"<\s*(?:set|animate)\b[^<]*attributename\s*=\s*[\"']?(?:xlink:)?href"
    ),
}
#: An ``on...=`` attribute inside a start tag.  Attribute values are skipped as quoted
#: strings, so a ">" inside a value does not end the tag, while text after the tag is
#: never mistaken for an attribute.  Matched on the text *before* character references
#: are decoded: "&quot;>" inside a value must not look like the end of the tag.  Every
#: part stops at "<", ">" or a quote, so the scan stays linear.
_EVENT_HANDLER = re.compile(
    r"<[a-z][^\s/<>]*"
    r"(?:[\s/]+[^\s/<>=\"']+(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s<>\"']*))?)*?"
    r"(?:[\s/]+|(?<=[\"']))on[a-z]+\s*="
)
_URL_INVISIBLES = re.compile(r"[\t\n\r\x00]")


def _decode_markup(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace").lower()
    return data.decode("utf-8", "replace").lower()


def _normalize_markup(text: str) -> str:
    # Browsers decode character references and ignore tabs/newlines inside URLs, so
    # "&#106;ava&#x09;script:" must be seen as "javascript:".
    return _URL_INVISIBLES.sub("", html.unescape(text)).lower()


@dataclass(frozen=True, slots=True)
class SvgActiveContent(Check):
    """Refuse SVG images that can run script or load external resources.

    SVG is XML that browsers execute like HTML; when served from your origin it is a
    stored-XSS vector.  Prefer rasterising user SVGs; if you accept them, this check
    rejects scripts, event handlers, ``javascript:`` URIs, ``foreignObject``,
    entities (XXE), XSLT and external references.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "svg"

    max_bytes: int = 10 * MiB

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and file.file_type.mime == "image/svg+xml"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        raw = _decode_markup(file.read(self.max_bytes))
        text = _normalize_markup(raw)
        found = [label for label, rule in _SVG_RULES.items() if rule.search(text)]
        if _EVENT_HANDLER.search(raw):
            found.insert(0, "event handler attribute")
        if found:
            yield self.violation(
                Code.SVG_ACTIVE_CONTENT, "The SVG image contains active content.", found=found
            )


# Markers specific enough that they do not occur by chance in compressed media data
# (a 3-byte "<?=" alone would, about once per 20 MB): PHP open and short-echo tags,
# HTML scripts, JSP/ASP directives, server-side includes and PHAR stubs (polyglot
# images that PHP deserializes through phar://).
_CODE_MARKERS = re.compile(
    rb"<\?php\s|<\?=\s{0,3}(?:[$`]|[a-z_]\w{0,30}\s*\()|<script[\s>]"
    rb"|<%@\s*(?:page|language|import)\b|<jsp:"
    rb"|<!--\s*#\s*(?:exec|include|echo|config|set|printenv)\b"
    rb"|__halt_compiler\s*\(\s*\)",
    re.IGNORECASE,
)
#: What a PHP ``include`` runs from *any* file, text included: open and short-echo tags.
_INCLUDABLE_CODE = re.compile(rb"<\?php\s|<\?=\s{0,3}(?:[$`]|[a-z_]\w{0,30}\s*\()", re.IGNORECASE)
_OVERLAP = 64
_EOCD = b"PK\x05\x06"
_CENTRAL_DIRECTORY = b"PK\x01\x02"
_EOCD_SEARCH_WINDOW = 65_557  # 22-byte record + maximum comment length


def _embedded_zip_offset(tail: bytes) -> int | None:
    """Locate a *structurally valid* ZIP end record (not just its 4 magic bytes)."""
    pos = tail.rfind(_EOCD)
    while pos != -1:
        if pos + 22 <= len(tail):
            disk, cd_disk, on_disk, total, cd_size = struct.unpack_from("<HHHHI", tail, pos + 4)
            cd_start = pos - cd_size
            if (
                disk == 0
                and cd_disk == 0
                and on_disk == total
                and total > 0
                and cd_start >= 0
                and tail[cd_start : cd_start + 4] == _CENTRAL_DIRECTORY
            ):
                return pos
        pos = tail.rfind(_EOCD, 0, pos)
    return None


@dataclass(frozen=True, slots=True)
class EmbeddedContent(Check):
    """Refuse files that smuggle server-side code or a second file format.

    In media it catches the classic "PHP in EXIF comment" image, HTML/script payloads
    and polyglots: an image with a ZIP appended (GIFAR), or a PDF header hidden near the
    start where PDF readers still find it.  In text files (``scan_text``) it refuses PHP
    tags anywhere, because PHP's ``include`` runs them from a ``.txt`` or ``.csv`` too.
    Files larger than ``max_scan_bytes`` are refused rather than scanned in part.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "embedded"

    categories: frozenset[str] = frozenset({"image", "audio", "video"})
    scan_text: bool = True
    max_scan_bytes: int = 1 * GiB

    def applies(self, file: InspectedFile) -> bool:
        file_type = file.file_type
        if file_type is None:
            return False
        if file_type.is_text:
            return self.scan_text
        return file_type.category in self.categories

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        if file.size > self.max_scan_bytes:
            raise ContentTooLargeError(f"{file.size} bytes exceeds {self.max_scan_bytes}")
        text = file.file_type is not None and file.file_type.is_text
        if marker := self._find_code(file, _INCLUDABLE_CODE if text else _CODE_MARKERS):
            yield self.violation(
                Code.EMBEDDED_CODE, "The file contains embedded code.", marker=marker
            )
            return
        if text:
            return
        if b"%PDF-" in file.head(1024):
            yield self.violation(Code.POLYGLOT, "The file also contains a PDF document.")
        elif _embedded_zip_offset(file.tail(_EOCD_SEARCH_WINDOW)) is not None:
            yield self.violation(Code.POLYGLOT, "The file also contains a ZIP archive.")

    @staticmethod
    def _find_code(file: InspectedFile, markers: re.Pattern[bytes]) -> str | None:
        carry = b""
        for chunk in file.iter_chunks():
            window = carry + chunk
            if match := markers.search(window):
                return match.group(0).decode("latin-1").strip()
            carry = window[-_OVERLAP:]
        return None
