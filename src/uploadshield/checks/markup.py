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
    # An external resource: @import, or href=/url() pointing at a scheme other than the
    # inert ones (data:, a #fragment, a relative path).  Backslashes are normalised to
    # "/" first, so "url(http:\\e)" reads like "url(http://e)".
    "external resource": re.compile(
        r"@import\b"
        r"|(?:href\s*=|url\()\s*[\"']?\s*(?!data:)(?:[a-z][a-z0-9+.-]*:|//)"
    ),
    "handler element": re.compile(r"<\s*(?:[a-z0-9_-]+:)?handler\b"),
    "CSS expression": re.compile(r"expression\s*\("),
    # SMIL animation that sets href or an on* event-handler attribute at runtime.
    "animated attribute": re.compile(
        r"<\s*(?:set|animate)\b[^<]*attributename\s*=\s*[\"']?(?:xlink:)?(?:href|on[a-z])"
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
_CSS_HEX_ESCAPE = re.compile(r"\\([0-9a-fA-F]{1,6})\s?")
_CSS_ESCAPE = re.compile(r"\\([^\n])")


def _strip_css_comments(text: str) -> str:
    """Remove ``/* ... */`` comments in a single linear pass (a regex with ``.*?`` is
    quadratic when many ``/*`` have no closing ``*/``).  An unterminated comment drops
    the rest, as a CSS parser ignores it."""
    if "/*" not in text:
        return text
    out: list[str] = []
    i = 0
    while (start := text.find("/*", i)) != -1:
        out.append(text[i:start])
        end = text.find("*/", start + 2)
        if end == -1:
            return "".join(out)
        i = end + 2
    out.append(text[i:])
    return "".join(out)


def _decode_markup(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace").lower()
    return data.decode("utf-8", "replace").lower()


def _normalize_markup(text: str) -> str:
    # Browsers decode character references and ignore tabs/newlines inside URLs, so
    # "&#106;ava&#x09;script:" must be seen as "javascript:".  This view keeps ALL of the
    # markup; it never drops content, so a marker is never hidden from the scan.
    return _URL_INVISIBLES.sub("", html.unescape(text)).lower()


def _normalize_css(text: str) -> str:
    # A second view that undoes CSS obfuscation inside <style>: the browser's CSS parser
    # drops comments and decodes "\" escapes, so "expr/**/ession(" and "@im\port" read as
    # "expression(" and "@import".  This view may drop content (an unterminated comment),
    # so it is only ever scanned *in addition* to _normalize_markup, never instead of it.
    # Character references are decoded before and after, and "\" is normalised to "/" so
    # "url(http:\\e)" reads like "url(http://e)".
    text = _strip_css_comments(html.unescape(text))
    text = _CSS_HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _CSS_ESCAPE.sub(r"\1", text)
    text = html.unescape(text).replace("\\", "/")
    return _URL_INVISIBLES.sub("", text).lower()


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
        # The plain view keeps all the markup; the CSS view undoes <style> obfuscation but
        # may drop content, so a rule fires on a match in *either* - the CSS view can only
        # add detections, never hide one.
        plain = _normalize_markup(raw)
        css = _normalize_css(raw)
        found = [
            label for label, rule in _SVG_RULES.items() if rule.search(plain) or rule.search(css)
        ]
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
# The PHP short open tag ``<?`` is matched only when code (a variable, a backtick, or a
# function call) follows, so prose such as "if a <? b then c" is not flagged while
# "<? system($_GET[0]) ?>" is.  ``<?xml``/``<?php``/``<?=`` have a non-space next byte,
# so the leading ``\s`` keeps the XML declaration and the other tags out of this branch.
# A variable, a backtick string, or a function call.  Whitespace is bounded (not open
# `\s*`) so the whole marker stays short enough to fit inside _OVERLAP, closing a
# chunk-boundary split; the bound is wide enough that padding a call does not evade.
_PHP_WS = rb"\s{0,40}"
_PHP_AFTER = rb"(?:[$`]|[a-z_]\w{0,30}" + _PHP_WS + rb"\()"
# PHP constructs that open a payload without a call: a short tag followed by one of these
# is code, not prose ("if a <? b then c" has none of them).
_PHP_KEYWORD = (
    rb"(?:php|echo|print|require(?:_once)?|include(?:_once)?|eval|exit|die|assert|system|exec"
    rb"|shell_exec|passthru|popen|proc_open|global|return|function|namespace|new|throw|print_r"
    rb"|var_dump|call_user_func|create_function|if|for|foreach|while|switch)\b"
)
# What may follow a bare ``<?`` short tag to make it code: a variable/backtick, "@", "(",
# a comment, a PHP keyword, or a function call.
_PHP_SHORT = rb"(?:[$`@(]|/[*/]|" + _PHP_KEYWORD + rb"|[a-z_]\w{0,30}" + _PHP_WS + rb"\()"
# The full and echo tags are specific enough not to occur by chance in compressed media.
_PHP_MEDIA = rb"<\?php\s|<\?=" + _PHP_WS + _PHP_AFTER
# In text, also the short open tag ``<?`` when code (not prose) follows: PHP's include()
# runs it from a .txt or .csv, with or without a space after "<?".  Left out of the media
# pattern, where the two bytes "<?" plus code-like bytes turn up by chance in binary.
_PHP_TEXT = _PHP_MEDIA + rb"|<\?" + _PHP_WS + _PHP_SHORT
_CODE_MARKERS = re.compile(
    _PHP_MEDIA + rb"|<script[\s>]"
    rb"|<%@\s*(?:page|language|import)\b|<jsp:"
    rb"|<!--\s*#\s*(?:exec|include|echo|config|set|printenv)\b"
    rb"|__halt_compiler\s*\(\s*\)",
    re.IGNORECASE,
)
#: What a PHP ``include`` runs from *any* file, text included: the open and short tags.
_INCLUDABLE_CODE = re.compile(_PHP_TEXT, re.IGNORECASE)
# Larger than the longest possible marker above (<=~115 bytes with the bounded
# whitespace), so a marker split across a streamed chunk boundary is still wholly present
# in the carried overlap.
_OVERLAP = 160
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
