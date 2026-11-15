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

from ._xmltext import checkable_encoding

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["EmbeddedContent", "SvgActiveContent"]

#: The namespace prefix an element name may carry.  A prefix is whatever the document
#: binds to a namespace (``svg:``, ``_:``, ``x.y:``, non-ASCII letters), so it is matched
#: by what it cannot contain rather than by a list of letters.  Each part ends at the
#: next ":" or delimiter, so the scan stays linear.
_PREFIX = r"(?:[^\s<>/=\"':]+:)*"

# "<" cannot occur inside an XML attribute value, so "<[^<]*" spans a whole start tag -
# also when an attribute value contains ">" - and the scan stays linear.
#
# The rules are matched against views of the markup in which character references are
# decoded and tabs and line breaks removed, to see through "java&#10;script:".  That
# also joins an element name to what follows a line break, so the rules about elements
# are a second opinion only: _active_tags() reads the names from the markup as written.
_SVG_RULES: dict[str, re.Pattern[str]] = {
    "script element": re.compile(rf"<\s*{_PREFIX}script\b"),
    "script URI": re.compile(r"(?:java|vb)script:|data:text/html"),
    "foreignObject": re.compile(rf"<\s*{_PREFIX}foreignobject\b"),
    "embedded document": re.compile(rf"<\s*{_PREFIX}(?:iframe|embed|object|frame)\b"),
    "entity declaration": re.compile(r"<!entity|<!doctype[^<]*\["),
    "XSLT stylesheet": re.compile(r"<\?xml-stylesheet"),
    # An external resource: @import (the views below have no line breaks, so "url(" may
    # follow it directly), or href=/url() pointing at a scheme other than the
    # inert ones (data:, a #fragment, a relative path).  Backslashes are normalised to
    # "/" first, so "url(http:\\e)" reads like "url(http://e)".
    "external resource": re.compile(
        r"@import(?:\b|url\()"
        r"|(?:href\s*=|url\()\s*[\"']?\s*(?!data:)(?:[a-z][a-z0-9+.-]*:|[/\\]{2})"
    ),
    "handler element": re.compile(rf"<\s*{_PREFIX}handler\b"),
    "CSS expression": re.compile(r"expression\s*\("),
    # SMIL animation that sets href or an on* event-handler attribute at runtime.
    "animated attribute": re.compile(
        rf"<\s*{_PREFIX}(?:set|animate)\b[^<]*attributename\s*=\s*[\"']?"
        r"(?:[^\s\"':<>]+:)?(?:href|on[a-z])"
    ),
}
#: The name of a start tag: anything after "<" that does not open a comment, a
#: declaration, a processing instruction or an end tag.  Names are not restricted to
#: ASCII letters: "<_:svg" and "<é:rect" are elements too.
_TAG_NAME = re.compile(r"<\s*([^\s/<>=\"'!?][^\s/<>]*)")
#: One attribute of a start tag: a name and, optionally, a value.  Quoted values may
#: hold ">" but never "<" (XML forbids it), so no part of the match runs past the next
#: tag.  Consecutive parts use disjoint character classes, so there is exactly one way
#: to read a tag and nothing to backtrack into.
_ATTRIBUTE = re.compile(r"([^\s/<>=\"']+)(\s*=\s*(?:\"[^\"<]*\"|'[^'<]*'|[^\s<>\"']*))?")
_SEPARATORS = re.compile(r"[\s/]*")
#: What cannot start an attribute where one is expected (everything else can).
_STRAY = re.compile(r"[=\"']+")
_EVENT_NAME = re.compile(r"on[a-z]+")
#: Elements that run script or embed another document, by their name without prefix.
_ACTIVE_ELEMENTS = {
    "script": "script element",
    "foreignobject": "foreignObject",
    "iframe": "embedded document",
    "embed": "embedded document",
    "object": "embedded document",
    "frame": "embedded document",
    "handler": "handler element",
}
#: SMIL elements that set an attribute at runtime, and the targets that make that active.
_ANIMATIONS = frozenset({"set", "animate"})
_ANIMATED_TARGET = re.compile(r"(?:[^\s:]+:)?(?:href|on[a-z])")
_EVENT_HANDLER = "event handler attribute"


def _after(pattern: re.Pattern[str], text: str, position: int) -> int:
    """The offset behind ``pattern`` at ``position``; ``position`` where it does not match."""
    match = pattern.match(text, position)
    return match.end() if match else position


def _active_tags(text: str) -> set[str]:
    """What the start tags in ``text`` ask a browser to do, as labels of the SVG rules:
    ``on...=`` event handlers, elements that run script or embed documents, and
    animations that set a handler or a link.

    Tags are read the way a parser reads them, from the markup as it was written: the
    name, then one attribute at a time.  Values are skipped as quoted strings, so a ">"
    inside a value does not end the tag, and text after the tag is never mistaken for
    an attribute.  ``text`` is the markup *before* character references are decoded
    ("&quot;>" inside a value must not look like the end of the tag) and with its
    white-space intact: a line break ends an element name like a space does, which a
    view without line breaks ("<script" + "type=...") no longer shows.

    Every "<" is tried as the start of a tag and no step moves past the next "<", so
    each character is read a bounded number of times: the scan is linear whatever the
    input (a single pattern for "any attributes, then on...=" is not - it backtracks
    exponentially on ``x=y/x=y/...``).
    """
    found: set[str] = set()
    size = len(text)
    position = 0
    while (start := text.find("<", position)) != -1:
        tag = _TAG_NAME.match(text, start)
        if tag is None:
            position = start + 1
            continue
        local = tag.group(1).rpartition(":")[2]
        if label := _ACTIVE_ELEMENTS.get(local):
            found.add(label)
        animation = local in _ANIMATIONS
        position = tag.end()
        while True:
            position = _after(_SEPARATORS, text, position)
            if position >= size or text[position] in "<>":
                break  # the end of this tag, or the start of the next one
            attribute = _ATTRIBUTE.match(text, position)
            if attribute is None:
                # Stray quotes or "=": no parser accepts them; read on behind them.
                position = max(_after(_STRAY, text, position), position + 1)
                continue
            position = attribute.end()
            name, assigned = attribute.group(1), attribute.group(2)
            if assigned is None:
                continue
            if _EVENT_NAME.fullmatch(name):
                found.add(_EVENT_HANDLER)
            elif animation and name.rpartition(":")[2] == "attributename":
                target = html.unescape(assigned.partition("=")[2]).strip(" \t\r\n\f\"'")
                if _ANIMATED_TARGET.match(target):
                    found.add("animated attribute")
    return found


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
    # "&#106;ava&#x09;script:" must be seen as "javascript:".  They also read "\" as "/"
    # in URLs, so href="\\evil/x" is the scheme-relative "//evil/x".  This view keeps ALL
    # of the markup; it never drops content, so a marker is never hidden from the scan.
    return _URL_INVISIBLES.sub("", html.unescape(text)).replace("\\", "/").lower()


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

    The markup is read as UTF-8 or UTF-16 text, as browsers read it.  An SVG that
    declares another encoding which can spell markup differently (ISO-2022-JP,
    Shift_JIS, UTF-7, ...) cannot be checked and is refused; single-byte encodings that
    leave ASCII alone (ISO 8859, Windows-125x) are fine.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "svg"

    max_bytes: int = 10 * MiB

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and file.file_type.mime == "image/svg+xml"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        data = file.read(self.max_bytes)
        raw = _decode_markup(data)
        # The plain view keeps all the markup; the CSS view undoes <style> obfuscation but
        # may drop content, so a rule fires on a match in *either* - the CSS view can only
        # add detections, never hide one.
        plain = _normalize_markup(raw)
        css = _normalize_css(raw)
        tags = _active_tags(raw)
        found = [
            label
            for label, rule in _SVG_RULES.items()
            if label in tags or rule.search(plain) or rule.search(css)
        ]
        if _EVENT_HANDLER in tags:
            found.insert(0, _EVENT_HANDLER)
        if not checkable_encoding(data):
            # A browser would decode this differently than the text scanned above.
            found.insert(0, "unsupported encoding")
        if found:
            yield self.violation(
                Code.SVG_ACTIVE_CONTENT, "The SVG image contains active content.", found=found
            )


# Markers specific enough that they do not occur by chance in compressed media data
# (a 3-byte "<?=" alone would, about once per 20 MB): PHP open and echo tags, HTML
# scripts, JSP/ASP directives, server-side includes and PHAR stubs (polyglot images
# that PHP deserializes through phar://).
#
# Every quantifier below is bounded, so a marker has a maximum length (it must fit
# inside _OVERLAP, or a marker split over two streamed chunks would be missed) and the
# scan is linear: no part of a pattern can run on through the file.  Runs of
# whitespace are possessive ("+"): what follows them never starts with whitespace, so
# giving some back could not help a match and is not tried.
_PHP_WS = rb"\s{0,40}+"
# A function or method call: an identifier then "(", allowing a leading "\" namespace and
# one "Foo::bar" static step, so "\system(" and "Foo::bar(" read as code.  It needs a "("
# or "::", so "\alpha" or "Foo bar" in prose is not a call.
_PHP_CALL = rb"\\?[a-z_]\w{0,30}(?:::[a-z_]\w{0,30})?(?:" + _PHP_WS + rb"\(|::)"
_PHP_INCLUDE = rb"(?:include|require)(?:_once)?\b"
# PHP constructs that open a statement without a call: a short tag followed by one of
# these is code, not prose ("if a <? b then c" has none of them).
_PHP_KEYWORD = (
    rb"(?:php|echo|print|require(?:_once)?|include(?:_once)?|eval|exit|die|assert|system|exec"
    rb"|shell_exec|passthru|popen|proc_open|global|return|function|namespace|new|throw|print_r"
    rb"|var_dump|call_user_func|create_function|if|for|foreach|while|switch)\b"
)


# What follows an echo tag, up to ``limit`` bytes: anything but the start of another echo
# tag.  Windows of neighbouring tags therefore never overlap, which keeps a file full of
# "<?=" linear to scan.
def _echo_window(limit: int) -> bytes:
    return rb"(?:[^<]|<(?!\?=)){0,%d}?" % limit


# The echo tag ``<?=`` is always enabled in PHP.  In media, where its three bytes also
# occur by chance, it counts as code when an expression follows - a variable, a backtick
# or a call, possibly behind brackets, "@" or unary operators ("<?=(f())", "<?=@f()",
# "<?=!f()") - or when the tag is closed again within a short distance ("<?='x'.f()?>").
_PHP_ECHO = rb"<\?=[\s(@!~+\-]{0,40}+(?:[$`]|" + _PHP_CALL + rb"|" + _PHP_INCLUDE + rb")"
_PHP_ECHO_CLOSED = rb"<\?=" + _echo_window(100) + rb"\?>"
_PHP_MEDIA = rb"<\?php\s|" + _PHP_ECHO + rb"|" + _PHP_ECHO_CLOSED
# In text the tag is no accident, and PHP's include() runs it from a .txt or .csv.  It is
# code when a variable, a backtick, a call, an include or the closing "?>" follows within
# 200 bytes, whatever the expression starts with; "the <?= tag" in prose has none of them.
_PHP_ECHO_TEXT = rb"<\?=" + _echo_window(200) + rb"(?:[$`(]|\?>|" + _PHP_INCLUDE + rb")"
# The short open tag ``<?`` (PHP's short_open_tag setting) is code when a statement
# follows.  A statement starts with a variable, a string, a number, a bracket, a unary
# operator, "@", a namespace separator, a comment or ";" - or with a keyword, a call, or
# a constant used as a statement.  Nothing else does: letters start prose ("if a <? b
# then c") and XML ("<?xml", "<?mso-application"), and "<?*" or "<?." is no PHP at all
# (Vim's manual documents its "<?" operator that way).  This is a proximity heuristic,
# not a parser: see "Known limits" in docs/ARCHITECTURE.md.
_PHP_STATEMENT = rb"[$`@(\[{;!~+\-'\"0-9\\#]|/[/*]"
_PHP_SHORT = (
    rb"<\?" + _PHP_WS + rb"(?:" + _PHP_STATEMENT + rb"|" + _PHP_KEYWORD + rb"|" + _PHP_CALL
    + rb"|[a-z_]\w{0,30}" + _PHP_WS + rb";)"
)  # fmt: skip
_PHP_TEXT = _PHP_MEDIA + rb"|" + _PHP_ECHO_TEXT + rb"|" + _PHP_SHORT
_CODE_MARKERS = re.compile(
    _PHP_MEDIA + rb"|<script[\s>]"
    rb"|<%@\s*(?:page|language|import)\b|<jsp:"
    rb"|<!--\s*#\s*(?:exec|include|echo|config|set|printenv)\b"
    rb"|__halt_compiler\s*\(\s*\)",
    re.IGNORECASE,
)
#: What a PHP ``include`` runs from *any* file, text included: the open, echo and short tags.
_INCLUDABLE_CODE = re.compile(_PHP_TEXT, re.IGNORECASE)
# Larger than the longest possible marker above (an echo tag, its 200-byte window and
# "require_once": 215 bytes), so a marker split across a streamed chunk boundary is
# still wholly present in the carried overlap.
_OVERLAP = 256
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
    tags anywhere, because PHP's ``include`` runs them from a ``.txt`` or ``.csv`` too:
    ``<?php``, the echo tag ``<?=`` when code or its closing ``?>`` follows, and the short
    tag ``<?`` when a statement follows.
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
                return match.group(0).decode("latin-1").strip()[:80]
            carry = window[-_OVERLAP:]
        return None
