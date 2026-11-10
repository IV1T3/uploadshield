"""Detection of active content in PDF documents (no third-party dependency)."""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from uploadshield.core.check import Check
from uploadshield.core.types import MiB
from uploadshield.core.upload import ContentTooLargeError
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["DEFAULT_PDF_KEYWORDS", "PdfActiveContent", "pdf_names"]

#: Name objects that make a PDF execute code, launch programs, carry payloads or
#: exfiltrate data.  ``/OpenAction`` and ``/AA`` are deliberately absent: LaTeX and
#: most office suites emit them for harmless view settings; the scripts they would
#: trigger are caught by ``/JavaScript`` and ``/JS``.
DEFAULT_PDF_KEYWORDS = frozenset(
    {
        "JavaScript",
        "JS",
        "Launch",
        "EmbeddedFile",
        "EmbeddedFiles",
        "RichMedia",
        "XFA",
        "ImportData",
        "SubmitForm",
        "GoToE",
    }
)

_NAME = re.compile(rb"/([^\s/()<>\[\]{}%]{1,127})")
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def pdf_names(data: bytes) -> set[str]:
    """All PDF name objects in ``data`` with ``#xx`` escapes decoded (``/J#61vaScript``)."""
    names: set[str] = set()
    for raw in set(_NAME.findall(data)):
        decoded = (
            _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw) if b"#" in raw else raw
        )
        names.add(decoded.decode("latin-1"))
    return names


class _Uncheckable(Exception):  # noqa: N818 - a verdict, not an error
    """An object stream that cannot be decoded, so the objects in it cannot be checked."""


_FILTER = re.compile(rb"/Filter\s*(\[[^\]]*\]|/[^\s/\[\]<>()]+)")
_PREDICTOR = re.compile(rb"/Predictor\s+(\d+)")
_FILTER_NAME = re.compile(rb"/([^\s/\[\]<>()]+)")
_LENGTH = re.compile(rb"/Length\s+(\d+)(?!\d)(?!\s+\d+\s+R)")
_WHITESPACE = b"\x00\t\n\f\r "
#: The ``stream`` keyword: after whitespace or a delimiter, before an end of line.
_KEYWORD = rb"(?:(?<=[\x00\t\n\f\r ()<>\[\]{}])|\A)stream(?:\r\n|\n|\r)"
_STREAM_KEYWORD = re.compile(_KEYWORD)
#: What the lexer stops at outside streams.  ``skip`` consumes whole runs of what
#: does not change its state - ordinary bytes, comments, strings without nested
#: parentheses, hex strings - so floods of them cost no Python-level iterations.
#: Each alternative starts with a different byte, so the run never backtracks.
_TOKEN = re.compile(
    rb"(?P<skip>(?:[^%(<>s]|s(?!tream[\r\n])|%[^\r\n]*|\((?:[^()\\]|\\.)*\)"
    rb"|<[0-9A-Fa-f\x00\t\n\f\r ]*>)+)"
    rb"|(?P<string>\()|(?P<open><<)|(?P<close>>>)|(?P<hex><)|(?P<stream>" + _KEYWORD + rb")",
    re.DOTALL,
)
_STRING_TOKEN = re.compile(rb"[()\\]")


def _skip_string(data: bytes, start: int) -> int:
    """The offset after the literal string opening at ``start`` (nested, escaped)."""
    depth, pos = 0, start
    while match := _STRING_TOKEN.search(data, pos):
        token, pos = match.group(), match.end()
        if token == b"\\":
            pos += 1  # the escaped character, whatever it is
        elif token == b"(":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return pos
    raise _Uncheckable("unterminated string")


def _skip_opaque(data: bytes, kind: str | None, match: re.Match[bytes]) -> int:
    """The offset after the comment, string or hex string at ``match``."""
    if kind == "skip":
        return match.end()
    if kind == "string":  # nested parentheses: counted here
        return _skip_string(data, match.start())
    close = data.find(b">", match.end())  # a malformed hex string
    if close == -1:
        raise _Uncheckable("unterminated hex string")
    return close + 1


def _streams(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    """Every stream as ``(dictionary, raw data)``, found the way a PDF lexer reads them.

    Strings, comments and nested dictionaries are skipped structurally, so text inside
    a dictionary (``/Note (obj)``) or its size cannot hide its keys.  Stream data is
    skipped by its direct ``/Length`` when ``endstream`` follows there, as readers do.

    A ``stream`` keyword the walk does not reach - inside a string, a comment or the
    data of another stream - could still be what a reader finds through the cross
    reference table, so it makes the file uncheckable rather than being ignored.
    """
    seen: set[int] = set()
    depth = pos = 0
    opened = -1
    last: tuple[int, int] | None = None  # the last top-level dictionary
    while match := _TOKEN.search(data, pos):
        kind, at = match.lastgroup, match.start()
        if kind in ("skip", "string", "hex"):
            pos = _skip_opaque(data, kind, match)
            continue
        pos = match.end()
        if kind == "open":
            opened = at if depth == 0 else opened
            depth += 1
        elif kind == "close":
            if depth == 1:
                last = (opened, pos)
            depth = max(depth - 1, 0)
        else:  # the stream keyword
            if depth or last is None or data[last[1] : at].strip(_WHITESPACE):
                raise _Uncheckable("stream without a dictionary")
            seen.add(at)
            dictionary = _HEX_ESCAPE.sub(
                lambda m: bytes([int(m.group(1), 16)]), data[last[0] : last[1]]
            )
            finish = _stream_end(data, dictionary, pos)
            yield dictionary, data[pos:finish]
            pos = min(finish + len(b"endstream"), len(data))
            last = None
    if depth:
        raise _Uncheckable("unterminated dictionary")
    if any(m.start() not in seen for m in _STREAM_KEYWORD.finditer(data)):
        raise _Uncheckable("stream keyword outside the object structure")


def _stream_end(data: bytes, dictionary: bytes, begin: int) -> int:
    """Where the data of a stream starting at ``begin`` ends (``endstream`` or the end)."""
    if length := _LENGTH.search(dictionary):
        end = begin + int(length.group(1))
        after = data[end : end + 64].lstrip(_WHITESPACE)
        if end <= len(data) and after.startswith(b"endstream"):
            return data.find(b"endstream", end)
    found = data.find(b"endstream", begin)
    return found if found != -1 else len(data)


def _inflate(data: bytes, budget: int) -> bytes:
    for wbits in (zlib.MAX_WBITS | 32, -zlib.MAX_WBITS):  # zlib/gzip with any window; raw
        try:
            inflated = zlib.decompressobj(wbits).decompress(data, budget + 1)
        except zlib.error:
            continue
        if len(inflated) > budget:
            raise ContentTooLargeError(f"object streams inflate to more than {budget} bytes")
        return inflated
    raise _Uncheckable("FlateDecode data that cannot be inflated")


def _decode(raw: bytes, filters: list[str], budget: int) -> bytes:
    data = raw
    for name in filters:
        if name in ("FlateDecode", "Fl"):
            data = _inflate(data, budget)
        elif name in ("ASCIIHexDecode", "AHx"):
            digits = bytes(c for c in data.split(b">", 1)[0] if c not in b" \t\r\n\f\x00")
            data = bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("latin-1"))
        elif name in ("ASCII85Decode", "A85"):
            data = base64.a85decode(data.strip().removeprefix(b"<~").split(b"~>", 1)[0])
        else:
            raise _Uncheckable(f"filter {name}")
    return data


def _object_streams(data: bytes, budget: int) -> Iterator[bytes]:
    """Decode every object stream, where PDFs can hide action dictionaries.

    Objects live either in the file body, which is scanned as it is, or in object
    streams (``/Type /ObjStm``, or any stream with ``/N`` and ``/First``, as readers do
    not insist on the type).  Each one is decoded completely, under one budget for the
    whole file; a budget overrun or an encoding that cannot be decoded is reported, so
    nothing is skipped silently.
    """
    for dictionary, raw in _streams(data):
        names = pdf_names(dictionary)
        if "ObjStm" not in names and not {"N", "First"} <= names:
            continue
        if (predictor := _PREDICTOR.search(dictionary)) and int(predictor.group(1)) > 1:
            raise _Uncheckable("predictor")
        filters_match = _FILTER.search(dictionary)
        filters = (
            [n.decode("latin-1") for n in _FILTER_NAME.findall(filters_match.group(1))]
            if filters_match
            else []
        )
        try:
            decoded = _decode(raw, filters, budget)
        except (ValueError, binascii.Error) as exc:
            raise _Uncheckable(str(exc)) from exc
        budget -= len(decoded)
        if budget < 0:
            raise ContentTooLargeError("object streams inflate beyond the budget")
        yield decoded


@dataclass(frozen=True, slots=True)
class PdfActiveContent(Check):
    """Refuse PDFs containing scripts, launch actions, embedded files or forms that
    submit data.

    Name objects are matched exactly after decoding ``#xx`` obfuscation, in the raw
    file *and* inside compressed (object) streams, where attackers usually hide them.
    Encrypted PDFs cannot be inspected and are refused unless ``allow_encrypted``.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "pdf"

    forbidden: frozenset[str] = DEFAULT_PDF_KEYWORDS
    inspect_streams: bool = True
    allow_encrypted: bool = False
    max_bytes: int = 200 * MiB
    max_inflated_bytes: int = 64 * MiB

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and file.file_type.mime == "application/pdf"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        data = file.read(self.max_bytes)
        names = pdf_names(data)
        if "Encrypt" in names and not self.allow_encrypted:
            yield self.violation(
                Code.PDF_ACTIVE_CONTENT,
                "Encrypted PDF files cannot be checked and are not allowed.",
                reason="encrypted",
                keywords=["Encrypt"],
            )
            return
        # Without these names no stream can be an object stream: nothing to decode.
        if self.inspect_streams and ("ObjStm" in names or {"N", "First"} <= names):
            try:
                for decoded in _object_streams(data, self.max_inflated_bytes):
                    names |= pdf_names(decoded)
            except _Uncheckable as exc:
                yield self.violation(
                    Code.PDF_ACTIVE_CONTENT,
                    "The PDF stores objects in a form that cannot be checked.",
                    reason="uncheckable",
                    detail=str(exc),
                )
                return
        if hits := sorted(names & self.forbidden):
            yield self.violation(
                Code.PDF_ACTIVE_CONTENT,
                "The PDF contains active content such as scripts or embedded files.",
                reason="active_content",
                keywords=hits,
            )
