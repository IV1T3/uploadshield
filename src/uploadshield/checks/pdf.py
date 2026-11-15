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
        "FileAttachment",
        "RichMedia",
        "XFA",
        "ImportData",
        "SubmitForm",
        "GoToE",
    }
)

# A name ends at white-space or a delimiter.  PDF white-space includes NUL (ISO 32000-1,
# table 1), which Python's "\s" does not: "/JS\x00" is the name "JS" to every reader.
_NAME = re.compile(rb"/([^\x00\s/()<>\[\]{}%]{1,127})")
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
#: A file specification that embeds a file: an ``/EF`` entry holding a dictionary or a
#: reference.  ``/Type /EmbeddedFile`` and the ``/EmbeddedFiles`` name tree are optional,
#: this entry is not.  It is matched with its value because the two letters alone turn up
#: by chance in compressed data.
_EMBEDDED_FILE_SPEC = re.compile(
    rb"/(?:E|#45)(?:F|#46)[\x00\t\n\f\r ]*"
    rb"(?:<<|\d{1,10}[\x00\t\n\f\r ]+\d{1,10}[\x00\t\n\f\r ]+R(?![^\x00\s/()<>\[\]{}%]))"
)


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


_LENGTH = re.compile(rb"/Length[\x00\t\n\f\r ]+(\d+)(?!\d)(?![\x00\t\n\f\r ]+\d+[\x00\t\n\f\r ]+R)")
_WHITESPACE = b"\x00\t\n\f\r "
#: The ``stream`` keyword: after whitespace or a delimiter, before an end of line.
_KEYWORD = rb"(?:(?<=[\x00\t\n\f\r ()<>\[\]{}])|\A)stream(?:\r\n|\n|\r)"
_STREAM_KEYWORD = re.compile(_KEYWORD)
#: What the lexer stops at outside streams.  ``skip`` consumes whole runs of what
#: does not change its state - ordinary bytes, comments, strings without nested
#: parentheses, hex strings - so floods of them cost no Python-level iterations.
#: Each alternative starts with a different byte, so there is one way to read a run
#: and giving part of it back could never help.  The quantifiers say so (they are
#: possessive): otherwise the regex engine keeps a record of every step in case it has
#: to go back, which is gigabytes of memory for a run of a few megabytes.
_TOKEN = re.compile(
    rb"(?P<skip>(?:[^%(<>s]++|s(?!tream[\r\n])|%[^\r\n]*+|\((?:[^()\\]++|\\.)*+\)"
    rb"|<[0-9A-Fa-f\x00\t\n\f\r ]*+>)++)"
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
            dictionary = data[last[0] : last[1]]
            finish = _stream_end(data, dictionary, pos)
            yield dictionary, data[pos:finish]
            pos = min(finish + len(b"endstream"), len(data))
            last = None
    if depth:
        raise _Uncheckable("unterminated dictionary")
    if any(m.start() not in seen for m in _STREAM_KEYWORD.finditer(data)):
        raise _Uncheckable("stream keyword outside the object structure")


def _stream_end(data: bytes, dictionary: bytes, begin: int) -> int:
    """Where the data of a stream starting at ``begin`` ends (``endstream`` or the end).

    Only good enough to step over a stream.  Where the *content* of an object stream
    ends is decided by its decoders, which must each reach their end marker
    (:func:`_decode`): what is cut short here is refused there, never read in part.
    """
    if length := _LENGTH.search(_unescape(dictionary)):
        end = begin + int(length.group(1))
        after = data[end : end + 64].lstrip(_WHITESPACE)
        if end <= len(data) and after.startswith(b"endstream"):
            return data.find(b"endstream", end)
    found = data.find(b"endstream", begin)
    return found if found != -1 else len(data)


def _unescape(raw: bytes) -> bytes:
    """``raw`` with the ``#xx`` escapes of names decoded."""
    return _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw) if b"#" in raw else raw


# --------------------------------------------------------------------------- #
# Stream dictionaries, read the way a PDF parser reads them
# --------------------------------------------------------------------------- #

_REGULAR = rb"[^\x00\t\n\f\r ()<>\[\]{}/%]"
#: One token of a dictionary, after any white-space and comments.  The quantifiers that
#: skip those are possessive and every alternative starts with a different byte, so
#: there is one way to read each token and nothing to backtrack into.
_OBJECT = re.compile(
    rb"(?:[\x00\t\n\f\r ]++|%[^\r\n]*+)*+"
    rb"(?:(?P<name>/" + _REGULAR + rb"*+)"
    rb"|(?P<open><<)|(?P<close>>>)"
    rb"|(?P<hex><[^<>]*+>)"
    rb"|(?P<string>\()"
    rb"|(?P<array>\[)|(?P<end>\])"
    rb"|(?P<word>" + _REGULAR + rb"++)"
    rb"|(?P<brace>[{}]))"
)
#: The dictionary of a real object stream takes about a hundred bytes.  One that is
#: larger than this is not read: what cannot be checked is refused.
_MAX_DICTIONARY = 64 * 1024
#: What follows the object number of an indirect reference: a generation and "R".
_REFERENCE = re.compile(
    rb"(?:[\x00\t\n\f\r ]++|%[^\r\n]*+)*+\d++(?:[\x00\t\n\f\r ]++|%[^\r\n]*+)*+R(?!"
    + _REGULAR
    + rb")"
)
_CLOSER = {"array": "end", "open": "close"}


@dataclass(frozen=True, slots=True)
class _Value:
    """The value of a dictionary entry, as far as decoding a stream needs to know it."""

    kind: str  # "name", "number", "array", "dictionary", "reference", "null" or "other"
    names: tuple[str, ...] = ()  # the name, or the names in an array
    plain: bool = True  # an array that holds nothing but names
    raw: bytes = b""  # a number, a nested dictionary or an array, as written


class _Dictionary:
    """Reads a dictionary token by token: strings, comments and nested values are
    stepped over as a whole, so nothing inside them can pass for one of its entries."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def token(self) -> tuple[str, bytes]:
        match = _OBJECT.match(self.data, self.position)
        if match is None or match.lastgroup is None:
            raise _Uncheckable("stream dictionary that cannot be read")
        kind = match.lastgroup
        if kind == "string":  # nested and escaped parentheses: counted
            self.position = _skip_string(self.data, match.start(kind))
            return kind, b""
        self.position = match.end()
        return kind, match.group(kind)

    def skip(self, opener: str) -> None:
        """Step over the rest of an array or dictionary that ``opener`` began."""
        closers = [_CLOSER[opener]]
        while closers:
            kind, _ = self.token()
            if kind in _CLOSER:
                closers.append(_CLOSER[kind])
            elif kind in ("end", "close") and kind != closers.pop():
                raise _Uncheckable("stream dictionary that cannot be read")

    def value(self) -> _Value:
        """The object at the current position: the value of the key just read."""
        start = self.position
        kind, text = self.token()
        if kind == "name":
            return _Value("name", (_unescape(text[1:]).decode("latin-1"),))
        if kind == "word":
            if text == b"null":
                return _Value("null")
            if text.isdigit():
                if rest := _REFERENCE.match(self.data, self.position):
                    self.position = rest.end()  # "7 0 R", not the number "7"
                    return _Value("reference")
                return _Value("number", raw=text)
            return _Value("other")
        if kind == "open":
            self.skip(kind)
            return _Value("dictionary", raw=self.data[start : self.position])
        if kind == "array":
            names: list[str] = []
            plain = True
            while (item := self.token())[0] != "end":
                if item[0] == "name":
                    names.append(_unescape(item[1][1:]).decode("latin-1"))
                    continue
                plain = False
                if item[0] in _CLOSER:
                    self.skip(item[0])
                elif item[0] == "close":
                    raise _Uncheckable("stream dictionary that cannot be read")
            return _Value("array", tuple(names), plain, self.data[start : self.position])
        if kind in ("string", "hex"):
            return _Value("other")
        raise _Uncheckable("stream dictionary that cannot be read")

    def value_or_end(self) -> _Value | None:
        """The next item of the array being read; ``None`` at its closing bracket."""
        before = self.position
        if self.token()[0] == "end":
            return None
        self.position = before
        return self.value()

    def entries(self) -> dict[str, _Value]:
        """The dictionary's own entries.  A key given twice is refused: readers
        disagree on which one counts."""
        if self.token()[0] != "open":
            raise _Uncheckable("stream dictionary that cannot be read")
        entries: dict[str, _Value] = {}
        while (key := self.token())[0] != "close":
            if key[0] != "name":
                raise _Uncheckable("stream dictionary that cannot be read")
            name = _unescape(key[1][1:]).decode("latin-1")
            if name in entries:
                raise _Uncheckable(f"/{name} given twice")
            entries[name] = self.value()
        return entries


def _refuse_predictors(parameters: _Value) -> None:
    """Refuse decode parameters that are not known here or that name a predictor.

    ``parameters`` is one dictionary, or an array with one dictionary (or ``null``) per
    filter.  Anything else - a reference, an array inside the array - is not given
    directly, so what it would say is not known.
    """
    if parameters.kind != "array":
        _refuse_predictor(parameters)
        return
    items = _Dictionary(parameters.raw)
    items.token()  # the opening bracket
    while (item := items.value_or_end()) is not None:
        _refuse_predictor(item)


def _refuse_predictor(parameters: _Value) -> None:
    if parameters.kind == "null":
        return
    if parameters.kind != "dictionary":
        raise _Uncheckable("decode parameters that are not given directly")
    predictor = _Dictionary(parameters.raw).entries().get("Predictor")
    if predictor is not None and (predictor.kind != "number" or int(predictor.raw) > 1):
        raise _Uncheckable("predictor")


def _filters(dictionary: bytes) -> list[str]:
    """The filters that decode an object stream, from the entries of its dictionary.

    Anything that keeps the decoded content from being known here is refused: filters
    or decode parameters given by reference, a predictor, data kept in another file, a
    dictionary too large to be one.
    """
    if len(dictionary) > _MAX_DICTIONARY:
        raise _Uncheckable("stream dictionary too large")
    entries = _Dictionary(dictionary).entries()
    if not entries.keys().isdisjoint(("F", "FFilter", "FDecodeParms")):
        raise _Uncheckable("stream data in another file")
    for key in ("DecodeParms", "DP"):
        if (parameters := entries.get(key)) is not None:
            _refuse_predictors(parameters)
    chosen = entries.get("Filter")
    if chosen is None or chosen.kind == "null":
        return []
    if chosen.kind == "name" or (chosen.kind == "array" and chosen.plain):
        return list(chosen.names)
    raise _Uncheckable("filter that is not given by name")


# --------------------------------------------------------------------------- #
# Decoding object streams
# --------------------------------------------------------------------------- #


def _inflate(data: bytes, budget: int) -> bytes:
    for wbits in (zlib.MAX_WBITS | 32, -zlib.MAX_WBITS):  # zlib/gzip with any window; raw
        inflater = zlib.decompressobj(wbits)
        try:
            inflated = inflater.decompress(data, budget + 1)
        except zlib.error:
            continue
        if len(inflated) > budget:
            raise ContentTooLargeError(f"object streams inflate to more than {budget} bytes")
        if inflater.eof:
            return inflated
        # Data that stops before its end: what a reader inflates may go on from here.
    raise _Uncheckable("FlateDecode data that cannot be inflated completely")


def _decode(raw: bytes, filters: list[str], budget: int) -> bytes:
    """``raw`` passed through ``filters``.

    Every filter must reach the end marker of its data.  Where the data of a stream
    ends in the file is not always certain (a ``/Length`` given by reference, the word
    ``endstream`` inside the data); the end markers are, and a reader stops at them too.
    Data without one may have been cut short, so it is refused, never read in part.
    """
    data = raw
    for name in filters:
        if name in ("FlateDecode", "Fl"):
            data = _inflate(data, budget)
        elif name in ("ASCIIHexDecode", "AHx"):
            encoded, marker, _ = data.partition(b">")
            if not marker:
                raise _Uncheckable("ASCIIHexDecode data without its end marker")
            digits = bytes(c for c in encoded if c not in b" \t\r\n\f\x00")
            data = bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("latin-1"))
        elif name in ("ASCII85Decode", "A85"):
            encoded, marker, _ = data.strip(_WHITESPACE).removeprefix(b"<~").partition(b"~>")
            if not marker:
                raise _Uncheckable("ASCII85Decode data without its end marker")
            data = base64.a85decode(encoded)
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
        filters = _filters(dictionary)
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
    Forbidding ``EmbeddedFile`` also refuses file specifications with an ``/EF`` entry:
    that is what embeds a file, the name itself is optional.
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
        embeds = "EmbeddedFile" in self.forbidden and bool(_EMBEDDED_FILE_SPEC.search(data))
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
                    embeds = embeds or (
                        "EmbeddedFile" in self.forbidden
                        and bool(_EMBEDDED_FILE_SPEC.search(decoded))
                    )
            except _Uncheckable as exc:
                yield self.violation(
                    Code.PDF_ACTIVE_CONTENT,
                    "The PDF stores objects in a form that cannot be checked.",
                    reason="uncheckable",
                    detail=str(exc),
                )
                return
        if hits := sorted((names & self.forbidden) | ({"EF"} if embeds else set())):
            yield self.violation(
                Code.PDF_ACTIVE_CONTENT,
                "The PDF contains active content such as scripts or embedded files.",
                reason="active_content",
                keywords=hits,
            )
