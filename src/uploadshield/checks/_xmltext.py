"""How a piece of XML is encoded, as far as the checks that read it need to know.

Several checks read markup as text to find what a parser would act on (a document type
definition, a script, a field).  That only works while the check and the parser see the
same characters, so the encoding decides whether a document can be checked at all:

* UTF-8, UTF-16 and UTF-32 are decoded here the way XML parsers detect them (byte order
  mark, or the shape of ``<?`` - XML 1.0, appendix F);
* single-byte encodings that leave ASCII alone (ISO 8859, Windows-125x) need no
  decoding: every ``<``, quote and letter of the markup is the byte it looks like;
* anything else - multi-byte and stateful encodings such as ISO-2022-JP, Shift_JIS or
  UTF-7, and EBCDIC - can spell markup with bytes that read differently here, or drop
  bytes while decoding.  Such documents cannot be checked and callers refuse them.
"""

from __future__ import annotations

import re

__all__ = [
    "checkable_encoding",
    "declared_encoding",
    "declares_dtd",
    "decode_head",
    "detected_encoding",
    "starts_as_xml",
]

_BOMS = (
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)
#: Encodings recognisable from "<?" without a byte order mark (XML 1.0, appendix F).
_UNMARKED = (
    (b"\x00\x00\x00<", "utf-32-be"),
    (b"<\x00\x00\x00", "utf-32-le"),
    (b"\x00<\x00?", "utf-16-be"),
    (b"<\x00?\x00", "utf-16-le"),
)
#: ``<?xm`` in EBCDIC: how XML parsers recognise that family (XML 1.0, appendix F).
_EBCDIC = b"\x4c\x6f\xa7\x94"

#: The encoding named by an XML declaration at the start of a document.  ``[^>]*?``
#: stops at the end of the declaration, so the match is linear in its length.
_DECLARATION = re.compile(r"﻿?\s*<\?xml\b[^>]*?\bencoding\s*=\s*[\"']\s*([^\"'\s>]*)", re.IGNORECASE)
#: Encodings in which every ASCII character is one byte that means nothing else.
_TRANSPARENT = re.compile(
    r"utf-?8|us-ascii|ascii|iso-?8859-?(?:1[0-6]|[1-9])|latin-?(?:10|[1-9])"
    r"|windows-125[0-8]|cp-?125[0-8]"
)
#: Encodings :func:`decode_head` reads from the byte order mark or the shape of ``<?``.
_WIDE = re.compile(r"(?:utf-?(16|32)|ucs-?([24]))(?:-?(le|be))?")


def detected_encoding(head: bytes) -> tuple[str, int]:
    """The encoding the first bytes of ``head`` show, and the length of its byte order
    mark: ``utf-8`` unless they say UTF-16 or UTF-32."""
    for marker, encoding in _BOMS:
        if head.startswith(marker):
            return encoding, len(marker)
    for marker, encoding in _UNMARKED:
        if head.startswith(marker):
            return encoding, 0
    return "utf-8", 0


def decode_head(head: bytes) -> str:
    """The start of an XML document as text, in the encoding its first bytes show."""
    encoding, skip = detected_encoding(head)
    return head[skip:].decode(encoding, "ignore")


def declared_encoding(text: str) -> str | None:
    """The encoding an XML declaration at the start of ``text`` names, lowercased."""
    match = _DECLARATION.match(text)
    return match.group(1).lower() if match else None


def checkable_encoding(head: bytes) -> bool:
    """Whether markup starting with ``head`` reads here as it does for a parser.

    False for documents that declare an encoding other than the ones above (see the
    module docstring), for EBCDIC, which parsers detect from the first four bytes, and
    when the declaration contradicts what the first bytes show - UTF-16 declared on
    bytes that are not, or the reverse.  Parsers disagree on which of the two wins, so
    what follows the declaration could be read either way.
    """
    if head.startswith(_EBCDIC):
        return False
    declared = declared_encoding(decode_head(head[:1024]))
    if not declared:
        return True
    detected = detected_encoding(head)[0]  # "utf-8", "utf-16-le", "utf-32-be", ...
    if named := _WIDE.fullmatch(declared):
        width = named.group(1) or {"2": "16", "4": "32"}[named.group(2)]
        order = named.group(3) or ""
        return detected.startswith(f"utf-{width}") and detected.endswith(order)
    return detected == "utf-8" and bool(_TRANSPARENT.fullmatch(declared))


def starts_as_xml(head: bytes) -> bool:
    """Whether ``head`` starts an XML document in any encoding parsers detect."""
    return head.startswith(_EBCDIC) or decode_head(head[:256]).lstrip().startswith("<")


_PROLOG_NOISE = re.compile(r"\s+|<\?.*?\?>|<!--.*?-->", re.DOTALL)
_ROOT_ELEMENT = re.compile(r"<[A-Za-z_:À-\U000effff]")


def declares_dtd(head: bytes, *, complete: bool) -> bool | None:
    """Whether the XML prolog in ``head`` declares a DTD; ``None`` if it cannot tell.

    A DTD (and with it every entity) can only appear in the prolog, before the root
    element, so the first bytes decide.  ``complete`` says whether ``head`` is the whole
    document: a prolog that runs past an incomplete head cannot be judged.  Neither can
    a document in an encoding that may spell ``<!DOCTYPE`` with other bytes (see
    the module docstring).
    """
    if not checkable_encoding(head):
        return None
    text = decode_head(head)
    position = 0
    while match := _PROLOG_NOISE.match(text, position):
        position = match.end()
    rest = text[position : position + 9].lower()
    if rest.startswith(("<!doctype", "<!entity")):
        return True
    if _ROOT_ELEMENT.match(text, position):
        return False
    return False if complete else None
