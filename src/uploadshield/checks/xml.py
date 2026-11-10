"""XML document type definitions: the vehicle of XXE and entity-expansion bombs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from uploadshield.core.check import Check
from uploadshield.core.containers import zip_entries, zip_head
from uploadshield.core.types import KiB
from uploadshield.core.violations import Code, Violation

from .office import OFFICE_ZIP_TYPES

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["XmlSafety"]

#: ZIP-based document formats whose parts are XML that servers parse (OOXML, ODF, EPUB).
XML_DOCUMENT_TYPES = OFFICE_ZIP_TYPES | {"application/epub+zip"}
_XML_TYPES = frozenset({"application/xml"})
_XML_PARTS = (
    ".xml", ".rels", ".vml", ".xhtml", ".htm", ".html", ".opf", ".ncx", ".svg", ".rdf", ".xsl",
)  # fmt: skip
_PROLOG_NOISE = re.compile(r"\s+|<\?.*?\?>|<!--.*?-->", re.DOTALL)
_ROOT_ELEMENT = re.compile(r"<[A-Za-z_:À-\U000effff]")
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


def _decode(head: bytes) -> str:
    for marker, encoding in _BOMS:
        if head.startswith(marker):
            return head[len(marker) :].decode(encoding, "ignore")
    for marker, encoding in _UNMARKED:
        if head.startswith(marker):
            return head.decode(encoding, "ignore")
    return head.decode("utf-8", "ignore")


def declares_dtd(head: bytes, *, complete: bool) -> bool | None:
    """Whether the XML prolog in ``head`` declares a DTD; ``None`` if it cannot tell.

    A DTD (and with it every entity) can only appear in the prolog, before the root
    element, so the first bytes decide.  ``complete`` says whether ``head`` is the whole
    document: a prolog that runs past an incomplete head cannot be judged.
    """
    text = _decode(head)
    position = 0
    while match := _PROLOG_NOISE.match(text, position):
        position = match.end()
    rest = text[position : position + 9].lower()
    if rest.startswith(("<!doctype", "<!entity")):
        return True
    if _ROOT_ELEMENT.match(text, position):
        return False
    return False if complete else None


@dataclass(frozen=True, slots=True)
class XmlSafety(Check):
    """Refuse XML that declares a document type (DTD) - in Office documents, ODF and
    EPUB, and in XML uploads a policy explicitly allows.

    DTDs are how external entities (XXE: server-side file disclosure and request
    forgery when the document is parsed) and entity-expansion bombs ("billion
    laughs") get in.  Office, LibreOffice and e-book readers never write them, so their
    presence is a reliable sign of an attack on whatever parses the upload.  SVG is
    covered by :class:`~uploadshield.checks.SvgActiveContent`.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "xml"

    head_bytes: int = 64 * KiB

    def applies(self, file: InspectedFile) -> bool:
        file_type = file.file_type
        return file_type is not None and file_type.mime in (XML_DOCUMENT_TYPES | _XML_TYPES)

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        file_type = file.file_type
        if file_type is not None and file_type.mime in _XML_TYPES:
            head = file.head(self.head_bytes)
            verdicts = {file.name: declares_dtd(head, complete=file.size <= len(head))}
        else:
            verdicts = {}
            for entry in zip_entries(file) or []:
                if entry.is_dir() or not entry.filename.lower().endswith(_XML_PARTS):
                    continue
                head = zip_head(file, entry.filename, self.head_bytes)
                if head is not None:  # unreadable members are ArchiveSafety's business
                    verdicts[entry.filename] = declares_dtd(
                        head, complete=entry.file_size <= len(head)
                    )
        if dtds := [part for part, verdict in verdicts.items() if verdict is True]:
            yield self.violation(
                Code.XML_DTD,
                "The document contains an XML document type definition, which is not allowed.",
                parts=dtds[:10],
            )
        elif unclear := [part for part, verdict in verdicts.items() if verdict is None]:
            yield self.violation(
                Code.XML_DTD,
                "The document's XML could not be checked for a document type definition.",
                parts=unclear[:10],
            )
