"""XML document type definitions: the vehicle of XXE and entity-expansion bombs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from uploadshield.core.check import Check
from uploadshield.core.containers import zip_entries, zip_head
from uploadshield.core.types import KiB
from uploadshield.core.violations import Code, Violation

from ._xmltext import declares_dtd, starts_as_xml
from .office import OFFICE_ZIP_TYPES

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["XmlSafety", "declares_dtd"]

#: ZIP-based document formats whose parts are XML that servers parse (OOXML, ODF, EPUB).
XML_DOCUMENT_TYPES = OFFICE_ZIP_TYPES | {"application/epub+zip"}
_XML_TYPES = frozenset({"application/xml"})
_XML_PARTS = (
    ".xml", ".rels", ".vml", ".xhtml", ".htm", ".html", ".opf", ".ncx", ".svg", ".rdf", ".xsl",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class XmlSafety(Check):
    """Refuse XML that declares a document type (DTD) - in Office documents, ODF and
    EPUB, and in XML uploads a policy explicitly allows.

    DTDs are how external entities (XXE: server-side file disclosure and request
    forgery when the document is parsed) and entity-expansion bombs ("billion
    laughs") get in.  Office, LibreOffice and e-book readers never write them, so their
    presence is a reliable sign of an attack on whatever parses the upload.  SVG is
    covered by :class:`~uploadshield.checks.SvgActiveContent`.

    In a document every member is looked at, whatever it is called: which members a
    program parses is decided by the document's relationships and manifests, not by
    file extensions.  A member is judged when its name says XML or its content starts
    as XML.  XML in an encoding that cannot be read reliably (anything but UTF-8,
    UTF-16, UTF-32 and single-byte encodings that leave ASCII alone) is refused.
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
            verdicts = [(file.name, declares_dtd(head, complete=file.size <= len(head)))]
        else:
            verdicts = []  # one per entry: names may repeat, and readers pick either
            for entry in zip_entries(file) or []:
                if entry.is_dir():
                    continue
                head = zip_head(file, entry, self.head_bytes)
                if head is None:  # unreadable members are ArchiveSafety's business
                    continue
                verdict = declares_dtd(head, complete=entry.file_size <= len(head))
                # A member named like XML is judged whatever it holds.  Any other one
                # is judged when it is an XML document: a DTD was found in its prolog,
                # or it starts as XML and that prolog cannot be read.
                if (
                    entry.filename.lower().endswith(_XML_PARTS)
                    or verdict is True
                    or (verdict is None and starts_as_xml(head))
                ):
                    verdicts.append((entry.filename, verdict))
        if dtds := [part for part, verdict in verdicts if verdict is True]:
            yield self.violation(
                Code.XML_DTD,
                "The document contains an XML document type definition, which is not allowed.",
                parts=dtds[:10],
            )
        elif unclear := [part for part, verdict in verdicts if verdict is None]:
            yield self.violation(
                Code.XML_DTD,
                "The document's XML could not be checked for a document type definition.",
                parts=unclear[:10],
            )
