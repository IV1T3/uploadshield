"""Macros and remote references in Office documents (OOXML, ODF, legacy OLE2)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from uploadshield.core.check import Check
from uploadshield.core.containers import zip_entries, zip_member, zip_read, zip_search
from uploadshield.core.types import MiB
from uploadshield.core.upload import ContentTooLargeError
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["OFFICE_ZIP_TYPES", "OfficeMacros"]

OFFICE_ZIP_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
    }
)

#: Relationship types that make Office fetch and run or embed remote content
#: ("remote template injection").  Plain hyperlinks are external too but harmless.
_REMOTE_RELATIONSHIPS = ("attachedtemplate", "oleobject", "frame", "subdocument")
# Every pattern stops at the next "<" (or cell delimiter), so scanning stays linear
# whatever the input: no quantifier can run across a tag boundary and backtrack.
_RELATIONSHIP = re.compile(rb"<relationship\b[^<>]*>", re.IGNORECASE)
_DDE_FIELD = re.compile(
    rb"(?:instrtext[^<>]*>|instr=\")[ \t\r\n]*\"?[ \t\r\n]*dde(?:auto)?\b", re.IGNORECASE
)
#: Excel dynamic data exchange: ``=cmd|' /C calc'!A0`` runs a program when the sheet
#: opens.  "|" is no Excel operator, so ``application|topic!item`` is a DDE reference.
_DDE_LINK = re.compile(rb"<ddeLink\b", re.IGNORECASE)
_DDE_FORMULA = re.compile(rb"<f\b[^<>]*>[^<|]*\|[^<]*!", re.IGNORECASE)
_DDE_CELL = re.compile(rb"(?:^|[,;\t\r\n])[ \t]*\"?[=+\-@][^,;\t\r\n|]*\|[^,;\t\r\n]*!")
_CSV_OVERLAP = 4096
_VBA_PROJECT_UTF16 = "_VBA_PROJECT".encode("utf-16-le")
_OLE_SCAN_CHUNK = 4 * MiB


def _is_macro_member(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.endswith(("vbaproject.bin", "vbadata.xml"))
        or "/activex/" in f"/{lowered}"
        or lowered.startswith(("basic/", "scripts/"))  # OpenDocument macros
    )


@dataclass(frozen=True, slots=True)
class OfficeMacros(Check):
    """Refuse Office documents with VBA macros, ActiveX controls, DDE (Word fields, Excel
    links and formulas, and formulas in CSV files, which open in Excel) or remote
    templates.

    For legacy OLE2 files (``.doc``/``.xls``) the presence of a ``_VBA_PROJECT``
    stream is detected from the directory entries; XLM (Excel 4.0) macros in OLE2
    files are not detected - use :class:`~uploadshield.checks.YaraRules` or
    :class:`~uploadshield.checks.ClamAV` if you must accept those formats.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "office"

    block_external_references: bool = True
    max_part_bytes: int = 16 * MiB

    def applies(self, file: InspectedFile) -> bool:
        file_type = file.file_type
        return file_type is not None and (
            file_type.mime in OFFICE_ZIP_TYPES
            or file_type.container == "ole"
            or file_type.mime == "text/csv"
        )

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        file_type = file.file_type
        if file_type is not None and file_type.container == "ole":
            yield from self._run_ole(file)
        elif file_type is not None and file_type.mime == "text/csv":
            yield from self._run_csv(file)
        else:
            yield from self._run_zip(file)

    def _run_csv(self, file: InspectedFile) -> Iterator[Violation]:
        """CSV opens in Excel, which evaluates DDE formulas in cells."""
        carry = b""
        for chunk in file.iter_chunks():
            window = carry + chunk
            if _DDE_CELL.search(window):
                yield self._dde()
                return
            carry = window[-_CSV_OVERLAP:]

    def _run_ole(self, file: InspectedFile) -> Iterator[Violation]:
        carry = b""
        for chunk in file.iter_chunks(_OLE_SCAN_CHUNK):
            if _VBA_PROJECT_UTF16 in carry + chunk:
                yield self.violation(Code.OFFICE_MACROS, "Documents with macros are not allowed.")
                return
            carry = chunk[-len(_VBA_PROJECT_UTF16) :]

    def _run_zip(self, file: InspectedFile) -> Iterator[Violation]:
        entries = zip_entries(file) or []
        names = [e.filename for e in entries]
        if macros := [n for n in names if _is_macro_member(n)]:
            yield self.violation(
                Code.OFFICE_MACROS, "Documents with macros are not allowed.", parts=macros[:10]
            )
            return
        # Fields run from every part Word renders: body, headers, footers, notes, ...
        word_parts = [n for n in names if n.startswith("word/") and n.endswith(".xml")]
        for part in word_parts:
            if zip_search(file, part, _DDE_FIELD):
                yield self.violation(
                    Code.OFFICE_MACROS, "Documents with DDE fields are not allowed.", parts=[part]
                )
                return
        spreadsheet = [
            n
            for n in names
            if n.startswith(("xl/externalLinks/", "xl/worksheets/")) and n.endswith(".xml")
        ]
        for part in spreadsheet:
            pattern = _DDE_LINK if part.startswith("xl/externalLinks/") else _DDE_FORMULA
            if zip_search(file, part, pattern):
                yield self._dde(parts=[part])
                return
        if self.block_external_references and (targets := self._remote_targets(file, names)):
            yield self.violation(
                Code.OFFICE_EXTERNAL_REFERENCE,
                "The document loads content from external locations.",
                targets=targets[:10],
            )

    def _dde(self, **details: object) -> Violation:
        return self.violation(
            Code.OFFICE_MACROS,
            "Spreadsheets with DDE links or formulas are not allowed.",
            **details,
        )

    def _remote_targets(self, file: InspectedFile, names: list[str]) -> list[str]:
        targets: list[str] = []
        for rels in (n for n in names if n.endswith(".rels")):
            info = zip_member(file, rels)
            if info is not None and info.file_size > self.max_part_bytes:
                # Unreadable means unchecked: refuse rather than skip (fails closed).
                raise ContentTooLargeError(f"{rels} exceeds {self.max_part_bytes} bytes")
            xml = zip_read(file, rels, self.max_part_bytes) or b""
            for element in _RELATIONSHIP.findall(xml):
                lowered = element.lower()
                if b'targetmode="external"' not in lowered:
                    continue
                type_match = re.search(rb'type="([^"]*)"', lowered)
                rel_type = type_match.group(1).decode("latin-1") if type_match else ""
                if rel_type.rsplit("/", 1)[-1] in _REMOTE_RELATIONSHIPS:
                    target = re.search(rb'target="([^"]*)"', element, re.IGNORECASE)
                    targets.append(target.group(1).decode("latin-1") if target else rels)
        return targets
