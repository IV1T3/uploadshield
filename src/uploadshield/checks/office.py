"""Macros and remote references in Office documents (OOXML, ODF, legacy OLE2)."""

from __future__ import annotations

import codecs
import itertools
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from xml.parsers import expat

from uploadshield.core.check import Check
from uploadshield.core.containers import zip_chunks, zip_entries
from uploadshield.core.types import KiB, MiB
from uploadshield.core.upload import ContentTooLargeError
from uploadshield.core.violations import Code, Violation

from ._xmltext import checkable_encoding, declares_dtd, detected_encoding, starts_as_xml

if TYPE_CHECKING:
    import zipfile
    from collections.abc import Iterable, Iterator

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
_REMOTE_RELATIONSHIPS = frozenset({"attachedtemplate", "oleobject", "frame", "subdocument"})
#: Relationship types of the parts that hold macros, whatever those parts are called.
_MACRO_RELATIONSHIPS = frozenset(
    {"vbaproject", "vbaprojectsignature", "wordvbadata", "xlmacrosheet", "xlintlmacrosheet"}
)
#: What an element means to this check, by its name without prefix.  The text of an
#: ``instrText`` (also when tracked as deleted) is a field instruction, the text of an
#: ``f`` or a ``definedName`` a spreadsheet formula.
_OTHER, _FIELD_TEXT, _FORMULA, _FIELD_MARK, _SIMPLE_FIELD, _DDE_LINK, _RELATIONSHIP = range(7)
_ELEMENTS = {
    "instrtext": _FIELD_TEXT,
    "delinstrtext": _FIELD_TEXT,
    "f": _FORMULA,
    "definedname": _FORMULA,
    "fldchar": _FIELD_MARK,
    "fldsimple": _SIMPLE_FIELD,
    "ddelink": _DDE_LINK,
    "relationship": _RELATIONSHIP,
}
#: What a part must contain to hold any of that: one of the element names - names cannot
#: be written with character references, and a part with a DTD (whose entities could
#: spell one out) is never read - or, for a DDE formula, its "|", as it is or as a
#: character reference (124; references with leading zeros are counted to be safe).
#: Searching for these is much cheaper than parsing, so parts without them, the bulk
#: of every document, are not parsed at all.  (Plain substring searches of the
#: lowercased bytes: one pattern with unrelated alternatives is many times slower.)
_TRIGGERS = (b"instrtext", b"fldsimple", b"ddelink", b"|")
_PIPE_REFERENCE = re.compile(rb"&#(?:124;|x7c;|0|x0)")
_TRIGGER_OVERLAP = 16
#: Limits on what is parsed.  An XML parser reports every element to Python and keeps
#: state for every open one, so what it may be made to do is bounded: a document nested
#: deeper, with a single piece of markup larger, or with more elements in the parts that
#: have to be parsed than these cannot be checked, and is refused.
_MAX_DEPTH = 1_000
_MAX_MARKUP = 1 * MiB
_MAX_ELEMENTS = 5_000_000
#: Qualified names whose meaning is remembered while a part is read (the rest is
#: looked up each time: names are the uploader's, the memory must not be).
_REMEMBERED_NAMES = 4_096
#: A field whose instruction starts with DDE or DDEAUTO (dynamic data exchange): judged
#: when the instruction is complete, and as soon as what follows the word shows that
#: the word is complete.
_DDE_FIELD = re.compile(r"dde(?:auto)?(?![a-z0-9_])", re.IGNORECASE)
_DDE_FIELD_SO_FAR = re.compile(r"dde(?:auto)?[^a-z0-9_]", re.IGNORECASE)
#: What may come before a field's instruction, and how much of one is kept to judge it.
_FIELD_LEAD = " \t\r\n\"'"
_FIELD_HEAD = 16
_MAX_FIELD_DEPTH = 64
#: expat's "unknown encoding" and "encoding specified in XML declaration is incorrect".
_ENCODING_ERRORS = frozenset({18, 19})

#: Excel dynamic data exchange in a CSV cell: ``=cmd|' /C calc'!A0`` runs a program when
#: the sheet opens.  "|" is no Excel operator, so ``application|topic!item`` is a DDE
#: reference.  A cell starts after a delimiter and is either quoted - then it runs to its
#: closing quote, delimiters included, with ``""`` for a quote - or bare.
#:
#: Which character delimits the cells of a bare row is not known here (Excel takes ";"
#: in many locales, or whatever a "sep=" line names), so only the application name must
#: sit in the cell that starts the formula: topic and item may hold any of them, up to
#: the end of the row.  Of all such cells in a row only the first one matters - what
#: follows a later one follows the first one too - so the pattern commits to it (the
#: atomic group) instead of trying every cell against the rest of the row, which would
#: be quadratic.  Every other part stops at the end of its cell.
_CELL = rb"[,;\t\r\n][ \t]*"


def _first_in_row(cell: bytes) -> bytes:
    """From a line break to the *earliest* bare cell of that row that starts like
    ``cell``: the row's first cell, or else the leftmost one behind a delimiter (the
    lazy run stops at the first delimiter that such a cell follows)."""
    return rb"[\r\n](?>[ \t]*" + cell + rb"|[^\r\n]*?[,;\t][ \t]*" + cell + rb")"


_DDE_CELL = re.compile(
    _CELL + rb"\"[ \t]*[=+\-@](?:[^\"|]|\"\")*\|(?:[^\"]|\"\")*!"
    rb"|" + _first_in_row(rb"[=+\-@][^,;\t\r\n|]*\|") + rb"[^\r\n]*!"
)
#: Spreadsheet functions that fetch or send data when the sheet opens or a cell is
#: clicked (Excel, LibreOffice, Google Sheets).
_DATA_FUNCTION = (
    rb"(?<![a-z0-9_.])(?:hyperlink|webservice|filterxml|rtd|dde|import(?:xml|data|html|feed|range))"
)
#: A formula cell that calls one of them.  After "=" the call may sit anywhere in the
#: formula, which in a bare row may run on past "," or ";" (see above); after "+", "-"
#: or "@", which also start numbers and ordinary text ("-5", "- see hyperlink (below)"),
#: only in the same cell and when its bracket follows directly.
_DATA_CELL = re.compile(
    _CELL + rb"\"[ \t]*(?:=(?:[^\"]|\"\")*?" + _DATA_FUNCTION + rb"[ \t]*\("
    rb"|[+\-@](?:[^\"]|\"\")*?" + _DATA_FUNCTION + rb"\()"
    rb"|" + _CELL + rb"[+\-@][^,;\t\r\n]*?" + _DATA_FUNCTION + rb"\("
    rb"|" + _first_in_row(rb"=") + rb"[^\r\n]*?" + _DATA_FUNCTION + rb"[ \t]*\(",
    re.IGNORECASE,
)
#: Longer than any cell a spreadsheet accepts (Excel: 32,767 characters), so a cell cut
#: by a chunk boundary is seen whole in the next window.
_CSV_OVERLAP = 128 * KiB
_VBA_PROJECT_UTF16 = "_VBA_PROJECT".encode("utf-16-le")
_OLE_SCAN_CHUNK = 4 * MiB


def _is_macro_member(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.endswith(("vbaproject.bin", "vbadata.xml"))
        or "/activex/" in f"/{lowered}"
        or lowered.startswith(("basic/", "scripts/"))  # OpenDocument macros
    )


class _Uncheckable(Exception):  # noqa: N818 - a verdict, not an error
    """A part that cannot be read the way an Office application reads it."""


class _Found(Exception):  # noqa: N818 - control flow, not an error
    """The part holds what the check refuses: there is no need to read on."""


def _attribute(attributes: dict[str, str], wanted: str) -> str:
    """The value of the attribute ``wanted``, whatever its prefix and case."""
    for name, value in attributes.items():
        if name.rpartition(":")[2].lower() == wanted:
            return value
    return ""


class _Field:
    """The start of a field's instruction, which names what the field does."""

    __slots__ = ("code",)

    def __init__(self, code: str = "") -> None:
        self.code = ""
        self.add(code)

    def add(self, text: str) -> None:
        if len(self.code) >= _FIELD_HEAD:
            return
        if not self.code:
            text = text.lstrip(_FIELD_LEAD)
        self.code = (self.code + text[:_FIELD_HEAD])[:_FIELD_HEAD]

    @property
    def is_dde(self) -> bool:
        return _DDE_FIELD.match(self.code) is not None

    @property
    def is_dde_already(self) -> bool:
        """Whether the instruction read so far is DDE whatever follows."""
        return _DDE_FIELD_SO_FAR.match(self.code) is not None


class _Part:
    """What one XML part of a document asks an Office application to do.

    Filled by an XML parser, so it sees what the application sees: attributes in either
    kind of quotes, character references, CDATA sections, any supported encoding.  A
    field's instruction is put together from all the runs it is spread over, as Word
    does; fields may nest, and each one is judged by its own instruction.

    ``elements`` is how many elements may still be read (see ``_MAX_ELEMENTS``); what is
    left of it afterwards is the budget of the next part.
    """

    def __init__(self, *, relationships: bool, elements: int) -> None:
        self.relationships = relationships  # a .rels part: its relationships count
        self.elements = elements
        self.dde_field = False
        self.dde_link = False
        self.macros = False
        self.remote: list[str] = []
        self._names: dict[str, int] = {}  # what the names seen so far mean
        self._open: list[int] = []  # what each open element means, innermost last
        self._fields: list[_Field] = []  # the fields being read, innermost last
        self._loose = _Field()  # instruction text outside any begin/end pair
        self._pipe = False  # the formula being read has shown its "|"

    def start(self, name: str, attributes: dict[str, str]) -> None:
        self.elements -= 1
        if self.elements < 0:
            raise _Uncheckable("too many elements")
        if len(self._open) >= _MAX_DEPTH:
            raise _Uncheckable("elements nested too deeply")
        kind = self._names.get(name)
        if kind is None:
            kind = _ELEMENTS.get(name.rpartition(":")[2].lower(), _OTHER)
            if len(self._names) < _REMEMBERED_NAMES:
                self._names[name] = kind
        self._open.append(kind)
        if kind == _FORMULA:
            self._pipe = False
        elif kind > _FORMULA:
            self._act(kind, attributes)

    def _act(self, kind: int, attributes: dict[str, str]) -> None:
        """A field mark, a simple field, a DDE link or a relationship started."""
        if kind == _FIELD_MARK:
            mark = _attribute(attributes, "fldchartype").strip().lower()
            if mark == "begin":
                if len(self._fields) >= _MAX_FIELD_DEPTH:
                    raise _Uncheckable("fields nested too deeply")
                self._fields.append(_Field())
            elif mark == "end" and self._fields:
                self._judge(self._fields.pop())
        elif kind == _SIMPLE_FIELD:
            self._judge(_Field(_attribute(attributes, "instr")))
        elif kind == _DDE_LINK:
            self.dde_link = True
            raise _Found
        elif kind == _RELATIONSHIP and self.relationships:
            self._relationship(attributes)

    def end(self, name: str) -> None:
        if self._open:
            self._open.pop()

    def text(self, data: str) -> None:
        if not self._open:
            return
        innermost = self._open[-1]
        if innermost == _FIELD_TEXT:
            field = self._fields[-1] if self._fields else self._loose
            field.add(data)
            if field.is_dde_already:
                self.dde_field = True
                raise _Found
        elif innermost == _FORMULA:
            if not self._pipe:
                cut = data.find("|")
                if cut == -1:
                    return
                self._pipe, data = True, data[cut:]
            if "!" in data:  # application|topic!item
                self.dde_link = True
                raise _Found

    def finish(self) -> None:
        """The part ended: judge the fields that were never closed."""
        for unfinished in (*self._fields, self._loose):
            if unfinished.is_dde:
                self.dde_field = True

    def _judge(self, finished: _Field) -> None:
        if finished.is_dde:
            self.dde_field = True
            raise _Found

    def _relationship(self, attributes: dict[str, str]) -> None:
        kind = _attribute(attributes, "type").strip().rsplit("/", 1)[-1].lower()
        if kind in _MACRO_RELATIONSHIPS:
            self.macros = True
            raise _Found
        external = _attribute(attributes, "targetmode").strip().lower() == "external"
        if external and kind in _REMOTE_RELATIONSHIPS and len(self.remote) < 10:
            self.remote.append(_attribute(attributes, "target")[:200])


def _refuse_doctype(*_: object) -> None:
    # Entities declared in a DTD could spell out anything the check looks for.
    raise _Uncheckable("document type definition")


def _parse(chunks: Iterable[bytes], part: _Part) -> None:
    """Feed ``chunks`` to an XML parser that reports to ``part``.

    Markup that is not well-formed ends the reading without a word: no XML parser gets
    past that point, so neither does the application.  Raises :class:`_Uncheckable` for
    a part that a parser may read differently than this one does, or that asks for more
    than the limits above allow.
    """
    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartElementHandler = part.start
    parser.EndElementHandler = part.end
    parser.CharacterDataHandler = part.text
    parser.StartDoctypeDeclHandler = _refuse_doctype
    fed = 0
    try:
        for chunk in chunks:
            parser.Parse(chunk)
            fed += len(chunk)
            # Text is handed over as it arrives; a tag, a comment or a processing
            # instruction only once it is complete.  Until then the parser keeps it
            # (and older versions read it again from its start with every piece).
            if fed - parser.CurrentByteIndex > _MAX_MARKUP:
                raise _Uncheckable("markup too large")
        parser.Parse(b"", True)  # noqa: FBT003 - expat's positional "is final" flag
    except _Found:
        return
    except expat.ExpatError as error:
        if error.code in _ENCODING_ERRORS:
            raise _Uncheckable("encoding") from None
    except (LookupError, ValueError):  # an encoding the parser has no table for
        raise _Uncheckable("encoding") from None
    part.finish()


def _may_matter(pieces: Iterable[bytes], encoding: str) -> bool:
    """Whether a part contains anything that could make :class:`_Part` find something
    (see ``_TRIGGERS``): a quick search of its bytes, UTF-16 read as such."""
    decoder = codecs.getincrementaldecoder(encoding)("replace") if "16" in encoding else None
    carry = b""
    for piece in pieces:
        window = (carry + (decoder.decode(piece).encode("utf-8") if decoder else piece)).lower()
        if any(trigger in window for trigger in _TRIGGERS) or _PIPE_REFERENCE.search(window):
            return True
        carry = window[-_TRIGGER_OVERLAP:]
    return False


def _read_part(file: InspectedFile, entry: zipfile.ZipInfo, part: _Part) -> bool:
    """Read the member ``entry`` into ``part``; ``False`` if it is not XML at all.

    Raises :class:`_Uncheckable` for XML that may read differently elsewhere: in an
    encoding other than UTF-8 and UTF-16 (what Office documents may use, and what the
    parser reads like any other program), or with a document type definition.
    """
    chunks = zip_chunks(file, entry)
    try:
        head = next(chunks, b"")
        if not starts_as_xml(head):
            return False
        encoding = detected_encoding(head)[0]
        if not checkable_encoding(head) or encoding.startswith("utf-32"):
            raise _Uncheckable("encoding")
        more = next(chunks, None)
        if declares_dtd(head, complete=more is None) is not False:
            raise _Uncheckable("document type definition")
        pieces = (head,) if more is None else itertools.chain((head, more), chunks)
        # Relationship parts are small and always read; any other part only if it
        # holds something that could matter.
        if not part.relationships and not _may_matter(pieces, encoding):
            return True
    finally:
        chunks.close()
    if more is None:
        _parse((head,), part)
        return True
    again = zip_chunks(file, entry)  # the search above used the pieces up
    try:
        _parse(again, part)
    finally:
        again.close()
    return True


def _csv_chunks(file: InspectedFile) -> Iterator[bytes]:
    """The file in pieces, as ASCII-compatible bytes: spreadsheets open UTF-16 CSV too."""
    decoder: codecs.IncrementalDecoder | None = None
    for index, chunk in enumerate(file.iter_chunks()):
        if index == 0 and chunk.startswith((b"\xff\xfe", b"\xfe\xff")):
            decoder = codecs.getincrementaldecoder("utf-16")("replace")
        yield decoder.decode(chunk).encode("utf-8") if decoder else chunk


@dataclass(frozen=True, slots=True)
class OfficeMacros(Check):
    """Refuse Office documents with VBA macros, ActiveX controls, DDE (Word fields, Excel
    links and formulas, and formulas in CSV files, which open in Excel) or remote
    templates.

    The parts of a document are read with an XML parser, whatever they are called:
    which part plays which role is decided by the document's relationships, not by its
    file names.  A part that cannot be read the way Office reads it - it declares a
    document type, or an encoding other than UTF-8 and UTF-16 - is refused, and so is a
    document that asks more of the parser than it is given: elements nested more than
    1,000 deep, a single tag or comment of more than 1 MiB, or more than 5 million
    elements in the parts that hold a field, a DDE link or a "|".

    In CSV files, formulas that fetch or send data (``HYPERLINK``, ``WEBSERVICE``,
    ``IMPORTXML``, ...) are refused too (``block_data_formulas``).

    For legacy OLE2 files (``.doc``/``.xls``) the presence of a ``_VBA_PROJECT``
    stream is detected from the directory entries; XLM (Excel 4.0) macros in OLE2
    files are not detected - use :class:`~uploadshield.checks.YaraRules` or
    :class:`~uploadshield.checks.ClamAV` if you must accept those formats.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "office"

    block_external_references: bool = True
    max_part_bytes: int = 16 * MiB
    block_data_formulas: bool = True

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
        """CSV opens in Excel, which evaluates the formulas in its cells."""
        carry = b"\n"  # the first cell starts a line like any other
        for chunk in _csv_chunks(file):
            window = carry + chunk
            if _DDE_CELL.search(window):
                yield self._dde()
                return
            if self.block_data_formulas and _DATA_CELL.search(window):
                yield self.violation(
                    Code.OFFICE_MACROS,
                    "Spreadsheets with formulas that fetch or send data are not allowed.",
                    reason="data_formula",
                )
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
        if macros := [e.filename for e in entries if _is_macro_member(e.filename)]:
            yield self._macros(macros)
            return
        remote: list[str] = []
        unchecked: list[str] = []
        elements = _MAX_ELEMENTS  # for all the parts that have to be parsed, together
        # Every entry is read, also when names repeat: readers pick either one.
        for entry in entries:
            if entry.is_dir():
                continue
            name = entry.filename
            relationships = name.lower().endswith(".rels")
            if relationships and entry.file_size > self.max_part_bytes:
                # Unreadable means unchecked: refuse rather than skip (fails closed).
                raise ContentTooLargeError(f"{name} exceeds {self.max_part_bytes} bytes")
            part = _Part(relationships=relationships, elements=elements)
            try:
                if not _read_part(file, entry, part):
                    continue
            except _Uncheckable:
                unchecked.append(name)
                continue
            finally:
                elements = max(part.elements, 0)
            if part.macros:
                yield self._macros([name])
                return
            if part.dde_field:
                yield self.violation(
                    Code.OFFICE_MACROS, "Documents with DDE fields are not allowed.", parts=[name]
                )
                return
            if part.dde_link:
                yield self._dde(parts=[name])
                return
            remote += [target or name for target in part.remote]
        if unchecked:
            yield self.violation(
                Code.OFFICE_MACROS,
                "The document has parts that cannot be checked for macros and fields.",
                reason="uncheckable",
                parts=unchecked[:10],
            )
        elif self.block_external_references and remote:
            yield self.violation(
                Code.OFFICE_EXTERNAL_REFERENCE,
                "The document loads content from external locations.",
                targets=remote[:10],
            )

    def _macros(self, parts: list[str]) -> Violation:
        return self.violation(
            Code.OFFICE_MACROS, "Documents with macros are not allowed.", parts=parts[:10]
        )

    def _dde(self, **details: object) -> Violation:
        return self.violation(
            Code.OFFICE_MACROS,
            "Spreadsheets with DDE links or formulas are not allowed.",
            **details,
        )
