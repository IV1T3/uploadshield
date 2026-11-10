"""OfficeMacros: macros, DDE and remote templates in OOXML, ODF and OLE2."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, presets
from uploadshield.checks import (
    OfficeMacros,
)

OOXML = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_office_documents() -> None:
    assert codes(corpus.ooxml("docx"), "a.docx") == ()
    assert codes(corpus.ooxml("xlsx"), "a.xlsx") == ()
    assert codes(corpus.odt(), "a.odt") == ()
    assert codes(corpus.docx_with_external_hyperlink(), "a.docx") == ()


def test_macro_documents_are_refused() -> None:
    # A real macro-enabled document is a different (disallowed) type, whatever its name.
    assert codes(corpus.ooxml("docm"), "a.docx") == ("type_not_allowed",)
    # Macros smuggled into a document that claims to be a plain .docx.
    smuggled = corpus.ooxml("docx", extra={"word/vbaProject.bin": b"\xd0\xcf\x11\xe0"})
    assert codes(smuggled, "a.docx") == ("office_macros",)
    assert codes(corpus.odt(extra={"Basic/Standard/Module1.xml": b"<x/>"}), "a.odt") == (
        "office_macros",
    )
    assert codes(corpus.docx_with_dde(), "a.docx") == ("office_macros",)
    assert codes(corpus.docx_with_remote_template(), "a.docx") == ("office_external_reference",)
    allow_remote = presets.DOCUMENTS.replace(
        content_checks=(OfficeMacros(block_external_references=False),)
    )
    assert codes(corpus.docx_with_remote_template(), "a.docx", allow_remote) == ()


def test_legacy_ole_documents() -> None:
    ole_policy = Policy(allowed_types={"application/x-ole-storage"})
    assert codes(corpus.ole(), "a.doc", ole_policy) == ()
    assert codes(corpus.ole(macros=True), "a.xls", ole_policy) == ("office_macros",)
    assert codes(corpus.ole(), "a.msi", ole_policy) == ("filename_dangerous_extension",)


DDE = (
    b'<w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" '
    b"</w:instrText></w:r>"
)


@pytest.mark.parametrize(
    "part", ["word/header1.xml", "word/footer2.xml", "word/footnotes.xml", "word/comments.xml"]
)
def test_dde_fields_in_any_word_part_are_refused(part: str) -> None:
    document = corpus.ooxml("docx", extra={part: b"<w:hdr><w:p>" + DDE + b"</w:p></w:hdr>"})
    assert codes(document, "a.docx") == ("office_macros",)


def test_dde_fields_in_parts_larger_than_the_read_limit_are_refused() -> None:
    padding = b"<w:p>" + b"x" * 50_000 + b"</w:p>"
    document = corpus.ooxml("docx", document=b"<w:document>" + padding + DDE + b"</w:document>")
    small = presets.DOCUMENTS.replace(content_checks=(OfficeMacros(max_part_bytes=1024),))
    assert codes(document, "a.docx", small) == ("office_macros",)


def test_relationship_parts_too_large_to_read_are_refused() -> None:
    rels = b"<Relationships>" + b" " * 5000 + b"</Relationships>"
    document = corpus.ooxml("docx", extra={"word/_rels/document.xml.rels": rels})
    small = presets.DOCUMENTS.replace(content_checks=(OfficeMacros(max_part_bytes=1024),))
    assert codes(document, "a.docx", small) == ("check_failed",)


@pytest.mark.parametrize(
    "csv",
    [
        b"x\n=" + b"a|" * 20_000 + b"\n",
        b"x\n" + b"=cmd" * 20_000 + b"\n",
        b"x\n" + b"|" * 50_000 + b"\n",
    ],
)
def test_csv_formula_scanning_is_linear(csv: bytes) -> None:
    import time

    started = time.perf_counter()
    codes(csv, "a.csv", presets.DOCUMENTS)
    assert time.perf_counter() - started < 2
