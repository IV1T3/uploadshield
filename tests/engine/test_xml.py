"""XmlSafety: document type definitions in XML documents and Office/ODF/EPUB parts."""

from __future__ import annotations

import io
import zipfile

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, Upload, presets, validate
from uploadshield.checks.xml import XmlSafety, declares_dtd

XML = Policy(allowed_types={"application/xml"})
DTD = b'<!DOCTYPE r [<!ENTITY x "y">]>'


@pytest.mark.parametrize(
    ("head", "complete", "expected"),
    [
        (b"<?xml version='1.0'?><r/>", True, False),
        (b"<?xml version='1.0'?>" + DTD + b"<r/>", True, True),
        (b"<!ENTITY x 'y'><r/>", True, True),
        (b"\n  <!-- c -->\n<?pi?>\n<!doctype r>", True, True),  # any case, after noise
        (b"<?xml version='1.0'?><!-- unfinished", False, None),  # cut inside the prolog
        (b"<?xml version='1.0'?><!-- unfinished", True, False),  # complete: no DTD
        (b"not xml at all", True, False),
        (b"<\xc3\xa4rger/>", True, False),  # non-ASCII element names
    ],
)
def test_declares_dtd(head: bytes, complete: bool, expected: bool | None) -> None:
    assert declares_dtd(head, complete=complete) is expected


@pytest.mark.parametrize(
    ("encoding", "bom"),
    [
        ("utf-8", b"\xef\xbb\xbf"),
        ("utf-16-le", b"\xff\xfe"),
        ("utf-16-be", b"\xfe\xff"),
        ("utf-32-le", b"\xff\xfe\x00\x00"),
        ("utf-32-be", b"\x00\x00\xfe\xff"),
        ("utf-16-le", b""),  # recognisable from "<?" alone (XML 1.0, appendix F)
        ("utf-16-be", b""),
        ("utf-32-le", b""),
        ("utf-32-be", b""),
    ],
)
def test_dtds_are_found_in_every_encoding(encoding: str, bom: bytes) -> None:
    text = "<?xml version='1.0'?>" + DTD.decode() + "<r/>"
    assert declares_dtd(bom + text.encode(encoding), complete=True) is True
    clean = "<?xml version='1.0'?><r/>"
    assert declares_dtd(bom + clean.encode(encoding), complete=True) is False


def test_members_are_judged_by_what_they_hold_not_by_their_names() -> None:
    # Which members a program parses is decided by a document's relationships and
    # manifests, not by file extensions (security review, 2026-11-14): an XML document
    # with a DTD is refused under any name.
    document = b"<?xml version='1.0'?>" + DTD + b"<r/>"
    for name in ("word/document.dat", "word/media/image1.bin", "customXml/item1", "x.XML"):
        docx = corpus.ooxml("docx", extra={name: document})
        result = validate(Upload.from_bytes(docx, "a.docx"), presets.DOCUMENTS)
        assert result.codes == ("xml_dtd",), name
        assert result.violations[0].details["parts"] == [name]
    for encoding in ("utf-16", "utf-32"):
        wide = corpus.ooxml("docx", extra={"word/part.dat": document.decode().encode(encoding)})
        assert codes(wide, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)
    flagged = corpus.ooxml("docx", extra={"customXml/item1.xml": b"<?xml version='1.0'?>" + DTD})
    assert codes(flagged, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)


def test_members_that_are_not_xml_documents_are_left_alone() -> None:
    # Text that looks like a DTD somewhere inside a member does not make it an XML
    # document: only a prolog can declare one.
    extra = {
        "word/media/image1.png": corpus.png() + DTD,
        "word/media/image2.bin": b"\x00\x01\x02" + DTD + b"\xff" * 100_000,
        "docProps/notes.txt": b"A DTD looks like this: " + DTD,
        "word/embeddings/data.bin": b"<r>plain XML without a document type</r>",
    }
    assert codes(corpus.ooxml("docx", extra=extra), "a.docx", presets.DOCUMENTS) == ()


def test_every_entry_of_a_repeated_name_is_judged() -> None:
    clean, dtd = b"<?xml version='1.0'?><r/>", b"<?xml version='1.0'?>" + DTD + b"<r/>"
    with zipfile.ZipFile(io.BytesIO(corpus.ooxml("docx"))) as zf:
        base = [(name, zf.read(name)) for name in zf.namelist()]
    for pair in ([dtd, clean], [clean, dtd]):
        entries = base + [("customXml/item1.xml", data) for data in pair]
        docx = corpus.build_zip_with_repeated_names(entries)
        assert codes(docx, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)


@pytest.mark.parametrize(
    "encoding", ["UTF-7", "utf-7", "ISO-2022-JP", "Shift_JIS", "EUC-KR", "GB2312", "IBM037", "x"]
)
def test_xml_in_an_encoding_that_cannot_be_read_reliably_cannot_be_judged(encoding: str) -> None:
    # "+ADw-!DOCTYPE" is "<!DOCTYPE" in UTF-7: no DTD is visible here, yet a parser that
    # honours the declaration finds one (security review, 2026-11-14).
    head = f'<?xml version="1.0" encoding="{encoding}"?>+ADw-!DOCTYPE r +AFs-+AF0-+AD4-'.encode()
    assert declares_dtd(head + b"<r/>", complete=True) is None
    assert codes(head + b"<r/>", "a.xml", XML) == ("xml_dtd",)
    docx = corpus.ooxml("docx", extra={"customXml/item1.xml": head + b"<r/>"})
    assert codes(docx, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)
    renamed = corpus.ooxml("docx", extra={"customXml/item1.dat": head + b"<r/>"})
    assert codes(renamed, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)


def test_ebcdic_xml_cannot_be_judged() -> None:
    ebcdic = '<?xml version="1.0" encoding="IBM037"?><r/>'.encode("cp037")
    assert declares_dtd(ebcdic, complete=True) is None
    docx = corpus.ooxml("docx", extra={"customXml/item1.dat": ebcdic})
    assert codes(docx, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)


@pytest.mark.parametrize(
    "encoding", ["UTF-8", "us-ascii", "ISO-8859-1", "iso-8859-15", "windows-1252", "latin1"]
)
def test_xml_in_encodings_that_leave_ascii_alone_is_judged(encoding: str) -> None:
    prolog = f"<?xml version='1.0' encoding='{encoding}'?>".encode()
    assert declares_dtd(prolog + b"<r>\xe9</r>", complete=True) is False
    assert declares_dtd(prolog + DTD + b"<r/>", complete=True) is True


def test_the_head_size_is_configurable_and_plain_text_is_ignored() -> None:
    padded = b"<?xml version='1.0'?>" + b" " * 2000 + b"<r/>"
    tiny = XML.replace(content_checks=(XmlSafety(head_bytes=1024),))
    assert codes(padded, "a.xml", tiny) == ("xml_dtd",)  # prolog longer than the head
    assert codes(padded, "a.xml", XML) == ()
    assert codes(b"just text", "a.txt", presets.DOCUMENTS) == ()  # not XML: not checked
