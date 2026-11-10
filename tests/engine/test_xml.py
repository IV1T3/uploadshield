"""XmlSafety: document type definitions in XML documents and Office/ODF/EPUB parts."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, presets
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


def test_only_xml_parts_of_documents_are_read() -> None:
    # A DTD-like text in a non-XML part (an embedded image, say) is not a DTD.
    docx = corpus.ooxml("docx", extra={"word/media/image1.bin": b"<?xml?>" + DTD})
    assert codes(docx, "a.docx", presets.DOCUMENTS) == ()
    flagged = corpus.ooxml("docx", extra={"customXml/item1.xml": b"<?xml version='1.0'?>" + DTD})
    assert codes(flagged, "a.docx", presets.DOCUMENTS) == ("xml_dtd",)


def test_the_head_size_is_configurable_and_plain_text_is_ignored() -> None:
    padded = b"<?xml version='1.0'?>" + b" " * 2000 + b"<r/>"
    tiny = XML.replace(content_checks=(XmlSafety(head_bytes=1024),))
    assert codes(padded, "a.xml", tiny) == ("xml_dtd",)  # prolog longer than the head
    assert codes(padded, "a.xml", XML) == ()
    assert codes(b"just text", "a.txt", presets.DOCUMENTS) == ()  # not XML: not checked
