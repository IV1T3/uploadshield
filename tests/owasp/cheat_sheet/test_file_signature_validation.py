"""OWASP File Upload Cheat Sheet - File Signature Validation.

The signature identifies the format; it is never trusted on its own: the formats are
decoded or parsed completely, and a valid header in front of a hostile body is refused.
"""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import BuiltinSniffer, InspectedFile, Upload

owasp = pytest.mark.owasp


@owasp("signature.check")
@pytest.mark.parametrize(
    ("data", "mime"),
    [
        (corpus.png(), "image/png"),
        (corpus.image("JPEG"), "image/jpeg"),
        (corpus.image("GIF"), "image/gif"),
        (corpus.image("WEBP"), "image/webp"),
        (corpus.pdf(), "application/pdf"),
        (
            corpus.ooxml("docx"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (corpus.ooxml("docm"), "application/vnd.ms-word.document.macroenabled.12"),
        (corpus.odt(), "application/vnd.oasis.opendocument.text"),
        (corpus.epub(), "application/epub+zip"),
        (corpus.mp3(), "audio/mpeg"),
        (corpus.pe_executable(), "application/vnd.microsoft.portable-executable"),
        (corpus.ELF, "application/x-elf"),
        (corpus.SHELL_SCRIPT, "application/x-sh"),
        (corpus.PHP_SHELL, "application/x-httpd-php"),
        (corpus.HTML, "text/html"),
        (corpus.EPS, "application/postscript"),
    ],
)
def test_the_format_comes_from_the_bytes(data: bytes, mime: str) -> None:
    file_type = InspectedFile(Upload.from_bytes(data, "upload"), BuiltinSniffer()).file_type
    assert file_type is not None
    assert file_type.mime == mime


@owasp("signature.check")
@pytest.mark.parametrize(
    ("name", "data"),
    [("a.gif", corpus.png()), ("a.png", corpus.image("JPEG")), ("a.pdf", corpus.image("GIF"))],
)
def test_renamed_formats_are_caught(app: App, name: str, data: bytes) -> None:
    assert app.post("/legacy", file(name, data)).codes == ["extension_mismatch"]


@owasp("signature.not-alone")
@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        # a genuine signature in front of a script
        ("a.gif", b"GIF89a<?php system($_GET['c']); ?>", {"embedded_code", "image_corrupt"}),
        ("a.png", b"\x89PNG\r\n\x1a\n" + corpus.PHP_SHELL, {"embedded_code", "image_corrupt"}),
        # a genuine header with a broken body
        ("a.png", corpus.png()[:40] + b"\x00" * 64, {"image_corrupt"}),
        ("a.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 200, {"image_corrupt"}),
        # two formats in one file
        ("a.gif", corpus.image("GIF") + corpus.build_zip({"x.class": b"\xca\xfe"}), {"polyglot"}),
        ("a.jpg", corpus.image("JPEG", comment=b"%PDF-1.4 hidden"), {"polyglot"}),
        # a container header without a container
        (
            "a.docx",
            b"PK\x03\x04" + b"\x00" * 100,
            {"archive_corrupt", "type_unknown", "type_not_allowed"},
        ),
    ],
    ids=["gif-php", "png-php", "png-truncated", "jpeg-empty", "gifar", "jpeg-pdf", "zip-header"],
)
def test_a_valid_signature_is_not_enough(
    app: App, name: str, data: bytes, expected: set[str]
) -> None:
    reply = app.post("/legacy", file(name, data))
    assert reply.status in (400, 415)
    assert set(reply.codes) & expected, reply.codes


@owasp("signature.not-alone")
def test_magic_bytes_alone_identify_nothing() -> None:
    for magic in (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF89a", b"%PDF-", b"PK\x03\x04"):
        assert codes(magic, "x.png") != ()
