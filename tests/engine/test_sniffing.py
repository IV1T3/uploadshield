from __future__ import annotations

from typing import IO, cast

import pytest

from tests.support import corpus
from uploadshield import BuiltinSniffer, ChainedSniffer, InspectedFile, MagicSniffer, Upload
from uploadshield.core.sniffing import is_binary
from uploadshield.core.types import (
    FileType,
    format_size,
    get_type,
    register_type,
    resolve_mime,
    types_for_extension,
)


def sniff(data: bytes, name: str = "x") -> str | None:
    file = InspectedFile(Upload.from_bytes(data, name), BuiltinSniffer())
    return file.detected_type.mime if file.detected_type else None


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (corpus.png(), "image/png"),
        (corpus.image("JPEG"), "image/jpeg"),
        (corpus.image("GIF"), "image/gif"),
        (corpus.image("WEBP"), "image/webp"),
        (corpus.image("BMP"), "image/bmp"),
        (corpus.image("TIFF"), "image/tiff"),
        # square: Pillow < 11 writes an icon without images for 16x12
        (corpus.image("ICO", size=(16, 16)), "image/vnd.microsoft.icon"),
        (corpus.pdf(), "application/pdf"),
        (
            corpus.ooxml("docx"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (
            corpus.ooxml("xlsx"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        (
            corpus.ooxml("pptx"),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        (corpus.ooxml("docm"), "application/vnd.ms-word.document.macroenabled.12"),
        (corpus.odt(), "application/vnd.oasis.opendocument.text"),
        (corpus.build_zip({"a.txt": b"x"}), "application/zip"),
        (corpus.build_zip({"META-INF/MANIFEST.MF": b"x"}), "application/java-archive"),
        (corpus.ole(), "application/x-ole-storage"),
        (corpus.pe_executable(), "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF\x02\x01\x01" + b"\x00" * 60, "application/x-elf"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 40, "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 40, "application/java-vm"),
        (corpus.mp3(), "audio/mpeg"),
        (b"\xff\xfb\x90\x64" + b"\x00" * 100, "audio/mpeg"),
        (b"\xff\xf1\x50\x80" + b"\x00" * 100, "audio/aac"),
        (corpus.wav(), "audio/wav"),
        (b"OggS\x00\x02" + b"\x00" * 50, "audio/ogg"),
        (b"fLaC\x00\x00\x00\x22" + b"\x00" * 50, "audio/flac"),
        (corpus.mp4(), "video/mp4"),
        (b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ", "video/quicktime"),
        (b"\x00\x00\x00\x1cftypmif1\x00\x00\x00\x00mif1avifmiaf", "image/avif"),
        (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic", "image/heic"),
        (corpus.webm(), "video/webm"),
        (b"\x1a\x45\xdf\xa3\x9f\x42\x82\x88matroska" + b"\x00" * 20, "video/x-matroska"),
        (b"RIFF\x00\x00\x00\x00AVI LIST" + b"\x00" * 20, "video/x-msvideo"),
        (b"\x00\x00\x01\xba\x44" + b"\x00" * 20, "video/mpeg"),
        (b"\x1f\x8b\x08\x00" + b"\x00" * 20, "application/gzip"),
        (b"BZh91AY&SY" + b"\x00" * 20, "application/x-bzip2"),
        (b"\xfd7zXZ\x00\x00" + b"\x00" * 20, "application/x-xz"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 20, "application/x-7z-compressed"),
        (b"Rar!\x1a\x07\x00" + b"\x00" * 20, "application/vnd.rar"),
        (b"a" * 257 + b"ustar\x0000" + b"\x00" * 300, "application/x-tar"),
        (b"SQLite format 3\x00" + b"\x00" * 100, "application/vnd.sqlite3"),
        (b"\x00asm\x01\x00\x00\x00", "application/wasm"),
        (b"{\\rtf1\\ansi hello}", "application/rtf"),
        (b"%!PS-Adobe-3.0\n", "application/postscript"),
    ],
)
def test_binary_signatures(data: bytes, expected: str) -> None:
    assert sniff(data) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"hello world\n", "text/plain"),
        (b"\xef\xbb\xbfutf-8 with bom", "text/plain"),
        ("café crème".encode("cp1252"), "text/plain"),  # legacy-encoded CSV/TXT
        ("text".encode("utf-16"), "text/plain"),
        (b"<!DOCTYPE html><html><body>x</body></html>", "text/html"),
        (b"  \n<script>alert(1)</script>", "text/html"),
        (b"<p>paragraph</p>", "text/html"),
        (b"<!-- comment --><b>bold</b>", "text/html"),
        (b"<?xml version='1.0'?><html xmlns='http://www.w3.org/1999/xhtml'/>", "text/html"),
        (b"<!doctype html><html><body><svg><circle/></svg></body></html>", "text/html"),
        (corpus.svg(), "image/svg+xml"),
        (corpus.svg(prolog=False), "image/svg+xml"),
        (
            b'<?xml version="1.0"?>\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "x">\n<svg/>',
            "image/svg+xml",
        ),
        (
            b'<?xml version="1.0"?><!-- c --><svg:svg xmlns:svg="http://www.w3.org/2000/svg"/>',
            "image/svg+xml",
        ),
        (b'<?xml version="1.0"?><note><to>x</to></note>', "application/xml"),
        (b"<note>not xml without prolog</note>", "text/plain"),
        (b"<?php echo 1;", "application/x-httpd-php"),
        (b"#!/bin/sh\necho hi", "application/x-sh"),
        (b"MZ is also how this sentence starts", "text/plain"),
        (b"BMW cars are fast", "text/plain"),
        (b"ID3 tags explained", "text/plain"),
    ],
)
def test_text_classification(data: bytes, expected: str) -> None:
    assert sniff(data) == expected


def test_dos_mz_binary_is_executable() -> None:
    assert sniff(b"MZ\x00\x00" + b"\x00" * 20) == "application/vnd.microsoft.portable-executable"


def test_random_binary_is_unknown() -> None:
    assert sniff(b"\x00\x01\x02\x03binary junk") is None


def test_extension_refines_text_but_never_contradicts_content() -> None:
    as_csv = InspectedFile(Upload.from_bytes(b"a,b\n1,2", "data.csv"), BuiltinSniffer())
    assert as_csv.file_type is not None
    assert as_csv.file_type.mime == "text/csv"
    png_named_csv = InspectedFile(Upload.from_bytes(corpus.png(), "x.csv"), BuiltinSniffer())
    assert png_named_csv.file_type is not None
    assert png_named_csv.file_type.mime == "image/png"


def test_inspected_file_restores_stream_position() -> None:
    upload = Upload.from_bytes(corpus.png(), "a.png")
    upload.stream.seek(3)
    file = InspectedFile(upload, BuiltinSniffer())
    file.head()
    _ = file.sha256
    assert upload.stream.tell() == 3


def test_extensions_parsing() -> None:
    file = InspectedFile(Upload.from_bytes(b"x", "Archive.Tar.GZ"), BuiltinSniffer())
    assert file.extensions == (".tar", ".gz")
    assert file.extension == ".gz"
    assert InspectedFile(Upload.from_bytes(b"x", ".bashrc"), BuiltinSniffer()).extensions == ()


def test_non_seekable_streams_are_spooled() -> None:
    class Pipe:
        def __init__(self, data: bytes) -> None:
            self.data = data

        def seekable(self) -> bool:
            return False

        def read(self, n: int = -1) -> bytes:
            out, self.data = self.data, b""
            return out

    pipe = cast("IO[bytes]", Pipe(corpus.png()))
    file = InspectedFile(Upload(pipe, "a.png"), BuiltinSniffer())
    assert file.size == len(corpus.png())
    assert file.detected_type is not None
    file.close()
    assert file.stream.closed


def test_chained_sniffer_falls_back() -> None:
    class Nothing:
        def sniff(self, file: InspectedFile) -> None:
            return None

    class AlwaysPdf:
        def sniff(self, file: InspectedFile) -> FileType | None:
            return get_type("application/pdf")

    chain = ChainedSniffer((Nothing(), AlwaysPdf()))
    file = InspectedFile(Upload.from_bytes(b"???", "a.pdf"), chain)
    assert file.detected_type is not None
    assert file.detected_type.mime == "application/pdf"


def test_magic_sniffer_maps_libmagic_output(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    fake = types.ModuleType("magic")
    setattr(fake, "from_buffer", lambda data, mime: "image/x-ms-bmp")  # noqa: B010
    monkeypatch.setitem(sys.modules, "magic", fake)
    file = InspectedFile(Upload.from_bytes(b"whatever", "a.bmp"), MagicSniffer())
    assert file.detected_type is not None
    assert file.detected_type.mime == "image/bmp"  # alias resolved to canonical type


def test_registry_lookups_and_registration() -> None:
    assert get_type("IMAGE/JPG; charset=binary") == get_type("image/jpeg")
    assert {t.mime for t in types_for_extension(".JPG")} == {"image/jpeg"}
    with pytest.raises(ValueError, match="Unknown file type"):
        resolve_mime("image/definitely-not-real")
    custom = FileType("application/x-test-format", (".tst",), "Test format")
    register_type(custom)
    register_type(custom)  # idempotent
    assert get_type("application/x-test-format") is custom
    with pytest.raises(ValueError, match="different FileType"):
        register_type(FileType("application/x-test-format", (".other",), "Other"))
    with pytest.raises(ValueError, match="lowercase"):
        FileType("Image/PNG", (".png",), "bad")
    with pytest.raises(ValueError, match="Extensions"):
        FileType("image/x-bad", ("png",), "bad")


def test_helpers() -> None:
    assert format_size(999) == "999 bytes"
    assert format_size(2_500_000) == "2.5 MB"
    assert format_size(10**13) == "1e+04 GB"
    assert is_binary(b"\x00abc")
    assert not is_binary(b"plain\ttext\r\n")
