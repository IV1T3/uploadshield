"""PdfActiveContent: scripts, actions and payloads in PDF documents."""

from __future__ import annotations

import base64
import zlib

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, Upload, presets, validate
from uploadshield.checks import (
    PdfActiveContent,
)
from uploadshield.checks.pdf import pdf_names


def test_pdf_active_content() -> None:
    assert codes(corpus.pdf(), "a.pdf") == ()
    assert codes(corpus.pdf_latex_style(), "a.pdf") == ()
    assert codes(corpus.pdf_with_javascript(), "a.pdf") == ("pdf_active_content",)
    assert codes(corpus.pdf_with_obfuscated_javascript(), "a.pdf") == ("pdf_active_content",)
    assert codes(corpus.pdf_with_javascript_in_object_stream(), "a.pdf") == ("pdf_active_content",)
    assert codes(corpus.pdf_encrypted(), "a.pdf") == ("pdf_active_content",)


def test_pdf_check_options() -> None:
    def policy(check: PdfActiveContent) -> Policy:
        return presets.PDF.replace(content_checks=(check,))

    no_streams = policy(PdfActiveContent(inspect_streams=False))
    assert codes(corpus.pdf_with_javascript_in_object_stream(), "a.pdf", no_streams) == ()
    assert (
        codes(corpus.pdf_encrypted(), "a.pdf", policy(PdfActiveContent(allow_encrypted=True))) == ()
    )
    tiny_buffer = policy(PdfActiveContent(max_bytes=10))
    assert codes(corpus.pdf(), "a.pdf", tiny_buffer) == ("check_failed",)


def test_pdf_name_decoding() -> None:
    assert {"JavaScript", "JS", "Type"} <= pdf_names(b"/J#61vaScript /JS /Type")
    assert "JavaScriptX" in pdf_names(b"/JavaScriptX")
    assert "JavaScript" not in pdf_names(b"/JavaScriptX")


# --------------------------------------------------------------------------- #
# Object streams: decoded completely, whatever their encoding, or refused
# --------------------------------------------------------------------------- #

JS_OBJECT = b"4 0 << /S /JavaScript /JS (app.alert(1)) >>"


def object_stream(encoded: bytes, dictionary: bytes = b"/Type /ObjStm /N 1 /First 4") -> bytes:
    return (
        b"5 0 obj << "
        + dictionary
        + b" /Length "
        + str(len(encoded)).encode()
        + b" >>\nstream\n"
        + encoded
        + b"\nendstream\nendobj"
    )


def deflate(data: bytes, wbits: int = 15) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, wbits)
    return compressor.compress(data) + compressor.flush()


def pdf_check(**options: object) -> Policy:
    return presets.PDF.replace(content_checks=(PdfActiveContent(**options),))


@pytest.mark.owasp("ufu.detector.decompression")
def test_object_streams_behind_large_streams_are_still_decoded() -> None:
    # Other streams (page content, images) are not inflated, so they cannot use up the
    # budget before the object stream that holds the script.
    padding = deflate(b"\x00" * (4 * 1024 * 1024))
    content = b"6 0 obj << /Filter /FlateDecode /Length %d >>\nstream\n" % len(padding)
    document = corpus.pdf(
        content + padding + b"\nendstream\nendobj",
        object_stream(deflate(JS_OBJECT), b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode"),
    )
    assert codes(document, "a.pdf", pdf_check(max_inflated_bytes=1024 * 1024)) == (
        "pdf_active_content",
    )


@pytest.mark.owasp("ufu.detector.decompression")
@pytest.mark.parametrize(
    ("encoded", "filters"),
    [
        (deflate(JS_OBJECT, wbits=9), b"/FlateDecode"),  # a 512-byte window
        (deflate(JS_OBJECT, wbits=-15), b"/FlateDecode"),  # raw deflate, no zlib header
        (deflate(JS_OBJECT, wbits=31), b"/Fl"),  # gzip framing, abbreviated name
        (deflate(JS_OBJECT).hex().encode() + b">", b"[/ASCIIHexDecode /FlateDecode]"),
        (base64.a85encode(deflate(JS_OBJECT)) + b"~>", b"[/A85 /Fl]"),
        (JS_OBJECT, b"[]"),  # no filter at all
    ],
)
def test_object_streams_are_decoded_in_any_encoding(encoded: bytes, filters: bytes) -> None:
    dictionary = b"/Type /ObjStm /N 1 /First 4 /Filter " + filters
    assert codes(corpus.pdf(object_stream(encoded, dictionary)), "a.pdf") == ("pdf_active_content",)


@pytest.mark.parametrize(
    "dictionary",
    [
        b"/N 1 /First 4 /Filter /FlateDecode",  # readers do not insist on /Type
        b"/Type /Obj#53tm /N 1 /First 4 /Filter /Fl#61teDecode",  # escaped names
    ],
)
def test_object_streams_are_recognised_by_their_keys(dictionary: bytes) -> None:
    assert codes(corpus.pdf(object_stream(deflate(JS_OBJECT), dictionary)), "a.pdf") == (
        "pdf_active_content",
    )


@pytest.mark.parametrize(
    ("encoded", "dictionary"),
    [
        (b"\x80\x0b\x60", b"/Type /ObjStm /N 1 /First 4 /Filter /LZWDecode"),
        (b"xx", b"/Type /ObjStm /N 1 /First 4 /Filter /JBIG2Decode"),
        (
            deflate(JS_OBJECT),
            b"/Type /ObjStm /N 1 /First 4 /Filter /Fl /DecodeParms << /Predictor 12 /Columns 4 >>",
        ),
        (b"not deflate data", b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode"),
    ],
)
def test_object_streams_that_cannot_be_decoded_are_refused(
    encoded: bytes, dictionary: bytes
) -> None:
    document = corpus.pdf(object_stream(encoded, dictionary))
    result = validate(Upload.from_bytes(document, "a.pdf"), presets.PDF)
    assert result.codes == ("pdf_active_content",)
    assert result.violations[0].details["reason"]


def test_object_streams_beyond_the_budget_are_refused() -> None:
    large = object_stream(
        deflate(JS_OBJECT + b" " * 5000), b"/Type /ObjStm /N 1 /First 4 /Filter /Fl"
    )
    assert codes(corpus.pdf(large), "a.pdf", pdf_check(max_inflated_bytes=1000)) == (
        "check_failed",
    )


def test_ordinary_streams_in_other_encodings_pass() -> None:
    # Page content and images may use any filter: only object streams hold objects.
    lzw = b"6 0 obj << /Filter /LZWDecode /Length 3 >>\nstream\n\x80\x0b\x60\nendstream\nendobj"
    image = b"7 0 obj << /Subtype /Image /Filter /DCTDecode /Length 4 >>\nstream\n\xff\xd8\xff\xd9"
    assert codes(corpus.pdf(lzw, image + b"\nendstream\nendobj"), "a.pdf") == ()


# --------------------------------------------------------------------------- #
# Stream dictionaries are read structurally, whatever they contain
# --------------------------------------------------------------------------- #

JS_STREAM = deflate(JS_OBJECT)


def objstm(dictionary: bytes, encoded: bytes = JS_STREAM, number: bytes = b"5") -> bytes:
    length = b" /Length " + str(len(encoded)).encode()
    return (
        number
        + b" 0 obj << "
        + dictionary
        + length
        + b" >>\nstream\n"
        + encoded
        + b"\nendstream\nendobj"
    )


KEYS = b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode"


@pytest.mark.owasp("ufu.detector.decompression")
@pytest.mark.parametrize(
    "dictionary",
    [
        KEYS + b" /Note (obj)",  # text that once cut the dictionary short
        KEYS + b" /Note (a \\) obj << (nested) >>)",
        b"/DecodeParms << /Columns 1 >> " + KEYS,  # a nested dictionary before the keys
        KEYS + b" /Pad [" + b" 0" * 6000 + b"]",  # 12 KB: beyond any fixed window
        b"/Pad <" + b"00" * 6000 + b"> " + KEYS,
        KEYS + b" % << a comment with brackets >>\n",
    ],
)
def test_object_stream_keys_cannot_be_hidden_in_their_dictionary(dictionary: bytes) -> None:
    assert codes(corpus.pdf(objstm(dictionary)), "a.pdf") == ("pdf_active_content",)


def test_stream_data_is_skipped_by_its_length() -> None:
    # Raw data that mentions "endstream" (and opens a string) is still skipped whole.
    data = b"BT (endstream (not a string start) Tj ET"
    content = b"6 0 obj << /Length %d >>\nstream\n" % len(data) + data + b"\nendstream\nendobj"
    benign_objstm = objstm(KEYS, deflate(b"4 0 << /Type /Font >>"))
    assert codes(corpus.pdf(content, benign_objstm), "a.pdf") == ()


@pytest.mark.owasp("ufu.detector.decompression")
@pytest.mark.parametrize(
    "hiding",
    [
        # An object stream inside the data of another stream, reachable by offset.
        lambda inner: (
            b"6 0 obj << /Length %d >>\nstream\n" % len(inner) + inner + b"\nendstream\nendobj"
        ),
        # Swallowed by an unterminated string, so a linear reading never reaches it.
        lambda inner: b"6 0 obj << /Title (unbalanced >> endobj\n" + inner,
        # Swallowed by a comment line.
        lambda inner: b"% " + inner.replace(b"\n", b" ").replace(b"stream ", b"stream\n", 1),
    ],
)
def test_object_streams_outside_the_object_structure_are_refused(hiding: object) -> None:
    document = corpus.pdf(hiding(objstm(KEYS, number=b"9")))  # type: ignore[operator]
    result = validate(Upload.from_bytes(document, "a.pdf"), presets.PDF)
    assert result.codes == ("pdf_active_content",)


@pytest.mark.parametrize(
    "broken",
    [
        b"7 0 obj << /N 1 /First 4 /Length 3 \nendobj",  # never closed
        b"7 0 obj << /N 1 /First 4 >> % comment\nstream\nabc\nendstream endobj",
        b"7 0 obj << /N 1 /First 4 /K <0a0b >> endobj",  # unterminated hex string
    ],
)
def test_malformed_structure_around_object_streams_is_refused(broken: bytes) -> None:
    result = validate(Upload.from_bytes(corpus.pdf(broken), "a.pdf"), presets.PDF)
    assert result.codes == ("pdf_active_content",)
    assert result.violations[0].details["reason"] == "uncheckable"


def test_pdfs_without_object_streams_are_not_lexed() -> None:
    # Unbalanced text cannot hide anything when there is no object stream to find.
    assert codes(corpus.pdf(b"6 0 obj << /Title (unbalanced >> endobj"), "a.pdf") == ()


@pytest.mark.parametrize(
    "unit", [b"<<>>", b"(())", b"()", b"<>", b"%\n", b"(", b"<<", b"s", b"\\("]
)
def test_the_structure_is_read_in_linear_time(unit: bytes) -> None:
    import time

    flood = corpus.pdf(objstm(KEYS + b" /X [" + unit * (2_000_000 // len(unit)) + b"]"))
    started = time.perf_counter()
    validate(Upload.from_bytes(flood, "a.pdf"), presets.PDF)
    assert time.perf_counter() - started < 3
