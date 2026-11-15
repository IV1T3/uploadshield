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


# --------------------------------------------------------------------------- #
# Security review, 2026-11-14: what the scanner reads must be what a reader reads
# --------------------------------------------------------------------------- #


def refusal(document: bytes, policy: Policy = presets.PDF) -> tuple[str, object] | None:
    """``(reason, keywords or detail)`` of the refusal; ``None`` for an accepted file.

    "uncheckable" and "active_content" share one code, so tests that only compare codes
    cannot tell a found script from a file that merely could not be read.
    """
    result = validate(Upload.from_bytes(document, "a.pdf"), policy)
    if result.ok:
        return None
    assert result.codes == ("pdf_active_content",)
    details = result.violations[0].details
    return details["reason"], details.get("keywords") or details.get("detail")


SCRIPT = ("active_content", ["JS", "JavaScript"])


def test_names_end_at_pdf_white_space_which_includes_nul() -> None:
    # NUL is white-space in PDF (ISO 32000-1, table 1) but not for Python's "\\s".
    assert {"S", "JavaScript", "JS"} <= pdf_names(b"<< /S/JavaScript\x00/JS\x00(app.alert(1)) >>")
    action = b"4 0 obj << /S /JavaScript\x00/JS\x00(app.alert(1)) >> endobj"
    assert refusal(corpus.pdf(action)) == SCRIPT
    stream = objstm(b"/Type\x00/ObjStm\x00/N\x001/First\x004/Filter\x00/FlateDecode")
    assert refusal(corpus.pdf(stream)) == SCRIPT


@pytest.mark.parametrize(
    "dictionary",
    [
        # A string or a comment that mentions /Filter is not the stream's filter.
        b"/Type /ObjStm /N 1 /First 4 /Note (/Filter []) /Filter /FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 /Note (/Filter /ASCIIHexDecode) /Filter /FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 % /Filter []\n/Filter /FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 /Note << /Filter [] >> /Filter /FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 /Note [/Filter []] /Filter /FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 /Note <2f46696c746572205b5d> /Filter /FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 /Filter%c\n/FlateDecode",
        b"/Type /ObjStm /N 1 /First 4 /Filter\x00[\x00/FlateDecode\x00]",
    ],
)
def test_the_filter_is_read_from_the_dictionary_itself(dictionary: bytes) -> None:
    assert refusal(corpus.pdf(objstm(dictionary))) == SCRIPT


@pytest.mark.parametrize(
    ("dictionary", "detail"),
    [
        (b"/Filter 7 0 R", "filter that is not given by name"),
        (b"/Filter [7 0 R]", "filter that is not given by name"),
        (b"/Filter [/FlateDecode 7 0 R]", "filter that is not given by name"),
        (b"/Filter (FlateDecode)", "filter that is not given by name"),
        (b"/Filter /FlateDecode /Filter []", "/Filter given twice"),
        (b"/Filter [] /Filter /FlateDecode", "/Filter given twice"),
        (
            b"/Filter /FlateDecode /DecodeParms 7 0 R",
            "decode parameters that are not given directly",
        ),
        (b"/Filter /FlateDecode /DP << /Predictor 12 >>", "predictor"),
        (b"/Filter /FlateDecode /DecodeParms [<< /Predictor 7 0 R >>]", "predictor"),
        (b"/Filter /FlateDecode /F (other.pdf)", "stream data in another file"),
    ],
)
def test_object_streams_decoded_by_what_is_not_in_their_dictionary_are_refused(
    dictionary: bytes, detail: str
) -> None:
    # A reader resolves the reference; nothing here does, so what the stream holds is
    # not known - and "unknown" must not be read as "no filter".
    document = corpus.pdf(objstm(b"/Type /ObjStm /N 1 /First 4 " + dictionary))
    assert refusal(document) == ("uncheckable", detail)


def test_references_that_do_not_decide_the_decoding_are_fine() -> None:
    benign = deflate(b"4 0 << /Type /Font >>")
    for extra in (
        b" /Extends 9 0 R",
        b" /DecodeParms null",
        b" /DecodeParms << /Columns 1 >>",
        b" /DecodeParms << /Predictor 1 /Columns 1 >>",
        b" /DecodeParms [ null << /Predictor 1 >> ]",
        # Decode parameters are read like the dictionary itself: a comment or a string
        # that mentions a predictor is not one.
        b" /DecodeParms << % /Predictor 12\n /Columns 1 >>",
        b" /DecodeParms << /Note (/Predictor 12) >>",
        b" /Note (/DecodeParms 7 0 R /Predictor 12)",
    ):
        assert refusal(corpus.pdf(objstm(KEYS + extra, benign))) is None, extra
    for extra in (
        b" /DecodeParms [ null << /Predictor 12 >> ]",
        b" /DecodeParms [ 7 0 R ]",
        b" /DecodeParms << /Predictor 1 /Predictor 12 >>",
        b" /DecodeParms << /Pre#64ictor 12 >>",
        b" /DecodeParms << /Predictor 1.5 >>",
        b" /DecodeParms (x)",
    ):
        found = refusal(corpus.pdf(objstm(KEYS + extra, benign)))
        assert found is not None, extra
        assert found[0] == "uncheckable", extra
    assert refusal(corpus.pdf(objstm(KEYS + b" /Extends 9 0 R"))) == SCRIPT


@pytest.mark.parametrize(
    ("encoded", "filters"),
    [
        (JS_STREAM[:-9], b"/FlateDecode"),  # cut inside the deflate data
        (JS_STREAM[:-4], b"/FlateDecode"),  # the checksum is missing
        (deflate(JS_OBJECT, wbits=-15)[:-3], b"/FlateDecode"),
        (base64.a85encode(JS_OBJECT), b"/ASCII85Decode"),  # no "~>"
        (JS_OBJECT.hex().encode(), b"/ASCIIHexDecode"),  # no ">"
        (base64.a85encode(JS_STREAM), b"[/A85 /Fl]"),
    ],
)
def test_object_streams_that_stop_before_their_end_marker_are_refused(
    encoded: bytes, filters: bytes
) -> None:
    # Where a stream ends in the file is not always certain; data that may have been cut
    # short is never read in part.
    document = corpus.pdf(objstm(b"/Type /ObjStm /N 1 /First 4 /Filter " + filters, encoded))
    found = refusal(document)
    assert found is not None
    assert found[0] == "uncheckable"


def test_a_stream_cut_at_a_false_endstream_is_not_read_in_part() -> None:
    # /Length is a reference here, so the data is taken up to the first "endstream" -
    # which the encoded data itself spells.  A reader, following the reference, reads on.
    hidden = base64.a85encode(b"4 0 << /Type /Font >>" + b" " * 40) + b" endstream "
    hidden += base64.a85encode(JS_OBJECT) + b"~>"
    stream = (
        b"5 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /A85 /Length 8 0 R >>\nstream\n"
        + hidden
        + b"\nendstream\nendobj"
    )
    found = refusal(corpus.pdf(stream, b"8 0 obj %d endobj" % len(hidden)))
    assert found is not None
    assert found[0] == "uncheckable"


ATTACHMENT = (
    b"4 0 obj << /Type /Annot /Subtype /FileAttachment /Rect [0 0 9 9] /FS 5 0 R >> endobj",
    b"5 0 obj << /Type /Filespec /F (a.bin) /EF << /F 6 0 R >> >> endobj",
    b"6 0 obj << /Length 4 >>\nstream\nabcd\nendstream\nendobj",
)


def test_embedded_files_are_found_without_their_optional_names() -> None:
    # Neither /Type /EmbeddedFile nor the /EmbeddedFiles name tree is needed to attach
    # a file: an annotation and a file specification with an /EF entry are enough.
    assert refusal(corpus.pdf(*ATTACHMENT)) == ("active_content", ["EF", "FileAttachment"])
    specification_only = corpus.pdf(b"5 0 obj << /F (a.bin) /E#46 7 0 R >> endobj")
    assert refusal(specification_only) == ("active_content", ["EF"])
    in_object_stream = objstm(KEYS, deflate(b"4 0 << /F (a.bin) /EF\x00<< /F 6 0 R >> >>"))
    assert refusal(corpus.pdf(in_object_stream)) == ("active_content", ["EF"])


def test_embedded_file_detection_follows_the_forbidden_names() -> None:
    allowed = PdfActiveContent(
        forbidden=PdfActiveContent().forbidden - {"EmbeddedFile", "EmbeddedFiles", "FileAttachment"}
    )
    assert refusal(corpus.pdf(*ATTACHMENT), presets.PDF.replace(content_checks=(allowed,))) is None


def test_the_letters_ef_in_stream_data_are_not_an_embedded_file() -> None:
    data = b"q /EF gs /EF\x00 Do (/EF <) Tj Q"
    content = b"6 0 obj << /Length %d >>\nstream\n" % len(data) + data + b"\nendstream\nendobj"
    assert refusal(corpus.pdf(content)) is None


def test_dictionaries_with_deep_or_broken_nesting_do_not_crash() -> None:
    deep = b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /X " + b"[" * 5_000 + b"]" * 5_000
    assert refusal(corpus.pdf(objstm(deep))) == SCRIPT
    for parameters in (b"[" * 5_000 + b"]" * 5_000, b"<<" * 5_000 + b">>" * 5_000):
        nested = b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /DecodeParms " + parameters
        found = refusal(corpus.pdf(objstm(nested)))
        assert found is not None  # refused or found, never a crash
        assert found[0] == "uncheckable"
    for broken in (b"/X [ << ] >>", b"/X [ ) ]", b"/X ]", b"(key) /Value", b"/X { /Filter [] }"):
        found = refusal(corpus.pdf(objstm(KEYS + b" " + broken)))
        assert found is not None  # a script that is found, or a file that is refused


def test_an_object_stream_dictionary_too_large_to_be_one_is_refused() -> None:
    # The dictionary of a real object stream takes about a hundred bytes; reading one
    # of megabytes token by token would cost seconds.
    import time

    for padding in (b"/Pad [" + b" 0" * 40_000 + b"]", b"/Pad (" + b"x" * 70_000 + b")"):
        assert refusal(corpus.pdf(objstm(KEYS + b" " + padding))) == (
            "uncheckable",
            "stream dictionary too large",
        )
    small = b"/Pad [" + b" 0" * 20_000 + b"]"  # 40 KB: read, and the script is found
    assert refusal(corpus.pdf(objstm(KEYS + b" " + small))) == SCRIPT
    # A large dictionary of any other stream is nobody's business.
    image = b"7 0 obj << /Subtype /Image /Lookup <" + b"00" * 100_000 + b"> /Length 2 >>"
    plain = corpus.pdf(
        image + b"\nstream\nab\nendstream\nendobj", objstm(KEYS, deflate(b"4 0 << >>"))
    )
    assert refusal(plain) is None
    flood = corpus.pdf(objstm(KEYS + b" " + b" ".join(b"/K%d %d" % (i, i) for i in range(300_000))))
    started = time.perf_counter()
    assert refusal(flood) == ("uncheckable", "stream dictionary too large")
    assert time.perf_counter() - started < 3


MEMORY_PROBE = """
import resource, sys, zlib
from uploadshield import Upload, presets, validate

run = b" ".join(b"/K%d %d" % (i, i) for i in range(250_000))  # about 4 MB of ordinary tokens
script = zlib.compress(b"4 0 << /S /JavaScript /JS (app.alert(1)) >>")
stream = (
    b"5 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length %d >>" % len(script)
    + b"\\nstream\\n" + script + b"\\nendstream\\nendobj"
)
document = (
    b"%PDF-1.7\\n1 0 obj << /Type /Catalog >> endobj\\n6 0 obj << " + run + b" >> endobj\\n"
    + stream + b"\\ntrailer << /Root 1 0 R >>\\n%%EOF\\n"
)
assert validate(Upload.from_bytes(document, "a.pdf"), presets.PDF).codes == ("pdf_active_content",)
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # bytes on macOS, KiB elsewhere
print(peak if sys.platform == "darwin" else peak * 1024)
"""


def test_long_runs_are_read_without_keeping_a_record_of_every_step() -> None:
    # The lexer steps over runs of ordinary tokens with one pattern.  Unless that
    # pattern is possessive, the regex engine keeps a record of every step in case it
    # has to go back: 600 MB for this 4 MB file, 3 GB for 25 MB (found on 2026-11-14).
    # That memory is the engine's own, so it shows in the size of a process only.
    import subprocess
    import sys

    pytest.importorskip("resource")
    probe = subprocess.run(
        [sys.executable, "-c", MEMORY_PROBE], capture_output=True, text=True, check=True
    )
    peak = int(probe.stdout.strip())
    assert peak < 300_000_000, f"{peak // 1_000_000} MB"


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
