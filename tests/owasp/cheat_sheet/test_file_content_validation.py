"""OWASP File Upload Cheat Sheet - File Content Validation."""

from __future__ import annotations

import hashlib
import io
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from PIL import Image, PngImagePlugin

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import InspectedFile, Policy, Upload, Violation, presets, validate
from uploadshield.checks import Check, ClamAV, ImageIntegrity, OfficeMacros
from uploadshield.presets import BUILTIN_POLICIES
from uploadshield.sanitizers import ReencodeImage

owasp = pytest.mark.owasp
TRAILER = b"\x00TRAILING-PAYLOAD-" * 8


def sanitize(data: bytes, name: str, policy: Policy = presets.SANITIZED_IMAGES) -> bytes:
    result = validate(Upload.from_bytes(data, name), policy)
    assert result.ok, result.violations
    assert result.sanitized is not None
    assert result.sanitized.data is not None
    return result.sanitized.data


def png_with_text(**chunks: str) -> bytes:
    info = PngImagePlugin.PngInfo()
    for key, value in chunks.items():
        info.add_text(key, value)
    buf = io.BytesIO()
    Image.new("RGB", (20, 10), (1, 2, 3)).save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Images: rewrite, strip metadata, restricted decoder with limits
# --------------------------------------------------------------------------- #


@owasp("content.image-rewrite")
@pytest.mark.parametrize(
    ("fmt", "ext"), [("JPEG", "jpg"), ("PNG", "png"), ("GIF", "gif"), ("WEBP", "webp")]
)
def test_images_are_decoded_and_re_encoded(fmt: str, ext: str) -> None:
    original = corpus.image(fmt, size=(32, 24)) + TRAILER
    data = sanitize(original, f"a.{ext}")
    assert data != original
    assert b"TRAILING-PAYLOAD" not in data  # nothing after the image data survives
    with Image.open(io.BytesIO(data)) as image:
        assert (image.format, image.size) == (fmt, (32, 24))


@owasp("content.image-rewrite", "content.image-metadata")
def test_every_framework_delivers_the_rewritten_image(app: App) -> None:
    original = png_with_text(Comment="tracking-id-4711", Author="Jane Doe")
    (delivered,) = app.post("/avatar", file("me.png", original)).files
    expected = sanitize(original, "me.png")
    assert delivered["sha256"] == hashlib.sha256(expected).hexdigest()
    assert b"tracking-id-4711" not in expected
    assert b"Jane Doe" not in expected


@owasp("content.image-metadata")
def test_exif_gps_and_comments_are_stripped_and_orientation_applied() -> None:
    original = corpus.jpeg_with_metadata()  # camera make, GPS, "rotate 90", a comment
    data = sanitize(original, "me.jpg")
    with Image.open(io.BytesIO(data)) as image:
        assert len(image.getexif()) == 0
        assert "comment" not in image.info
        assert image.size == (20, 40)  # rotated into place before the EXIF was dropped
    for secret in (b"EvilCam", b"secret comment"):
        assert secret not in data


@owasp("content.image-metadata")
def test_gif_comments_and_png_text_chunks_are_stripped() -> None:
    assert b"tracking-id-123" not in sanitize(corpus.animated_gif(), "a.gif")
    assert b"tEXt" not in sanitize(png_with_text(Comment="x"), "a.png")


@owasp("content.image-metadata")
def test_colour_profiles_are_kept_unless_asked_not_to() -> None:
    from PIL import ImageCms

    profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    buf = io.BytesIO()
    Image.new("RGB", (8, 8)).save(buf, "JPEG", icc_profile=profile)
    kept = sanitize(buf.getvalue(), "a.jpg")
    no_icc = presets.IMAGES.replace(sanitizers=(ReencodeImage(keep_icc_profile=False),))
    dropped = sanitize(buf.getvalue(), "a.jpg", no_icc)
    assert Image.open(io.BytesIO(kept)).info.get("icc_profile") == profile
    assert "icc_profile" not in Image.open(io.BytesIO(dropped)).info


@pytest.fixture
def pillow_calls(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    calls: list[Any] = []
    real = Image.open

    def spy(fp: Any, mode: str = "r", formats: Any = None) -> Any:
        calls.append(tuple(formats) if formats else None)
        return real(fp, formats=formats)

    monkeypatch.setattr(Image, "open", spy)
    return calls


@owasp("content.image-library", "threat.parser-exploit")
def test_pillow_only_decodes_the_sniffed_format(pillow_calls: list[Any]) -> None:
    assert codes(corpus.png(), "a.png", presets.IMAGES) == ()
    assert pillow_calls
    assert set(pillow_calls) == {("PNG",)}  # never "whatever Pillow can open"


@owasp("content.image-library", "threat.parser-exploit")
@pytest.mark.parametrize(
    ("data", "name"),
    [(corpus.EPS, "a.png"), (corpus.IMAGETRAGICK_MVG, "a.jpg"), (corpus.svg(), "a.png")],
    ids=["eps", "imagetragick-mvg", "svg"],
)
def test_formats_outside_the_allow_list_never_reach_a_decoder(
    pillow_calls: list[Any], data: bytes, name: str
) -> None:
    assert codes(data, name, presets.IMAGES)[0] in ("type_not_allowed", "extension_mismatch")
    assert pillow_calls == []


@owasp("content.image-library")
@pytest.mark.parametrize(
    ("data", "code"),
    [
        (corpus.png_huge_dimensions(), "image_too_large"),  # decompression bomb
        (corpus.gif_with_frames(1001), "image_too_large"),  # frame bomb
        (corpus.png()[:-20], "image_corrupt"),
    ],
    ids=["pixels", "frames", "truncated"],
)
def test_resource_limits_and_complete_decoding(data: bytes, code: str) -> None:
    assert codes(data, "a.gif" if data[:3] == b"GIF" else "a.png", presets.IMAGES) == (code,)


@owasp("content.image-library")
def test_limits_are_configurable() -> None:
    tight = presets.IMAGES.replace(content_checks=(ImageIntegrity(max_pixels=100, max_frames=2),))
    assert codes(corpus.png(), "a.png", tight) == ("image_too_large",)  # 16 x 12 pixels
    assert codes(corpus.gif_with_frames(3), "a.gif", tight) == ("image_too_large",)


# --------------------------------------------------------------------------- #
# Microsoft (and ODF) documents
# --------------------------------------------------------------------------- #

OFFICE_ATTACKS = {
    "vba-in-docx": (
        corpus.ooxml("docx", extra={"word/vbaProject.bin": b"x"}),
        "a.docx",
        "office_macros",
    ),
    "activex": (
        corpus.ooxml("docx", extra={"word/activeX/activeX1.xml": b"<ax/>"}),
        "a.docx",
        "office_macros",
    ),
    "odf-basic": (
        corpus.odt(extra={"Basic/Standard/Module1.xml": b"<x/>"}),
        "a.odt",
        "office_macros",
    ),
    "dde": (corpus.docx_with_dde(), "a.docx", "office_macros"),
    "remote-template": (corpus.docx_with_remote_template(), "a.docx", "office_external_reference"),
    "xxe-document": (corpus.docx_with_dtd(), "a.docx", "xml_dtd"),
    "xxe-content-types": (corpus.docx_with_dtd(part="[Content_Types].xml"), "a.docx", "xml_dtd"),
    "xxe-relationships": (
        corpus.docx_with_dtd(part="word/_rels/document.xml.rels"),
        "a.docx",
        "xml_dtd",
    ),
    "xxe-odt": (corpus.odt_with_dtd(), "a.odt", "xml_dtd"),
    "macro-enabled-type": (corpus.ooxml("docm"), "a.docx", "type_not_allowed"),
}


@owasp("content.office")
@pytest.mark.parametrize(
    ("data", "name", "code"), OFFICE_ATTACKS.values(), ids=list(OFFICE_ATTACKS)
)
def test_hostile_office_documents_are_refused(data: bytes, name: str, code: str) -> None:
    assert codes(data, name, presets.DOCUMENTS) == (code,)


@owasp("content.office")
@pytest.mark.parametrize(
    "attack", ["vba-in-docx", "dde", "remote-template", "xxe-document", "xxe-odt"]
)
def test_hostile_office_documents_are_refused_in_every_framework(app: App, attack: str) -> None:
    data, name, code = OFFICE_ATTACKS[attack]
    assert app.post("/documents", file(name, data)).codes == [code]


@owasp("content.office")
def test_legacy_ole_documents_with_macros() -> None:
    ole = Policy(allowed_types={"application/x-ole-storage"})
    assert codes(corpus.ole(), "a.doc", ole) == ()
    assert codes(corpus.ole(macros=True), "a.doc", ole) == ("office_macros",)


@owasp("content.office")
@pytest.mark.parametrize(
    ("data", "name"),
    [
        (corpus.ooxml("docx"), "a.docx"),
        (corpus.ooxml("xlsx"), "a.xlsx"),
        (corpus.ooxml("pptx"), "a.pptx"),
        (corpus.odt(), "a.odt"),
        (corpus.docx_with_external_hyperlink(), "links.docx"),  # hyperlinks are not templates
    ],
)
def test_ordinary_office_documents_pass(data: bytes, name: str) -> None:
    assert codes(data, name, presets.DOCUMENTS) == ()


@owasp("content.office")
def test_remote_references_can_be_allowed_explicitly() -> None:
    lenient = presets.DOCUMENTS.replace(
        content_checks=(OfficeMacros(block_external_references=False),)
    )
    assert codes(corpus.docx_with_remote_template(), "a.docx", lenient) == ()


# --------------------------------------------------------------------------- #
# ZIP files
# --------------------------------------------------------------------------- #


@owasp("content.zip")
@pytest.mark.parametrize("policy", list(BUILTIN_POLICIES.values()), ids=list(BUILTIN_POLICIES))
def test_no_preset_accepts_archives(policy: Policy) -> None:
    for mime in (
        "application/zip",
        "application/java-archive",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-rar-compressed",
    ):
        assert not policy.allows_mime(mime), (policy.name, mime)


@owasp("content.zip")
@pytest.mark.parametrize("path", ["/legacy", "/documents", "/avatar"])
def test_archives_are_refused_by_every_endpoint(app: App, path: str) -> None:
    archive = corpus.build_zip({"readme.txt": b"hello"})
    assert app.post(path, file("files.zip", archive)).codes == ["type_not_allowed"]


@owasp("content.zip")
def test_policies_that_accept_archives_still_inspect_them() -> None:
    zips = Policy(allowed_types={"application/zip"})
    assert codes(corpus.build_zip({"a.txt": b"a"}), "a.zip", zips) == ()
    assert codes(corpus.zip_bomb_ratio(), "a.zip", zips) == ("archive_bomb",)


# --------------------------------------------------------------------------- #
# Malware scanning
# --------------------------------------------------------------------------- #


@owasp("content.malware-scan")
def test_clamav_refuses_malware_and_fails_closed(clamd: str) -> None:
    policy = presets.DOCUMENTS.extend(checks=[ClamAV(address=clamd)])
    assert codes(b"just some text", "a.txt", policy) == ()
    assert codes(corpus.EICAR, "a.txt", policy) == ("malware_detected",)
    unreachable = presets.DOCUMENTS.extend(
        checks=[ClamAV(address="tcp://127.0.0.1:9", timeout=0.5)]
    )
    assert codes(b"just some text", "a.txt", unreachable) == ("scanner_unavailable",)


@owasp("content.malware-scan")
def test_yara_signatures() -> None:
    pytest.importorskip("yara")
    from uploadshield.checks import YaraRules

    rule = 'rule Dropper { strings: $a = "DownloadFile" condition: $a }'
    policy = presets.DOCUMENTS.extend(checks=[YaraRules(source=rule)])
    assert codes(b"$c.DownloadFile('http://x')", "a.txt", policy) == ("signature_match",)


@dataclass(frozen=True)
class KnownBadHashes(Check):
    """How a hash look-up service (e.g. VirusTotal) plugs in: a custom check."""

    name = "known_bad"
    hashes: frozenset[str] = frozenset()

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        if file.sha256 in self.hashes:
            yield self.violation("malware_detected", "The file is known to be malicious.")


@owasp("content.malware-scan")
def test_hash_look_ups_fit_a_custom_check() -> None:
    bad = hashlib.sha256(b"known bad\n").hexdigest()
    policy = presets.DOCUMENTS.extend(checks=[KnownBadHashes(hashes=frozenset({bad}))])
    assert codes(b"known bad\n", "a.txt", policy) == ("malware_detected",)
    assert codes(b"harmless\n", "a.txt", policy) == ()


# --------------------------------------------------------------------------- #
# Content Disarm & Reconstruct
# --------------------------------------------------------------------------- #


@owasp("content.cdr")
def test_images_are_reconstructed_but_documents_are_refused_not_disarmed() -> None:
    # Covered: images are rebuilt from their pixels.
    original = corpus.image("JPEG", comment=b"hidden")
    assert sanitize(original, "a.jpg") != original
    # Not covered: active PDF and Office content is refused; nothing is disarmed.
    pdf = validate(Upload.from_bytes(corpus.pdf_with_javascript(), "a.pdf"), presets.DOCUMENTS)
    docx = validate(Upload.from_bytes(corpus.docx_with_dde(), "a.docx"), presets.DOCUMENTS)
    assert (pdf.codes, pdf.sanitized) == (("pdf_active_content",), None)
    assert (docx.codes, docx.sanitized) == (("office_macros",), None)
