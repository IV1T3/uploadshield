"""Sanitizers: re-encoding, filename rewriting, and failing closed."""

from __future__ import annotations

import io
from dataclasses import dataclass

import pytest
from PIL import Image

from tests.support import corpus
from uploadshield import (
    InspectedFile,
    Policy,
    Upload,
    ValidationResult,
    presets,
    validate,
)
from uploadshield.checks import FilenameCheck
from uploadshield.core.check import Replacement, Sanitizer
from uploadshield.sanitizers import RandomizeFilename, ReencodeImage, SafeFilename


def run(data: bytes, name: str, policy: Policy) -> ValidationResult:
    return validate(Upload.from_bytes(data, name), policy)


def test_reencode_strips_metadata_and_applies_orientation() -> None:
    original = corpus.jpeg_with_metadata()
    with Image.open(io.BytesIO(original)) as im:
        assert im.getexif().get(0x010F) == "EvilCam"
        assert im.size == (40, 20)
    result = run(original, "holiday.jpg", presets.SANITIZED_IMAGES)
    assert result.ok
    assert result.sanitized is not None
    assert result.sanitized.applied == ("reencode_image", "randomize_filename")
    assert result.sanitized.content_type == "image/jpeg"
    assert result.sanitized.name.endswith(".jpg")
    assert len(result.sanitized.name) == 32 + 4
    data = result.sanitized.data
    assert data is not None
    assert b"EvilCam" not in data
    assert b"secret comment" not in data
    with Image.open(io.BytesIO(data)) as im:
        assert dict(im.getexif()) == {}
        assert im.size == (20, 40)  # rotated according to the orientation tag


def test_reencode_keeps_animation_and_drops_comments() -> None:
    result = run(corpus.animated_gif(), "a.gif", presets.SANITIZED_IMAGES)
    assert result.sanitized is not None
    assert result.sanitized.data is not None
    assert b"tracking-id-123" not in result.sanitized.data
    with Image.open(io.BytesIO(result.sanitized.data)) as im:
        assert getattr(im, "n_frames", 1) == 3


@pytest.mark.parametrize(
    ("fmt", "mode"),
    [("PNG", "RGBA"), ("PNG", "P"), ("WEBP", "RGB"), ("JPEG", "L"), ("JPEG", "CMYK")],
)
def test_reencode_formats_and_modes(fmt: str, mode: str) -> None:
    ext = {"JPEG": "jpg"}.get(fmt, fmt.lower())
    result = run(corpus.image(fmt, mode=mode), f"a.{ext}", presets.SANITIZED_IMAGES)
    assert result.ok, result.codes
    assert result.sanitized is not None
    assert result.sanitized.data is not None
    with Image.open(io.BytesIO(result.sanitized.data)) as im:
        assert im.format == fmt


def test_reencode_also_removes_trailing_payloads() -> None:
    lenient = presets.SANITIZED_IMAGES.replace(content_checks=())
    payload = corpus.png() + b"<?php system('id'); ?>"
    result = run(payload, "a.png", lenient)
    assert result.sanitized is not None
    assert result.sanitized.data is not None
    assert b"<?php" not in result.sanitized.data


def test_safe_filename() -> None:
    policy = presets.PDF.replace(sanitizers=(SafeFilename(),))
    cases = {
        "Résumé (final).PDF": "Resume_final.pdf",
        "report.pdf": "report.pdf",
        "中文.pdf": "file.pdf",
    }
    for name, expected in cases.items():
        result = run(corpus.pdf(), name, policy)
        assert result.sanitized is not None
        assert result.sanitized.name == expected
        assert result.sanitized.data is None  # content untouched
    long = run(
        corpus.pdf(), "x" * 300 + ".pdf", policy.replace(filename=FilenameCheck(max_length=400))
    )
    assert long.sanitized is not None
    assert len(long.sanitized.name) == 100


def test_randomize_filename_uses_refined_type() -> None:
    policy = presets.DOCUMENTS.replace(sanitizers=(RandomizeFilename(),))
    result = run(b"a,b\n1,2\n", "Data.CSV", policy)
    assert result.sanitized is not None
    assert result.sanitized.name.endswith(".csv")
    assert result.sanitized.content_type == "text/csv"


@dataclass(frozen=True)
class Corrupting(Sanitizer):
    name = "corrupting"

    def sanitize(self, file: InspectedFile) -> Replacement:
        return Replacement(data=b"<html>now it is html</html>")


@dataclass(frozen=True)
class Crashing(Sanitizer):
    name = "crashing"

    def sanitize(self, file: InspectedFile) -> Replacement:
        raise OSError("disk full")


@dataclass(frozen=True)
class NoOp(Sanitizer):
    name = "noop"

    def sanitize(self, file: InspectedFile) -> Replacement:
        return Replacement()


def test_sanitizer_failures_fail_closed() -> None:
    corrupting = presets.IMAGES.replace(sanitizers=(Corrupting(),))
    assert run(corpus.png(), "a.png", corrupting).codes == ("sanitization_failed",)
    crashing = presets.IMAGES.replace(sanitizers=(Crashing(),))
    assert run(corpus.png(), "a.png", crashing).codes == ("sanitization_failed",)
    noop = presets.IMAGES.replace(sanitizers=(NoOp(),))
    result = run(corpus.png(), "a.png", noop)
    assert result.ok
    assert result.sanitized is not None
    assert result.sanitized.applied == ("noop",)


def test_sanitizers_skip_unsupported_types_and_can_be_disabled() -> None:
    policy = presets.DOCUMENTS.replace(sanitizers=(ReencodeImage(),))
    assert run(corpus.pdf(), "a.pdf", policy).sanitized is None
    assert (
        validate(
            Upload.from_bytes(corpus.png(), "a.png"), presets.SANITIZED_IMAGES, sanitize=False
        ).sanitized
        is None
    )


@pytest.mark.owasp("filename.reserved-names")
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("C\u00d6N.pdf", "CON_.pdf"),  # folds to the device name CON
        ("\u00c4UX.pdf", "AUX_.pdf"),
        ("n\u00fcL.pdf", "nuL_.pdf"),
        ("c\u014dm1.pdf", "com1_.pdf"),
        ("CO\u0143.pdf", "CON_.pdf"),
        ("CONSOLE.pdf", "CONSOLE.pdf"),  # not a device name
    ],
)
def test_safe_filename_never_produces_device_names(name: str, expected: str) -> None:
    result = run(corpus.pdf(), name, presets.PDF.replace(sanitizers=(SafeFilename(),)))
    assert result.ok
    assert result.sanitized is not None
    assert result.sanitized.name == expected


@dataclass(frozen=True)
class Renaming(Sanitizer):
    name = "renaming"
    to: str = "shell.php"

    def sanitize(self, file: InspectedFile) -> Replacement:
        return Replacement(name=self.to)


@pytest.mark.owasp("ufu.detector.decompression")
@pytest.mark.parametrize(
    ("to", "code"),
    [
        ("shell.php", "filename_dangerous_extension"),
        ("../../etc/cron.d/x.png", "filename_invalid"),
        ("nul.png", "filename_reserved"),
    ],
)
def test_names_from_sanitizers_pass_the_filename_rules(to: str, code: str) -> None:
    result = run(corpus.png(), "a.png", presets.IMAGES.replace(sanitizers=(Renaming(to),)))
    assert code in result.codes
    assert result.sanitized is None
    assert result.violations[0].details["in_sanitized_output"] is True
    renamed = run(corpus.png(), "a.png", presets.IMAGES.replace(sanitizers=(Renaming("b.png"),)))
    assert renamed.ok
    assert renamed.sanitized is not None
    assert renamed.sanitized.name == "b.png"


def test_reencoding_refuses_animations_with_too_many_pixels() -> None:
    gif = corpus.gif_with_frames(30)  # 30 frames of 2x1 pixels
    unchecked = presets.IMAGES.replace(content_checks=(), sanitizers=(ReencodeImage(),))
    assert run(gif, "a.gif", unchecked).ok
    capped = unchecked.replace(sanitizers=(ReencodeImage(max_total_pixels=50),))
    assert run(gif, "a.gif", capped).codes == ("sanitization_failed",)
