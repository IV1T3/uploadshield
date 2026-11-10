"""ImageIntegrity: full decoding with the sniffed format, pixel and frame limits."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from uploadshield import Policy, Upload, presets, validate
from uploadshield.checks import (
    ImageIntegrity,
)


@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "GIF", "WEBP"])
def test_valid_images_pass(fmt: str) -> None:
    ext = {"JPEG": "jpg"}.get(fmt, fmt.lower())
    assert codes(corpus.image(fmt), f"a.{ext}") == ()


def test_truncated_and_corrupt_images_are_refused() -> None:
    assert codes(corpus.png()[:60], "a.png") == ("image_corrupt",)
    jpeg = corpus.image("JPEG", size=(64, 64))
    assert codes(jpeg[: len(jpeg) // 2], "a.jpg") == ("image_corrupt",)
    assert codes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100, "a.png") == ("image_corrupt",)


def test_decompression_bombs_are_refused_before_decoding() -> None:
    assert codes(corpus.png_huge_dimensions(), "bomb.png") == ("image_too_large",)
    small_limit = presets.IMAGES.replace(content_checks=(ImageIntegrity(max_pixels=100),))
    assert codes(corpus.image("PNG", size=(20, 20)), "a.png", small_limit) == ("image_too_large",)
    frames = presets.IMAGES.replace(content_checks=(ImageIntegrity(max_frames=2),))
    assert codes(corpus.animated_gif(), "a.gif", frames) == ("image_too_large",)


def test_image_check_skips_formats_pillow_cannot_decode() -> None:
    heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" + b"\x00" * 64
    policy = Policy(allowed_types={"image/heic"})
    result = validate(Upload.from_bytes(heic, "a.heic"), policy)
    assert result.ok
    assert "image" not in result.checks_run


@pytest.mark.owasp("content.image-library")
def test_animations_are_limited_by_their_total_pixels() -> None:
    # Each frame is small and the frame count is allowed: together they are too many.
    gif = corpus.gif_with_frames(30)  # 30 frames of 2x1 pixels
    total = presets.IMAGES.replace(content_checks=(ImageIntegrity(max_total_pixels=50),))
    assert codes(gif, "a.gif", total) == ("image_too_large",)
    assert codes(gif, "a.gif", presets.IMAGES) == ()
    assert ImageIntegrity().max_total_pixels == 100_000_000
