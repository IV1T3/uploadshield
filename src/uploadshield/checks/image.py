"""Raster image integrity via Pillow (``uv add "uploadshield[images]"``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from uploadshield.core.check import Check
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["PILLOW_FORMATS", "ImageIntegrity", "pillow_supports"]

#: Detected MIME type -> Pillow format names that may legitimately decode it.
PILLOW_FORMATS: dict[str, tuple[str, ...]] = {
    "image/jpeg": ("JPEG", "MPO"),
    "image/png": ("PNG",),
    "image/gif": ("GIF",),
    "image/webp": ("WEBP",),
    "image/bmp": ("BMP", "DIB"),
    "image/tiff": ("TIFF",),
    "image/vnd.microsoft.icon": ("ICO",),
    "image/avif": ("AVIF",),
    "image/heic": ("HEIF",),
}


def pillow_supports(mime: str) -> bool:
    """Whether the installed Pillow has a decoder for ``mime``."""
    try:
        from PIL import Image
    except ImportError:
        return False
    Image.init()
    return any(fmt in Image.OPEN for fmt in PILLOW_FORMATS.get(mime, ()))


@dataclass(frozen=True, slots=True)
class ImageIntegrity(Check):
    """Decode the image completely and enforce pixel, frame and total-pixel limits.

    Decoding with the format the *sniffer* detected (not whatever Pillow guesses)
    proves the bytes really are that format.  Limits are checked from the header
    before any pixel data is decoded, which defeats decompression bombs.  Formats the
    installed Pillow cannot decode (e.g. HEIC without a plugin) are skipped.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "image"
    requires = ("PIL",)

    max_pixels: int = 50_000_000
    max_frames: int = 1_000
    #: All frames together: an animation of 100 frames of 4000x4000 pixels is 1.3 MB on
    #: the wire but costs minutes and gigabytes to re-encode.
    max_total_pixels: int = 100_000_000

    def applies(self, file: InspectedFile) -> bool:
        file_type = file.file_type
        return file_type is not None and pillow_supports(file_type.mime)

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        if (found := self._inspect(file)) is not None:
            yield found

    def _inspect(self, file: InspectedFile) -> Violation | None:
        from PIL import Image

        if file.file_type is None:  # pragma: no cover - excluded by applies()
            return None
        formats = PILLOW_FORMATS[file.file_type.mime]
        try:
            with file.open() as fh, Image.open(fh, formats=formats) as image:
                width, height = image.size
                frames = getattr(image, "n_frames", 1)
                if (
                    width * height > self.max_pixels
                    or frames > self.max_frames
                    or width * height * frames > self.max_total_pixels
                ):
                    return self.violation(
                        Code.IMAGE_TOO_LARGE,
                        "The image dimensions are too large.",
                        width=width,
                        height=height,
                        frames=frames,
                        max_pixels=self.max_pixels,
                    )
                image.verify()
            # verify() leaves the image unusable; decode again to catch truncation.
            with file.open() as fh, Image.open(fh, formats=formats) as image:
                image.load()
        except Image.DecompressionBombError as exc:
            return self.violation(
                Code.IMAGE_TOO_LARGE, "The image dimensions are too large.", error=str(exc)
            )
        except Exception as exc:  # any decoder failure means "corrupt"
            return self.violation(
                Code.IMAGE_CORRUPT,
                "The image is damaged or not a valid image file.",
                error=f"{type(exc).__name__}: {exc}",
            )
        return None
