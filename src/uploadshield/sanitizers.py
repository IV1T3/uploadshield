"""Sanitizers turn a validated upload into a safer equivalent.

They run only after every check passed.  Content Disarm & Reconstruction
(re-encoding) is the strongest generic defence for images: whatever was hidden in
metadata, comments or trailing bytes does not survive a decode/encode round trip.
"""

from __future__ import annotations

import io
import re
import unicodedata
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .checks.basic import WINDOWS_RESERVED_NAMES
from .core.check import Replacement, Sanitizer
from .core.types import MiB

if TYPE_CHECKING:
    from .core.upload import InspectedFile

__all__ = ["RandomizeFilename", "ReencodeImage", "SafeFilename", "Sanitizer"]

_PUBLIC = "uploadshield.sanitizers"
_PILLOW_SAVE_FORMATS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/gif": "GIF",
    "image/webp": "WEBP",
}
#: Image.info keys that describe pixels/animation rather than metadata.
_KEEP_INFO = frozenset({"transparency", "duration", "loop", "background", "disposal"})


@dataclass(frozen=True, slots=True)
class ReencodeImage(Sanitizer):
    """Decode and re-encode JPEG/PNG/GIF/WebP images, discarding all metadata.

    EXIF (incl. GPS location), XMP, comments and any bytes after the image data are
    removed.  The EXIF orientation is applied to the pixels first so photos do not
    appear rotated.  Animated GIF/WebP keep their frames.
    """

    _deconstruct_module = _PUBLIC
    name = "reencode_image"
    requires = ("PIL",)

    quality: int = 90
    keep_icc_profile: bool = True
    max_bytes: int = 100 * MiB
    #: Refuse to re-encode more pixels than this across all frames (see ImageIntegrity).
    max_total_pixels: int = 100_000_000

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and file.file_type.mime in _PILLOW_SAVE_FORMATS

    def sanitize(self, file: InspectedFile) -> Replacement:
        from PIL import Image, ImageOps

        if file.file_type is None:  # pragma: no cover - excluded by applies()
            return Replacement()
        fmt = _PILLOW_SAVE_FORMATS[file.file_type.mime]
        with Image.open(io.BytesIO(file.read(self.max_bytes)), formats=[fmt]) as source:
            # MPO (multi-picture JPEG from cameras) also has frames; keep only the first.
            frames = getattr(source, "n_frames", 1)
            if source.width * source.height * frames > self.max_total_pixels:
                raise ValueError(f"{frames} frames of {source.size} exceed max_total_pixels")
            animated = fmt in ("GIF", "WEBP") and frames > 1
            image = source if animated else (ImageOps.exif_transpose(source) or source)
            icc = image.info.get("icc_profile") if self.keep_icc_profile else None
            image.info = {k: v for k, v in source.info.items() if k in _KEEP_INFO}
            if fmt == "JPEG" and image.mode not in ("RGB", "L", "CMYK"):
                image = image.convert("RGB")
            options: dict[str, object] = {"format": fmt}
            if icc:
                options["icc_profile"] = icc
            if fmt in ("JPEG", "WEBP"):
                options["quality"] = self.quality
            if animated:
                options["save_all"] = True
            out = io.BytesIO()
            image.save(out, **options)
        return Replacement(data=out.getvalue())


@dataclass(frozen=True, slots=True)
class RandomizeFilename(Sanitizer):
    """Replace the client's filename with a random one plus the canonical extension
    of the *detected* type, e.g. ``3f2b...9c.jpg``.

    This removes every name-based attack (traversal, double extensions, Unicode
    tricks, collisions) and stops filenames from leaking personal information.
    """

    _deconstruct_module = _PUBLIC
    name = "randomize_filename"

    def sanitize(self, file: InspectedFile) -> Replacement:
        extension = file.file_type.canonical_extension if file.file_type else ""
        return Replacement(name=f"{uuid.uuid4().hex}{extension}")


_UNSAFE_NAME_CHARS = re.compile(r"[^\w.\- ]+")
_SPACES = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class SafeFilename(Sanitizer):
    """Keep a readable name but normalise it to ``[A-Za-z0-9_.- ]`` characters, a single
    extension that matches the detected type, and at most ``max_length`` characters.

    ``"Résumé (final).PDF"`` becomes ``"Resume_final.pdf"``.
    """

    _deconstruct_module = _PUBLIC
    name = "safe_filename"

    max_length: int = 100

    def sanitize(self, file: InspectedFile) -> Replacement:
        extension = file.file_type.canonical_extension if file.file_type else ""
        if file.file_type and file.extension in file.file_type.extensions:
            extension = file.extension
        stem = file.name.lstrip(".").split(".", 1)[0]
        ascii_stem = unicodedata.normalize("NFKD", stem).encode("ascii", "ignore").decode()
        cleaned = _SPACES.sub("_", _UNSAFE_NAME_CHARS.sub("", ascii_stem).strip()).strip("._-")
        cleaned = cleaned[: max(1, self.max_length - len(extension))] or "file"
        if cleaned.lower() in WINDOWS_RESERVED_NAMES:  # "C\u00d6N" folds to "CON", a device
            cleaned += "_"
        return Replacement(name=f"{cleaned}{extension}")
