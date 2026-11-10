"""Ready-made type sets and policies.

Every preset is an allow-list: formats that are script-capable when served from
your origin (HTML, SVG, XML) or executable are never included.
"""

from __future__ import annotations

from .core.types import MB
from .policy import Policy
from .sanitizers import RandomizeFilename, ReencodeImage

__all__ = [
    "AUDIO_TYPES",
    "BUILTIN_POLICIES",
    "DEFAULT",
    "DOCUMENTS",
    "DOCUMENT_TYPES",
    "IMAGES",
    "IMAGE_TYPES",
    "MEDIA",
    "OFFICE_TYPES",
    "PDF",
    "SANITIZED_IMAGES",
    "TEXT_TYPES",
    "VIDEO_TYPES",
]

IMAGE_TYPES = frozenset({"image/jpeg", "image/png", "image/gif", "image/webp"})
OFFICE_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
    }
)
TEXT_TYPES = frozenset({"text/plain", "text/csv"})
DOCUMENT_TYPES = frozenset({"application/pdf"}) | OFFICE_TYPES | TEXT_TYPES
AUDIO_TYPES = frozenset(
    {"audio/mpeg", "audio/wav", "audio/ogg", "audio/flac", "audio/mp4", "audio/aac"}
)
VIDEO_TYPES = frozenset({"video/mp4", "video/webm", "video/quicktime"})

IMAGES = Policy(name="images", allowed_types=IMAGE_TYPES, max_size=10 * MB)
#: Images re-encoded without metadata and stored under a random name - the right
#: default for avatars and other user images that are displayed to other users.
SANITIZED_IMAGES = IMAGES.replace(
    name="sanitized_images", sanitizers=(ReencodeImage(), RandomizeFilename())
)
PDF = Policy(name="pdf", allowed_types={"application/pdf"}, max_size=25 * MB)
DOCUMENTS = Policy(name="documents", allowed_types=DOCUMENT_TYPES, max_size=25 * MB)
MEDIA = Policy(name="media", allowed_types=AUDIO_TYPES | VIDEO_TYPES, max_size=500 * MB)
#: Common, passive formats.  Used by the upload handler when nothing more specific applies.
DEFAULT = Policy(
    name="default",
    allowed_types=IMAGE_TYPES | DOCUMENT_TYPES | AUDIO_TYPES | VIDEO_TYPES,
    max_size=50 * MB,
)

BUILTIN_POLICIES: dict[str, Policy] = {
    p.name: p for p in (DEFAULT, IMAGES, SANITIZED_IMAGES, PDF, DOCUMENTS, MEDIA)
}
