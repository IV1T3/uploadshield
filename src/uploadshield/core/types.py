"""A deterministic registry of the file types this library can reason about.

The standard library's :mod:`mimetypes` reads ``/etc/mime.types`` and the Windows
registry, so its answers differ between machines.  Validation results must not depend
on the host, so every type we detect or allow is declared here explicitly.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = [
    "GB",
    "KB",
    "MB",
    "FileType",
    "GiB",
    "KiB",
    "MiB",
    "all_types",
    "get_type",
    "register_type",
    "resolve_mime",
    "types_for_extension",
]

KB = 1000
MB = 1000 * KB
GB = 1000 * MB
KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB


@dataclass(frozen=True, slots=True)
class FileType:
    """A file format identified by its canonical MIME type.

    ``extensions`` are lowercase, start with a dot and the first one is canonical.
    ``aliases`` are non-canonical MIME strings that clients commonly send.
    ``container`` names the physical container (``"zip"``/``"ole"``) so that
    container-level checks can apply to every format built on it.
    ``parent`` marks a *refinement*: content can prove a file is ``text/plain`` but not
    that it is CSV, so a ``.csv`` name may narrow ``text/plain`` to ``text/csv``.
    """

    mime: str
    extensions: tuple[str, ...]
    label: str
    aliases: tuple[str, ...] = ()
    container: str | None = None
    is_text: bool = False
    parent: str | None = None
    executable: bool = field(default=False, compare=False)

    def __post_init__(self) -> None:
        if self.mime != self.mime.lower() or "/" not in self.mime:
            raise ValueError(f"MIME type must be lowercase 'type/subtype': {self.mime!r}")
        for ext in self.extensions:
            if not ext.startswith(".") or ext != ext.lower():
                raise ValueError(f"Extensions must be lowercase and start with '.': {ext!r}")

    @property
    def category(self) -> str:
        """The top-level media type, e.g. ``"image"`` for ``image/png``."""
        return self.mime.split("/", 1)[0]

    @property
    def canonical_extension(self) -> str:
        return self.extensions[0] if self.extensions else ""

    def matches(self, mime: str) -> bool:
        """Whether ``mime`` (canonical or alias, parameters ignored) denotes this type."""
        bare = normalize_mime(mime)
        return bare == self.mime or bare in self.aliases


def normalize_mime(mime: str) -> str:
    """Strip parameters and whitespace and lowercase a MIME string."""
    return mime.split(";", 1)[0].strip().lower()


def format_size(num_bytes: int) -> str:
    """Human-readable decimal size: ``format_size(2_500_000) == "2.5 MB"``."""
    value = float(num_bytes)
    for unit in ("bytes", "KB", "MB", "GB"):
        if value < 1000 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "bytes" else f"{value:.3g} {unit}"
        value /= 1000
    raise AssertionError("unreachable")  # pragma: no cover


_OOXML = "application/vnd.openxmlformats-officedocument"
_ODF = "application/vnd.oasis.opendocument"

_BUILTIN_TYPES: tuple[FileType, ...] = (
    # --- raster & vector images -------------------------------------------------------
    FileType(
        "image/jpeg",
        (".jpg", ".jpeg", ".jpe", ".jfif"),
        "JPEG image",
        aliases=("image/jpg", "image/pjpeg"),
    ),
    FileType("image/png", (".png",), "PNG image", aliases=("image/x-png",)),
    FileType("image/gif", (".gif",), "GIF image"),
    FileType("image/webp", (".webp",), "WebP image"),
    FileType("image/bmp", (".bmp", ".dib"), "BMP image", aliases=("image/x-ms-bmp", "image/x-bmp")),
    FileType("image/tiff", (".tif", ".tiff"), "TIFF image"),
    FileType("image/vnd.microsoft.icon", (".ico",), "ICO icon", aliases=("image/x-icon",)),
    FileType("image/avif", (".avif",), "AVIF image"),
    FileType("image/heic", (".heic", ".heif"), "HEIC image", aliases=("image/heif",)),
    FileType("image/svg+xml", (".svg",), "SVG image", is_text=True),
    # --- documents --------------------------------------------------------------------
    FileType("application/pdf", (".pdf",), "PDF document", aliases=("application/x-pdf",)),
    FileType(f"{_OOXML}.wordprocessingml.document", (".docx",), "Word document", container="zip"),
    FileType(f"{_OOXML}.spreadsheetml.sheet", (".xlsx",), "Excel workbook", container="zip"),
    FileType(
        f"{_OOXML}.presentationml.presentation",
        (".pptx",),
        "PowerPoint presentation",
        container="zip",
    ),
    FileType(
        "application/vnd.ms-word.document.macroenabled.12",
        (".docm",),
        "Word macro-enabled document",
        container="zip",
    ),
    FileType(
        "application/vnd.ms-excel.sheet.macroenabled.12",
        (".xlsm",),
        "Excel macro-enabled workbook",
        container="zip",
    ),
    FileType(
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        (".pptm",),
        "PowerPoint macro-enabled presentation",
        container="zip",
    ),
    FileType(f"{_ODF}.text", (".odt",), "OpenDocument text", container="zip"),
    FileType(f"{_ODF}.spreadsheet", (".ods",), "OpenDocument spreadsheet", container="zip"),
    FileType(f"{_ODF}.presentation", (".odp",), "OpenDocument presentation", container="zip"),
    FileType("application/epub+zip", (".epub",), "EPUB e-book", container="zip"),
    FileType(
        "application/x-ole-storage",
        (".doc", ".xls", ".ppt", ".msg"),
        "OLE2 compound document (legacy Office)",
        container="ole",
        aliases=(
            "application/msword",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/vnd.ms-outlook",
        ),
    ),
    FileType("application/rtf", (".rtf",), "Rich Text Format", aliases=("text/rtf",)),
    FileType("application/postscript", (".ps", ".eps"), "PostScript"),
    # --- text -------------------------------------------------------------------------
    FileType("text/plain", (".txt", ".text", ".log"), "Plain text", is_text=True),
    FileType(
        "text/csv",
        (".csv",),
        "CSV",
        is_text=True,
        parent="text/plain",
        aliases=("application/csv",),
    ),
    FileType("text/tab-separated-values", (".tsv",), "TSV", is_text=True, parent="text/plain"),
    FileType("text/markdown", (".md", ".markdown"), "Markdown", is_text=True, parent="text/plain"),
    FileType("application/json", (".json",), "JSON", is_text=True, parent="text/plain"),
    FileType("text/html", (".html", ".htm", ".xhtml"), "HTML document", is_text=True),
    FileType("application/xml", (".xml",), "XML document", is_text=True, aliases=("text/xml",)),
    FileType(
        "application/x-sh",
        (".sh",),
        "Shell script",
        is_text=True,
        aliases=("text/x-shellscript",),
        executable=True,
    ),
    FileType(
        "application/x-httpd-php",
        (".php",),
        "PHP script",
        is_text=True,
        aliases=("application/x-php", "text/x-php"),
        executable=True,
    ),
    # --- archives ---------------------------------------------------------------------
    FileType(
        "application/zip",
        (".zip",),
        "ZIP archive",
        container="zip",
        aliases=("application/x-zip-compressed",),
    ),
    FileType("application/gzip", (".gz", ".tgz"), "gzip archive", aliases=("application/x-gzip",)),
    FileType("application/x-tar", (".tar",), "tar archive"),
    FileType("application/x-bzip2", (".bz2",), "bzip2 archive"),
    FileType("application/x-xz", (".xz",), "xz archive"),
    FileType("application/x-7z-compressed", (".7z",), "7-Zip archive"),
    FileType(
        "application/vnd.rar", (".rar",), "RAR archive", aliases=("application/x-rar-compressed",)
    ),
    FileType(
        "application/java-archive", (".jar",), "Java archive", container="zip", executable=True
    ),
    FileType(
        "application/vnd.android.package-archive",
        (".apk",),
        "Android package",
        container="zip",
        executable=True,
    ),
    # --- audio ------------------------------------------------------------------------
    FileType("audio/mpeg", (".mp3",), "MP3 audio", aliases=("audio/mp3",)),
    FileType(
        "audio/wav", (".wav",), "WAV audio", aliases=("audio/x-wav", "audio/wave", "audio/vnd.wave")
    ),
    FileType("audio/ogg", (".ogg", ".oga", ".opus"), "Ogg audio"),
    FileType("audio/flac", (".flac",), "FLAC audio", aliases=("audio/x-flac",)),
    FileType("audio/mp4", (".m4a",), "MPEG-4 audio", aliases=("audio/x-m4a",)),
    FileType("audio/aac", (".aac",), "AAC audio"),
    # --- video ------------------------------------------------------------------------
    FileType("video/mp4", (".mp4", ".m4v"), "MPEG-4 video"),
    FileType("video/quicktime", (".mov", ".qt"), "QuickTime video"),
    FileType("video/webm", (".webm",), "WebM video"),
    FileType("video/x-matroska", (".mkv",), "Matroska video"),
    FileType("video/x-msvideo", (".avi",), "AVI video", aliases=("video/avi", "video/msvideo")),
    FileType("video/mpeg", (".mpeg", ".mpg"), "MPEG video"),
    FileType("video/3gpp", (".3gp",), "3GPP video"),
    # --- executables & other binaries (detected so they can be named and refused) -----
    FileType(
        "application/vnd.microsoft.portable-executable",
        (".exe", ".dll", ".sys", ".scr"),
        "Windows executable",
        aliases=("application/x-msdownload", "application/x-dosexec"),
        executable=True,
    ),
    FileType("application/x-elf", (".elf", ".so"), "ELF executable", executable=True),
    FileType("application/x-mach-binary", (".dylib",), "Mach-O executable", executable=True),
    FileType("application/java-vm", (".class",), "Java class file", executable=True),
    FileType("application/wasm", (".wasm",), "WebAssembly module", executable=True),
    FileType("application/vnd.sqlite3", (".sqlite", ".sqlite3", ".db"), "SQLite database"),
)


class _Registry:
    """Thread-safe lookup tables built from the declared types."""

    def __init__(self, types: Iterable[FileType]) -> None:
        self._lock = threading.Lock()
        self._by_mime: dict[str, FileType] = {}
        self._by_alias: dict[str, FileType] = {}
        self._by_ext: dict[str, list[FileType]] = {}
        for ft in types:
            self.register(ft)

    def register(self, file_type: FileType) -> None:
        with self._lock:
            existing = self._by_mime.get(file_type.mime)
            if existing is not None and existing != file_type:
                raise ValueError(f"A different FileType is already registered for {file_type.mime}")
            self._by_mime[file_type.mime] = file_type
            for alias in file_type.aliases:
                self._by_alias.setdefault(alias, file_type)
            for ext in file_type.extensions:
                bucket = self._by_ext.setdefault(ext, [])
                if file_type not in bucket:
                    bucket.append(file_type)

    def get(self, mime: str) -> FileType | None:
        bare = normalize_mime(mime)
        return self._by_mime.get(bare) or self._by_alias.get(bare)

    def for_extension(self, ext: str) -> tuple[FileType, ...]:
        return tuple(self._by_ext.get(ext.lower(), ()))

    def __iter__(self) -> Iterator[FileType]:
        return iter(tuple(self._by_mime.values()))


_registry = _Registry(_BUILTIN_TYPES)


def get_type(mime: str) -> FileType | None:
    """Look up a type by canonical MIME or alias (case and parameters ignored)."""
    return _registry.get(mime)


def resolve_mime(mime: str) -> FileType:
    """Like :func:`get_type` but raise a helpful ``ValueError`` for unknown types."""
    ft = _registry.get(mime)
    if ft is None:
        raise ValueError(
            f"Unknown file type {mime!r}. Use a canonical MIME type such as 'image/jpeg', "
            "a wildcard such as 'image/*', or register custom types with register_type()."
        )
    return ft


def types_for_extension(ext: str) -> tuple[FileType, ...]:
    """All registered types that use ``ext`` (e.g. ``".jpg"``)."""
    return _registry.for_extension(ext)


def all_types() -> tuple[FileType, ...]:
    return tuple(_registry)


def register_type(file_type: FileType) -> None:
    """Register a custom type, e.g. one produced by a custom :class:`Sniffer`."""
    _registry.register(file_type)
