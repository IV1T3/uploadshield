"""Cheap checks on size, name and type that every policy runs first."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import unquote

from uploadshield.core.check import Check
from uploadshield.core.types import (
    FileType,
    all_types,
    format_size,
    get_type,
    normalize_mime,
    resolve_mime,
)
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = [
    "DANGEROUS_EXTENSIONS",
    "DANGEROUS_NAMES",
    "WINDOWS_RESERVED_NAMES",
    "AllowedTypes",
    "DeclaredTypeMatches",
    "ExtensionMatchesType",
    "FileSize",
    "FilenameCheck",
    "extension_segments",
    "name_variants",
]

_PUBLIC = "uploadshield.checks"

#: Extensions that web servers may execute or treat as configuration, and file types
#: Windows runs when a user opens a download.  They are refused *anywhere* in a name,
#: defeating ``shell.php.jpg`` and ``shell.asp;.jpg``.  A defense in depth only: the
#: allow-list on the *content* is what decides (OWASP: blocklists alone are weak).
DANGEROUS_EXTENSIONS = frozenset(
    {
        "php",
        "php2",
        "php3",
        "php4",
        "php5",
        "php6",
        "php7",
        "php8",
        "phpt",
        "pht",
        "phtm",
        "phtml",
        "phar",
        "phps",
        "pgif",
        "inc",
        "hphp",
        "ctp",
        "shtml",
        "shtm",
        "stm",
        "asp",
        "aspx",
        "aspq",
        "ascx",
        "ashx",
        "asmx",
        "asax",
        "asa",
        "cer",
        "cshtml",
        "cshtm",
        "vbhtml",
        "vbhtm",
        "axd",
        "rem",
        "soap",
        "svc",
        "jsp",
        "jspx",
        "jspf",
        "jsw",
        "jsv",
        "wss",
        "war",
        "cfm",
        "cfml",
        "cfc",
        "dbm",
        "cgi",
        "pl",
        "pm",
        "py",
        "pyc",
        "pyw",
        "rb",
        "sh",
        "bash",
        "ksh",
        "zsh",
        "bat",
        "cmd",
        "com",
        "exe",
        "dll",
        "msi",
        "msp",
        "scr",
        "pif",
        "cpl",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "wsc",
        "ws",
        "sct",
        "hta",
        "ps1",
        "psm1",
        "psd1",
        "ps1xml",
        "lnk",
        "url",
        "scf",
        "reg",
        "inf",
        "msc",
        "chm",
        "hlp",
        "jar",
        "jnlp",
        "swf",  # Flash and Silverlight: cross-site content hijacking
        "xap",
        "application",
        "appref-ms",
        "gadget",
        "settingcontent-ms",
        "iqy",
        "slk",
        "xll",
        "htaccess",
        "htpasswd",
    }
)

#: Whole names that act as server or browser configuration when dropped into a directory:
#: web server config, and the Flash/Silverlight cross-domain policies browsers obey.
DANGEROUS_NAMES = frozenset(
    {
        ".htaccess",
        ".htpasswd",
        "web.config",
        ".user.ini",
        "php.ini",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
    }
)

WINDOWS_RESERVED_NAMES = _WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{i}" for i in range(10)}
    | {f"lpt{i}" for i in range(10)}
)
#: Characters Windows forbids in names (besides separators): they also break shell
#: quoting (``|``, ``*``, ``?``), header quoting (``"``) and unescaped HTML (``<>``).
_WINDOWS_FORBIDDEN = '<>"|?*'
#: A Windows 8.3 short-name alias such as ``WEBCON~1.CON`` (OWASP: overwrite checks
#: that only look at long names can be bypassed through it).
_SHORT_NAME = re.compile(r"^[^~.\s]{1,6}~[0-9]{1,6}(?:\.[^.]{1,3})?$")
_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_SEGMENT_TERMINATORS = re.compile(r"[:;\s]")


def _is_forbidden_char(char: str) -> bool:
    # Control characters (C0, DEL, C1), bidi overrides, path separators including ":"
    # (Windows drives and NTFS streams: os.path.join("D:\\up", "C:x.png") is "C:x.png"),
    # and the other characters Windows forbids.  Other format characters are legitimate:
    # emoji ZWJ sequences, and the U+202F narrow no-break space macOS puts into
    # screenshot names.  Lone surrogates ("Cs") are bytes that were not valid UTF-8 in a
    # name read from disk: no filesystem can store them as text.
    return (
        char in _BIDI_CONTROLS
        or char in "/\\:"
        or char in _WINDOWS_FORBIDDEN
        or unicodedata.category(char) in ("Cc", "Cs")
    )


def name_variants(name: str) -> list[tuple[str, str]]:
    """``(variant, how)`` pairs: the name itself and how later layers may read it.

    OWASP: validate *after* decoding.  Names are percent-decoded repeatedly (double
    encoding: ``%2500`` -> ``%00`` -> NUL) and NFKC-normalised, which is what Windows'
    "best fit" conversion and many filesystems do to fullwidth forms (U+FF50 U+FF48
    U+FF50 -> ``php``, U+FF0F -> ``/``) and superscripts (``COM\u00b9`` -> ``COM1``).
    """
    variants = [(name, "raw")]
    current = name
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            break
        variants.append((decoded, "percent-decoded"))
        current = decoded
    for text, _how in list(variants):
        normalized = unicodedata.normalize("NFKC", text)
        if all(normalized != seen for seen, _ in variants):
            variants.append((normalized, "normalized"))
    return variants


#: Content that executes scripts in browsers; wildcards never match these.
_SCRIPTABLE = frozenset({"text/html", "image/svg+xml", "application/xml"})
#: Archives that no check opens, so their members cannot be inspected.  Wildcards never
#: match them: a policy accepts one only by naming its type.
UNINSPECTED_ARCHIVES = frozenset({"application/x-7z-compressed", "application/vnd.rar"})


@dataclass(frozen=True, slots=True)
class FileSize(Check):
    """Refuse empty files and files larger than ``max_bytes``."""

    _deconstruct_module = _PUBLIC
    name = "size"
    stage = "size"

    max_bytes: int | None = None
    allow_empty: bool = False

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        if file.size == 0 and not self.allow_empty:
            yield self.violation(Code.FILE_EMPTY, "The file is empty.")
        if self.max_bytes is not None and file.size > self.max_bytes:
            yield self.violation(
                Code.FILE_TOO_LARGE,
                f"The file is too large (maximum {format_size(self.max_bytes)}).",
                size=file.size,
                limit=self.max_bytes,
            )


@dataclass(frozen=True, slots=True)
class FilenameCheck(Check):
    """Refuse names that can attack storage backends, web servers or users.

    Follows the OWASP File Upload Cheat Sheet: the name is judged as given *and* as
    decoding layers may later read it (:func:`name_variants`).  It refuses control and
    bidi-override characters, path and drive separators and the other characters
    Windows forbids, hidden files and server configuration names, Windows device and
    8.3 short names, leading hyphens or spaces (argument injection), consecutive dots,
    trailing dots/spaces, over-long names and executable extensions in any position
    (double extensions).
    """

    _deconstruct_module = _PUBLIC
    name = "filename"
    stage = "name"

    max_length: int = 255
    allow_hidden: bool = False
    require_extension: bool = True
    forbidden_extensions: frozenset[str] = DANGEROUS_EXTENSIONS
    forbidden_names: frozenset[str] = DANGEROUS_NAMES
    allow_leading_hyphen: bool = False
    allow_consecutive_dots: bool = False
    allow_short_names: bool = False

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        name = file.name
        if not name.strip():
            yield self.violation(Code.FILENAME_INVALID, "The file has no name.")
            return
        reported: set[tuple[str, str]] = set()
        for variant, how in name_variants(name):
            for found in self._name_rules(variant, how):
                key = (str(found.code), found.message)
                if key in reported:
                    continue
                reported.add(key)
                details = (
                    dict(found.details) if how == "raw" else {**found.details, "read_as": variant}
                )
                yield self.violation(found.code, found.message, **details)
        if len(name.encode("utf-8", "surrogatepass")) > self.max_length:
            yield self.violation(
                Code.FILENAME_TOO_LONG,
                f"The file name is too long (maximum {self.max_length} bytes).",
                limit=self.max_length,
            )
        if self.require_extension and not file.extensions:
            yield self.violation(Code.FILENAME_MISSING_EXTENSION, "The file name has no extension.")

    def _name_rules(self, name: str, how: str) -> Iterator[Violation]:
        if any(_is_forbidden_char(c) for c in name):
            yield self.violation(
                Code.FILENAME_INVALID, "The file name contains invalid characters."
            )
        if name != name.rstrip(". "):
            yield self.violation(
                Code.FILENAME_INVALID, "The file name must not end with a dot or space."
            )
        if name[:1].isspace() or (name.startswith("-") and not self.allow_leading_hyphen):
            yield self.violation(
                Code.FILENAME_INVALID, "The file name must not start with a hyphen or space."
            )
        # NFKC turns the ellipsis "…" into "...": harmless on its own, so only the
        # name as sent (or percent-decoded) counts here.
        if not self.allow_consecutive_dots and how != "normalized" and ".." in name.strip("."):
            yield self.violation(
                Code.FILENAME_INVALID, "The file name must not contain consecutive dots."
            )
        lowered = name.lower()
        if lowered in self.forbidden_names:
            yield self.violation(Code.FILENAME_RESERVED, "This file name is not allowed.")
        elif name.startswith(".") and not self.allow_hidden:
            yield self.violation(Code.FILENAME_HIDDEN, "Hidden files are not allowed.")
        if lowered in {".", ".."} or lowered.split(".", 1)[0].strip() in _WINDOWS_RESERVED:
            yield self.violation(Code.FILENAME_RESERVED, "This file name is reserved.")
        if not self.allow_short_names and _SHORT_NAME.match(name):
            yield self.violation(
                Code.FILENAME_RESERVED, "The file name looks like a Windows short (8.3) name."
            )
        if dangerous := sorted(set(self._segments(lowered)) & self.forbidden_extensions):
            yield self.violation(
                Code.FILENAME_DANGEROUS_EXTENSION,
                "The file name contains a forbidden extension.",
                extensions=dangerous,
            )

    @staticmethod
    def _segments(lowered_name: str) -> Iterator[str]:
        return extension_segments(lowered_name)


def extension_segments(lowered_name: str) -> Iterator[str]:
    """Every dot-separated segment after the first, as a server would read it.

    ``"a.asp;.jpg"`` yields ``"asp"`` (IIS ``;``), ``"a.asp::$data"`` yields ``"asp"``
    (NTFS streams), and ``"a.php .jpg"`` yields ``"php"``.
    """
    for segment in lowered_name.lstrip(".").split(".")[1:]:
        yield _SEGMENT_TERMINATORS.split(segment, maxsplit=1)[0]


def normalize_allowed_types(entries: Iterable[str | FileType]) -> frozenset[str]:
    """Canonicalise MIME types/aliases and validate wildcards; unknown types raise."""
    normalized: set[str] = set()
    for entry in entries:
        if isinstance(entry, FileType):
            normalized.add(entry.mime)
            continue
        value = normalize_mime(entry)
        if value.endswith("/*"):
            category = value[:-2]
            if not any(t.category == category for t in all_types()):
                raise ValueError(f"Unknown media category in wildcard {entry!r}")
            normalized.add(value)
        else:
            normalized.add(resolve_mime(value).mime)
    return frozenset(normalized)


@dataclass(frozen=True, slots=True)
class AllowedTypes(Check):
    """Allow only files whose *content* is one of ``types``.

    Entries are MIME types (aliases are resolved, unknown types raise) or wildcards
    such as ``"image/*"``.  Wildcards never match executables, script-capable formats
    (HTML, SVG, XML) or archives no check can open (7-Zip, RAR): those must be listed
    explicitly.
    """

    _deconstruct_module = _PUBLIC
    name = "type"
    stage = "type"

    types: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "types", normalize_allowed_types(self.types))

    def allows(self, file_type: FileType) -> bool:
        if file_type.mime in self.types:
            return True
        if file_type.executable or file_type.mime in _SCRIPTABLE | UNINSPECTED_ARCHIVES:
            return False
        return f"{file_type.category}/*" in self.types

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        file_type = file.file_type
        if file_type is None:
            yield self.violation(
                Code.TYPE_UNKNOWN,
                "The file type could not be identified.",
                declared_type=file.declared_type,
                extension=file.extension,
            )
        elif not self.allows(file_type):
            yield self.violation(
                Code.TYPE_NOT_ALLOWED,
                f"{file_type.label} files are not allowed.",
                detected_type=file_type.mime,
                declared_type=file.declared_type,
            )


@dataclass(frozen=True, slots=True)
class ExtensionMatchesType(Check):
    """The final extension must be one that belongs to the detected type.

    This stops content from being stored under a name that makes servers or browsers
    interpret it differently (an image named ``.html``, a script named ``.png``).
    """

    _deconstruct_module = _PUBLIC
    name = "extension"
    stage = "type"

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and bool(file.extension)

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        file_type = file.file_type
        if file_type is not None and file.extension not in file_type.extensions:
            yield self.violation(
                Code.EXTENSION_MISMATCH,
                f"The file extension '{file.extension}' does not match its content "
                f"({file_type.label}).",
                extension=file.extension,
                detected_type=file_type.mime,
                expected=list(file_type.extensions),
            )


@dataclass(frozen=True, slots=True)
class DeclaredTypeMatches(Check):
    """The client's ``Content-Type`` must agree with the detected type.

    Off by default: browsers derive this header from the OS (Windows labels CSV
    ``application/vnd.ms-excel``), so it causes false positives without adding
    protection beyond content detection.
    """

    _deconstruct_module = _PUBLIC
    name = "declared_type"
    stage = "type"

    ignored: frozenset[str] = frozenset({"application/octet-stream", "binary/octet-stream"})

    def applies(self, file: InspectedFile) -> bool:
        declared = normalize_mime(file.declared_type or "")
        return file.file_type is not None and bool(declared) and declared not in self.ignored

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        file_type = file.file_type
        declared = file.declared_type or ""
        if file_type is None or file_type.matches(declared):
            return
        parent = get_type(file_type.parent) if file_type.parent else None
        if parent is not None and parent.matches(declared):
            return
        yield self.violation(
            Code.DECLARED_TYPE_MISMATCH,
            "The declared content type does not match the file's content.",
            declared_type=declared,
            detected_type=file_type.mime,
        )
