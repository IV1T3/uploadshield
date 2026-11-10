"""Built-in validation checks.

Every check is a small frozen dataclass: its fields are its configuration, ``applies``
decides whether it is relevant for a file, and ``run`` yields violations.  Write your
own by subclassing :class:`~uploadshield.core.check.Check`.
"""

from uploadshield.core.check import Check

from .archive import ArchiveSafety
from .basic import (
    DANGEROUS_EXTENSIONS,
    DANGEROUS_NAMES,
    UNINSPECTED_ARCHIVES,
    WINDOWS_RESERVED_NAMES,
    AllowedTypes,
    DeclaredTypeMatches,
    ExtensionMatchesType,
    FilenameCheck,
    FileSize,
)
from .image import ImageIntegrity
from .magika import DEFAULT_MAGIKA_FORBIDDEN, MAGIKA_EQUIVALENTS, MagikaCheck
from .markup import EmbeddedContent, SvgActiveContent
from .office import OfficeMacros
from .pdf import DEFAULT_PDF_KEYWORDS, PdfActiveContent
from .scanners import ClamAV, YaraRules
from .xml import XmlSafety

__all__ = [
    "DANGEROUS_EXTENSIONS",
    "DANGEROUS_NAMES",
    "DEFAULT_CONTENT_CHECKS",
    "DEFAULT_MAGIKA_FORBIDDEN",
    "DEFAULT_PDF_KEYWORDS",
    "MAGIKA_EQUIVALENTS",
    "UNINSPECTED_ARCHIVES",
    "WINDOWS_RESERVED_NAMES",
    "AllowedTypes",
    "ArchiveSafety",
    "Check",
    "ClamAV",
    "DeclaredTypeMatches",
    "EmbeddedContent",
    "ExtensionMatchesType",
    "FileSize",
    "FilenameCheck",
    "ImageIntegrity",
    "MagikaCheck",
    "OfficeMacros",
    "PdfActiveContent",
    "SvgActiveContent",
    "XmlSafety",
    "YaraRules",
]

#: Format-specific checks every policy runs by default.  Each one only applies to
#: the formats it understands, so the set is safe to run against any upload.
DEFAULT_CONTENT_CHECKS: tuple[Check, ...] = (
    ArchiveSafety(),
    OfficeMacros(),
    XmlSafety(),
    PdfActiveContent(),
    SvgActiveContent(),
    EmbeddedContent(),
    ImageIntegrity(),
)
