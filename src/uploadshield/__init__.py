"""Content-aware validation and sanitization of file uploads.

The framework-agnostic engine lives here; Django integration lives in
:mod:`uploadshield.django`.

>>> from uploadshield import Policy, Upload, validate, MB
>>> policy = Policy(allowed_types={"image/png"}, max_size=1 * MB)
>>> result = validate(Upload.from_bytes(b"hello", "notes.png"), policy)
>>> result.ok, result.codes
(False, ('type_not_allowed',))
"""

from . import checks, presets, sanitizers
from .core.result import SanitizedFile, ValidationResult
from .core.sniffing import BuiltinSniffer, ChainedSniffer, MagicSniffer, Sniffer
from .core.types import GB, KB, MB, FileType, GiB, KiB, MiB, get_type, register_type
from .core.upload import InspectedFile, Upload
from .core.violations import Code, Violation
from .engine import validate
from .policy import Policy

__version__ = "2.0.0"

__all__ = [
    "GB",
    "KB",
    "MB",
    "BuiltinSniffer",
    "ChainedSniffer",
    "Code",
    "FileType",
    "GiB",
    "InspectedFile",
    "KiB",
    "MagicSniffer",
    "MiB",
    "Policy",
    "SanitizedFile",
    "Sniffer",
    "Upload",
    "ValidationResult",
    "Violation",
    "checks",
    "get_type",
    "presets",
    "register_type",
    "sanitizers",
    "validate",
]
