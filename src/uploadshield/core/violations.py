"""Structured reasons why a file was rejected."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["Code", "Violation"]


class Code(StrEnum):
    """Stable, machine-readable violation codes.

    Codes are part of the public API: clients, log pipelines and translations key on
    them.  Custom checks may use their own string codes.
    """

    FILE_EMPTY = "file_empty"
    FILE_TOO_LARGE = "file_too_large"
    FILENAME_INVALID = "filename_invalid"
    FILENAME_TOO_LONG = "filename_too_long"
    FILENAME_HIDDEN = "filename_hidden"
    FILENAME_RESERVED = "filename_reserved"
    FILENAME_DANGEROUS_EXTENSION = "filename_dangerous_extension"
    FILENAME_MISSING_EXTENSION = "filename_missing_extension"
    TYPE_UNKNOWN = "type_unknown"
    TYPE_NOT_ALLOWED = "type_not_allowed"
    EXTENSION_MISMATCH = "extension_mismatch"
    CONTENT_MISMATCH = "content_mismatch"
    DECLARED_TYPE_MISMATCH = "declared_type_mismatch"
    IMAGE_CORRUPT = "image_corrupt"
    IMAGE_TOO_LARGE = "image_too_large"
    PDF_ACTIVE_CONTENT = "pdf_active_content"
    ARCHIVE_CORRUPT = "archive_corrupt"
    ARCHIVE_UNSAFE_PATH = "archive_unsafe_path"
    ARCHIVE_BOMB = "archive_bomb"
    ARCHIVE_ENCRYPTED = "archive_encrypted"
    ARCHIVE_DANGEROUS_MEMBER = "archive_dangerous_member"
    OFFICE_MACROS = "office_macros"
    OFFICE_EXTERNAL_REFERENCE = "office_external_reference"
    SVG_ACTIVE_CONTENT = "svg_active_content"
    XML_DTD = "xml_dtd"
    EMBEDDED_CODE = "embedded_code"
    POLYGLOT = "polyglot"
    MALWARE_DETECTED = "malware_detected"
    SIGNATURE_MATCH = "signature_match"
    SCANNER_UNAVAILABLE = "scanner_unavailable"
    SANITIZATION_FAILED = "sanitization_failed"
    CHECK_FAILED = "check_failed"


@dataclass(frozen=True, slots=True)
class Violation:
    """One reason a file failed validation.

    ``message`` is a short English sentence that is safe to show to the uploader.
    ``details`` carries diagnostics (detected type, matched signatures, ...) that are
    meant for logs and must not be exposed to clients by default.
    """

    code: str
    message: str
    check: str = ""
    details: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def as_dict(self, *, include_details: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {"code": str(self.code), "message": self.message}
        if include_details:
            data["check"] = self.check
            data["details"] = dict(self.details)
        return data
