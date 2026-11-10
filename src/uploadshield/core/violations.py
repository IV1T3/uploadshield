"""Structured reasons why a file was rejected."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["CWE", "Code", "CweRef", "Violation", "cwe_for"]


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

    def as_dict(
        self, *, include_details: bool = False, include_cwe: bool = False
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"code": str(self.code), "message": self.message}
        if include_details:
            data["check"] = self.check
            data["details"] = dict(self.details)
        # CWE is gated separately from details: it belongs in logs, signals and the CLI,
        # never in the client response, even when EXPOSE_DETAILS puts details there.
        if include_cwe:
            data["cwe"] = [{"id": ref.id, "name": ref.name} for ref in cwe_for(self.code)]
        return data


@dataclass(frozen=True, slots=True)
class CweRef:
    """A Common Weakness Enumeration entry a violation code corresponds to."""

    id: str  # e.g. "CWE-434"
    name: str  # e.g. "Unrestricted Upload of File with Dangerous Type"


# A function/variable reused across codes, so each is written once and shared.
_UNRESTRICTED_UPLOAD = CweRef("CWE-434", "Unrestricted Upload of File with Dangerous Type")
_PATH_TRAVERSAL = CweRef("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory")
_NAME_OR_EXTENSION = CweRef(
    "CWE-646", "Reliance on File Name or Extension of Externally-Supplied File"
)
_RESOURCE_CONSUMPTION = CweRef("CWE-400", "Uncontrolled Resource Consumption")
_COMPRESSED_DATA = CweRef(
    "CWE-409", "Improper Handling of Highly Compressed Data (Data Amplification)"
)
_DEVICE_NAMES = CweRef("CWE-67", "Improper Handling of Windows Device Names")
_SSRF = CweRef("CWE-918", "Server-Side Request Forgery (SSRF)")
_XSS = CweRef(
    "CWE-79", "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"
)
_XXE = CweRef("CWE-611", "Improper Restriction of XML External Entity Reference")
_ENTITY_EXPANSION = CweRef(
    "CWE-776", "Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)"
)
_CODE_INJECTION = CweRef("CWE-94", "Improper Control of Generation of Code (Code Injection)")
_MALICIOUS_CODE = CweRef("CWE-506", "Embedded Malicious Code")

#: Each built-in :class:`Code` and the CWE weakness(es) it corresponds to.  Codes whose
#: cause has no accurate CWE - operational failures ("cannot inspect", scanner down) or
#: ones too generic to be useful - map to an empty tuple deliberately, not by omission.
#: This is surfaced only where diagnostics already are (logs, signals, the CLI), never in
#: the client response.  A custom check's own code has no entry; :func:`cwe_for` yields ().
CWE: dict[Code, tuple[CweRef, ...]] = {
    Code.FILE_EMPTY: (),
    Code.FILE_TOO_LARGE: (_RESOURCE_CONSUMPTION,),
    Code.FILENAME_INVALID: (_PATH_TRAVERSAL,),
    Code.FILENAME_TOO_LONG: (),
    Code.FILENAME_HIDDEN: (),
    Code.FILENAME_RESERVED: (_DEVICE_NAMES,),
    Code.FILENAME_DANGEROUS_EXTENSION: (_UNRESTRICTED_UPLOAD,),
    Code.FILENAME_MISSING_EXTENSION: (),
    Code.TYPE_UNKNOWN: (),
    Code.TYPE_NOT_ALLOWED: (_UNRESTRICTED_UPLOAD,),
    Code.EXTENSION_MISMATCH: (_NAME_OR_EXTENSION, _UNRESTRICTED_UPLOAD),
    Code.CONTENT_MISMATCH: (_NAME_OR_EXTENSION, _UNRESTRICTED_UPLOAD),
    Code.DECLARED_TYPE_MISMATCH: (_NAME_OR_EXTENSION,),
    Code.IMAGE_CORRUPT: (),
    Code.IMAGE_TOO_LARGE: (_COMPRESSED_DATA,),
    Code.PDF_ACTIVE_CONTENT: (_UNRESTRICTED_UPLOAD,),
    Code.ARCHIVE_CORRUPT: (),
    Code.ARCHIVE_UNSAFE_PATH: (_PATH_TRAVERSAL,),
    Code.ARCHIVE_BOMB: (_COMPRESSED_DATA, _RESOURCE_CONSUMPTION),
    Code.ARCHIVE_ENCRYPTED: (),
    Code.ARCHIVE_DANGEROUS_MEMBER: (_UNRESTRICTED_UPLOAD,),
    Code.OFFICE_MACROS: (_UNRESTRICTED_UPLOAD,),
    Code.OFFICE_EXTERNAL_REFERENCE: (_SSRF,),
    Code.SVG_ACTIVE_CONTENT: (_XSS,),
    Code.XML_DTD: (_XXE, _ENTITY_EXPANSION),
    Code.EMBEDDED_CODE: (_UNRESTRICTED_UPLOAD, _CODE_INJECTION),
    Code.POLYGLOT: (_UNRESTRICTED_UPLOAD,),
    Code.MALWARE_DETECTED: (_MALICIOUS_CODE,),
    Code.SIGNATURE_MATCH: (_MALICIOUS_CODE,),
    Code.SCANNER_UNAVAILABLE: (),
    Code.SANITIZATION_FAILED: (),
    Code.CHECK_FAILED: (),
}


def cwe_for(code: str) -> tuple[CweRef, ...]:
    """The CWE weaknesses a violation ``code`` corresponds to (``()`` for a custom code)."""
    try:
        return CWE[Code(code)]
    except ValueError:  # not a built-in Code: a custom check's own string code
        return ()
