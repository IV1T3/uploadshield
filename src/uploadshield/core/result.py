"""The outcome of validating one file."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .types import FileType
    from .violations import Violation

__all__ = ["SanitizedFile", "ValidationResult"]


@dataclass(frozen=True, slots=True)
class SanitizedFile:
    """The sanitized replacement for an upload.

    ``data`` is ``None`` when only metadata (e.g. the name) changed and the original
    content can be kept as-is.
    """

    name: str
    content_type: str
    data: bytes | None
    applied: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationResult:
    name: str
    field: str | None
    size: int
    file_type: FileType | None
    declared_type: str | None
    violations: tuple[Violation, ...]
    checks_run: tuple[str, ...]
    sanitized: SanitizedFile | None = None

    @property
    def ok(self) -> bool:
        return not self.violations

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(str(v.code) for v in self.violations)

    def as_dict(
        self, *, include_details: bool = False, include_cwe: bool = False
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "field": self.field,
            "name": self.name,
            "ok": self.ok,
            "errors": [
                v.as_dict(include_details=include_details, include_cwe=include_cwe)
                for v in self.violations
            ],
        }
        if include_details:
            data |= {
                "size": self.size,
                "detected_type": self.file_type.mime if self.file_type else None,
                "declared_type": self.declared_type,
                "checks_run": list(self.checks_run),
                "sanitized": list(self.sanitized.applied) if self.sanitized else [],
            }
        return data
