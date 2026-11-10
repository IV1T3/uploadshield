"""Policies: declarative, immutable descriptions of what an upload may be."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .checks import (
    DEFAULT_CONTENT_CHECKS,
    AllowedTypes,
    Check,
    DeclaredTypeMatches,
    ExtensionMatchesType,
    FilenameCheck,
    FileSize,
)
from .checks.basic import normalize_allowed_types
from .core._deconstruct import Deconstructible
from .core.check import Sanitizer
from .core.sniffing import BuiltinSniffer, Sniffer
from .core.types import MB, FileType, get_type

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable

__all__ = ["Policy"]


@dataclass(frozen=True, kw_only=True)
class Policy(Deconstructible):
    """What an upload must look like to be accepted, and how to sanitize it.

    The pipeline always runs in cost order and stops at the first failing check
    (``fail_fast``), so expensive parsers never see files that already failed
    basic checks:

    1. size, 2. filename, 3. content type allow-list, 4. extension/content agreement,
    5. (optional) declared ``Content-Type`` agreement, 6. format-specific
    ``content_checks``, 7. your additional ``checks`` (e.g. ClamAV, YARA).

    Policies are immutable and hashable; derive variants with :meth:`replace` and
    :meth:`extend`.
    """

    _deconstruct_module = "uploadshield"

    allowed_types: Collection[str | FileType]
    max_size: int | None = 10 * MB
    allow_empty: bool = False
    filename: FilenameCheck = FilenameCheck()
    match_extension: bool = True
    match_declared_type: bool = False
    content_checks: tuple[Check, ...] = DEFAULT_CONTENT_CHECKS
    checks: tuple[Check, ...] = ()
    sanitizers: tuple[Sanitizer, ...] = ()
    sniffer: Sniffer = BuiltinSniffer()
    fail_fast: bool = True
    name: str = ""

    pipeline: tuple[Check, ...] = field(init=False, repr=False, compare=False)
    _type_check: AllowedTypes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        type_check = AllowedTypes(normalize_allowed_types(_as_iterable(self.allowed_types)))
        set_ = object.__setattr__
        set_(self, "allowed_types", type_check.types)
        set_(self, "_type_check", type_check)
        set_(self, "content_checks", tuple(self.content_checks))
        set_(self, "checks", tuple(self.checks))
        set_(self, "sanitizers", tuple(self.sanitizers))
        if self.max_size is not None and self.max_size < 0:
            raise ValueError("max_size must be a positive number of bytes or None")
        for check in (*self.content_checks, *self.checks):
            if not isinstance(check, Check):
                raise TypeError(f"{check!r} is not a Check")
        for sanitizer in self.sanitizers:
            if not isinstance(sanitizer, Sanitizer):
                raise TypeError(f"{sanitizer!r} is not a Sanitizer")
        if not hasattr(self.sniffer, "sniff"):
            raise TypeError(f"{self.sniffer!r} is not a Sniffer")

        pipeline: list[Check] = [
            FileSize(max_bytes=self.max_size, allow_empty=self.allow_empty),
            self.filename,
            type_check,
        ]
        if self.match_extension:
            pipeline.append(ExtensionMatchesType())
        if self.match_declared_type:
            pipeline.append(DeclaredTypeMatches())
        pipeline += [*self.content_checks, *self.checks]
        set_(self, "pipeline", tuple(pipeline))

    # -- derivation -------------------------------------------------------------------

    def replace(self, **changes: Any) -> Policy:
        """A copy with some fields changed: ``IMAGES.replace(max_size=2 * MB)``."""
        return dataclasses.replace(self, **changes)

    def extend(
        self,
        *,
        allowed_types: Iterable[str | FileType] = (),
        checks: Iterable[Check] = (),
        sanitizers: Iterable[Sanitizer] = (),
        name: str | None = None,
    ) -> Policy:
        """A copy that additionally allows types and runs more checks/sanitizers."""
        return dataclasses.replace(
            self,
            allowed_types=self.types | normalize_allowed_types(allowed_types),
            checks=(*self.checks, *checks),
            sanitizers=(*self.sanitizers, *sanitizers),
            name=self.name if name is None else name,
        )

    @property
    def types(self) -> frozenset[str]:
        """The normalized allow-list (canonical MIME types and wildcards)."""
        return self._type_check.types

    def allows(self, file_type: FileType) -> bool:
        """Whether content of ``file_type`` passes the type allow-list."""
        return self._type_check.allows(file_type)

    def allows_mime(self, mime: str) -> bool:
        """Like :meth:`allows` for a MIME string; unknown types are never allowed."""
        file_type = get_type(mime)
        return file_type is not None and self.allows(file_type)


def _as_iterable(value: Iterable[str | FileType] | str | FileType) -> Iterable[str | FileType]:
    # Guard against Policy(allowed_types="image/png"), which would iterate characters.
    if isinstance(value, (str, FileType)):
        return (value,)
    return value
