"""Extension points: validation checks and sanitizers."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from ._deconstruct import Deconstructible
from .violations import Violation

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .upload import InspectedFile

__all__ = ["Check", "Replacement", "Sanitizer", "Stage"]

#: What a check needs to see: the name only, the byte count, the first 8 KiB, or
#: the complete content.  Streaming integrations run the early stages while the
#: upload is still arriving.
Stage = Literal["name", "size", "type", "content"]


class _Component(Deconstructible):
    __slots__ = ()

    #: Short identifier used in violations, logs and ``checks_run``.
    name: ClassVar[str] = "component"
    #: Importable modules this component needs (e.g. ``("PIL",)``).
    requires: ClassVar[tuple[str, ...]] = ()
    #: The earliest point at which the component can run (see :data:`Stage`).
    stage: ClassVar[Stage] = "content"

    def applies(self, file: InspectedFile) -> bool:
        """Whether this component is relevant for ``file`` (e.g. only for PDFs)."""
        return True

    @classmethod
    def missing_dependencies(cls) -> tuple[str, ...]:
        return tuple(m for m in cls.requires if importlib.util.find_spec(m) is None)


class Check(_Component):
    """A single, focused validation rule.

    Subclasses are frozen dataclasses whose fields are the rule's parameters.  ``run``
    yields zero or more :class:`Violation` objects and must not modify the file.
    Exceptions raised by a check are treated as a failed verification (fail closed).
    """

    __slots__ = ()

    def run(self, file: InspectedFile) -> Iterable[Violation]:
        raise NotImplementedError

    def violation(self, code: str, message: str, **details: Any) -> Violation:
        return Violation(code=code, message=message, check=self.name, details=details)


@dataclass(frozen=True, slots=True)
class Replacement:
    """What a sanitizer changed. ``None`` fields are left as they were."""

    data: bytes | None = None
    name: str | None = None


class Sanitizer(_Component):
    """Transforms an already *validated* file into a safer equivalent.

    Examples: re-encoding images to drop metadata and trailing payloads, or replacing
    the client-chosen filename.  Sanitizers run only after every check has passed.
    """

    __slots__ = ()

    def sanitize(self, file: InspectedFile) -> Replacement:
        raise NotImplementedError
