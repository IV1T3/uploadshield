"""Support for Django's migration serializer without importing Django.

Django serialises model-field validators into migration files by calling
``deconstruct()`` on them.  Policies and checks are frozen dataclasses, so their
constructor arguments are exactly their fields; emitting the non-default ones keeps
migrations short and stable.
"""

from __future__ import annotations

import dataclasses
from typing import Any

__all__ = ["Deconstructible"]


class Deconstructible:
    """Mixin for frozen dataclasses: ``deconstruct() -> (path, args, kwargs)``."""

    __slots__ = ()

    #: Public import path prefix used in migrations instead of the private module.
    _deconstruct_module: str | None = None

    def deconstruct(self) -> tuple[str, tuple[Any, ...], dict[str, Any]]:
        if not dataclasses.is_dataclass(self):  # pragma: no cover - programming error
            raise TypeError(f"{type(self).__name__} must be a dataclass")
        kwargs: dict[str, Any] = {}
        for f in dataclasses.fields(self):
            if not f.init or not f.repr:
                continue
            value = getattr(self, f.name)
            if f.default is not dataclasses.MISSING and value == f.default:
                continue
            if f.default_factory is not dataclasses.MISSING and value == f.default_factory():
                continue
            kwargs[f.name] = value
        module = self._deconstruct_module or type(self).__module__
        return f"{module}.{type(self).__qualname__}", (), kwargs
