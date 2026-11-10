"""Per-view configuration: ``@validate_uploads`` and ``@skip_upload_validation``."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping
from typing import Any, TypeVar, cast

from uploadshield.policy import Policy

from .core import SKIP, USE_DEFAULT, VIEW_ATTR, FileOutcome, ViewSpec, check_request

__all__ = ["skip_upload_validation", "validate_uploads"]

V = TypeVar("V", bound=Callable[..., Any])


def _apply(view: V, spec: ViewSpec) -> V:
    if inspect.iscoroutinefunction(view):

        @functools.wraps(view)
        async def async_view(*args: Any, **kwargs: Any) -> Any:
            check_request(spec)
            return await view(*args, **kwargs)

        wrapped: Callable[..., Any] = async_view
    else:

        @functools.wraps(view)
        def sync_view(*args: Any, **kwargs: Any) -> Any:
            check_request(spec)
            return view(*args, **kwargs)

        wrapped = sync_view
    setattr(wrapped, VIEW_ATTR, spec)
    return cast("V", wrapped)


def validate_uploads(
    policy: Any = USE_DEFAULT,
    /,
    *,
    fields: Mapping[str, Any] | None = None,
    mode: str | None = None,
    on_reject: Callable[[list[FileOutcome]], Any] | None = None,
) -> Any:
    """Validate the files uploaded to a Flask view.

    ``policy`` is a :class:`~uploadshield.Policy`, a name from
    ``UPLOADSHIELD["POLICIES"]``/the presets, or a dotted path; ``fields`` overrides it
    per form field (``None`` skips a field).  ``on_reject`` receives the refused
    outcomes and returns a response (e.g. ``flash()`` + ``redirect()``).  Works with or
    without the extension's request hook::

        @app.post("/avatar")
        @validate_uploads("sanitized_images")
        def avatar(): ...
    """
    if callable(policy) and not isinstance(policy, Policy):  # bare ``@validate_uploads``
        return _apply(policy, ViewSpec())
    spec = ViewSpec(policy=policy, fields=fields or {}, mode=mode, on_reject=on_reject)
    return functools.partial(_apply, spec=spec)


def skip_upload_validation(view: V) -> V:
    """Exempt a view from the extension's request hook."""
    setattr(view, VIEW_ATTR, SKIP)
    return view
