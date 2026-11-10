"""Per-view configuration: ``@validate_uploads`` and ``@skip_upload_validation``."""

from __future__ import annotations

import functools
import inspect
import sys
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeVar, cast, overload

from asgiref.sync import sync_to_async
from django.views import View

from .service import SKIP, USE_DEFAULT, VIEW_ATTR, ViewSpec, rejection_response, validate_request

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

    from .conf import PolicyRef
    from .handlers import ValidatingUploadHandler
    from .service import UploadValidation

__all__ = ["skip_upload_validation", "validate_uploads"]

if sys.version_info >= (3, 12):
    from inspect import iscoroutinefunction
else:  # asgiref also recognises markcoroutinefunction() on Python 3.11
    from asgiref.sync import iscoroutinefunction

V = TypeVar("V", bound=Callable[..., Any])
RejectHandler = Callable[["HttpRequest", "UploadValidation"], "HttpResponse"]


class ViewDecorator(Protocol):
    """What ``validate_uploads(...)`` returns: preserves the decorated view's type."""

    def __call__(self, view: V, /) -> V: ...


def _check(request: HttpRequest, spec: ViewSpec) -> HttpResponse | None:
    """Validate the request unless ``ValidatingUploadHandler`` will -> rejection or None.

    With the handler installed nothing needs to happen up front: it reads this view's
    spec and validates whenever the body is parsed (by the view, a form or DRF).  A
    multipart POST that was already parsed (before routing), or that Django will parse
    without the handler, is validated here.  Any other body without the handler (DRF's
    PUT/PATCH and raw file uploads, which Django never parses) gets a handler for this
    request, so it is validated while whatever parser reads it.
    """
    if spec.mode == "off":
        return None
    # DRF's Request (``@api_view``) wraps the HttpRequest; its own ``_files`` says nothing
    # about whether Django parsed the body.
    request = getattr(request, "_request", request)
    parsed = hasattr(request, "_files")
    handler = _installed_handler(request)
    if handler is not None and not parsed:
        # Routing may not see this decorator (DRF, method_decorator): tell the handler.
        handler.use_spec(spec)
    if request.method == "POST" and request.content_type == "multipart/form-data":
        if parsed or handler is None:
            return rejection_response(request, validate_request(request, spec), spec)
    elif not parsed and handler is None:
        _install_handler(request, spec)
    return None


def _installed_handler(request: HttpRequest) -> ValidatingUploadHandler | None:
    from .handlers import ValidatingUploadHandler

    for handler in request.upload_handlers:
        if isinstance(handler, ValidatingUploadHandler):
            return handler
    return None


def _install_handler(request: HttpRequest, spec: ViewSpec) -> None:
    from .handlers import ValidatingUploadHandler

    inner = list(request.upload_handlers)
    request.upload_handlers = [ValidatingUploadHandler(request, inner=inner, spec=spec)]


async def _acheck(request: HttpRequest, spec: ViewSpec) -> HttpResponse | None:
    # Parsing the body and running checks is blocking work: keep it off the event loop.
    return await sync_to_async(_check)(request, spec)


def _wrap_function(view: Callable[..., Any], spec: ViewSpec) -> Callable[..., Any]:
    if iscoroutinefunction(view):  # ty: ignore[deprecated] - asgiref branch on 3.11

        @functools.wraps(view)
        async def async_view(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if (response := await _acheck(request, spec)) is not None:
                return response
            return await view(request, *args, **kwargs)

        wrapped: Callable[..., Any] = async_view
    else:

        @functools.wraps(view)
        def sync_view(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if (response := _check(request, spec)) is not None:
                return response
            return view(request, *args, **kwargs)

        wrapped = sync_view
    setattr(wrapped, VIEW_ATTR, spec)
    return wrapped


def _wrap_class(cls: type[View], spec: ViewSpec) -> type[View]:
    dispatch = cls.dispatch
    try:
        is_async = bool(cls.view_is_async)
    except Exception:
        is_async = False

    if is_async:

        @functools.wraps(dispatch)
        async def async_dispatch(self: Any, request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if (response := await _acheck(request, spec)) is not None:
                return response
            # View.dispatch returns the handler's coroutine for async views.
            response = dispatch(self, request, *args, **kwargs)
            return await response if inspect.isawaitable(response) else response

        cls.dispatch = async_dispatch  # ty: ignore[invalid-assignment]
    else:

        @functools.wraps(dispatch)
        def sync_dispatch(self: Any, request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if (response := _check(request, spec)) is not None:
                return response
            return dispatch(self, request, *args, **kwargs)

        cls.dispatch = sync_dispatch  # ty: ignore[invalid-assignment]
    setattr(cls, VIEW_ATTR, spec)
    return cls


def _apply(view: V, spec: ViewSpec) -> V:
    if isinstance(view, type):
        if not issubclass(view, View):
            raise TypeError(f"{view.__name__} is not a Django class-based view")
        return cast("V", _wrap_class(view, spec))
    return cast("V", _wrap_function(view, spec))


@overload
def validate_uploads(policy: V, /) -> V: ...
@overload
def validate_uploads(
    policy: PolicyRef | None = ...,
    /,
    *,
    fields: Mapping[str, PolicyRef | None] | None = ...,
    mode: str | None = ...,
    on_reject: RejectHandler | Literal["reject", "field"] | None = ...,
) -> ViewDecorator: ...
def validate_uploads(
    policy: Any = USE_DEFAULT,
    /,
    *,
    fields: Mapping[str, PolicyRef | None] | None = None,
    mode: str | None = None,
    on_reject: RejectHandler | Literal["reject", "field"] | None = None,
) -> Any:
    """Validate the files uploaded to a view (function or class-based, sync or async).

    ``policy`` is a :class:`~uploadshield.Policy`, a name from
    ``UPLOADSHIELD["POLICIES"]``/the presets, or a dotted path; ``fields``
    overrides it per form field (``None`` skips a field).  ``mode`` overrides the
    global ``MODE``.  ``on_reject`` decides what a refusal looks like:

    * ``"reject"`` (default ``ON_REJECT``): the request is answered with 400/413/415;
    * ``"field"``: the file is replaced by an empty placeholder and the view runs, so
      the form reports the error next to the field;
    * a callable ``(request, validation) -> HttpResponse``, e.g.
      :func:`~uploadshield.django.redirect_with_messages`.

    ``ValidatingUploadHandler`` reads these settings while the body streams in.  Without
    the handler, the decorator validates ``request.FILES`` itself before calling the
    view, so it also works on its own.

    ::

        @validate_uploads("images")
        def avatar(request): ...

        @validate_uploads(fields={"cv": "pdf", "photo": "sanitized_images"})
        class ApplicationView(FormView): ...
    """
    if callable(policy):  # bare ``@validate_uploads``
        return _apply(policy, ViewSpec())
    spec = ViewSpec(policy=policy, fields=fields or {}, mode=mode, on_reject=on_reject)
    return functools.partial(_apply, spec=spec)


def skip_upload_validation(view: V) -> V:
    """Exempt a view from upload validation (like ``csrf_exempt``)."""
    setattr(view, VIEW_ATTR, SKIP)
    return view
