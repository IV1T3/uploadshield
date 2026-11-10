"""Error views.

Point Django's ``handler400`` at :func:`bad_request` in your root URLconf::

    handler400 = "uploadshield.django.views.bad_request"

Rejected uploads then get 413/415/400 responses with a JSON or HTML body (or a view's
own ``on_reject`` handler); every other bad request falls through to Django's default.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.views import defaults

from .conf import get_config
from .exceptions import UploadRejected
from .service import get_view_spec

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

__all__ = ["bad_request"]


def bad_request(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    if not isinstance(exception, UploadRejected):
        return defaults.bad_request(request, exception)  # ty: ignore[invalid-argument-type]
    match = getattr(request, "resolver_match", None)
    spec = get_view_spec(match.func, request.method) if match is not None else None
    on_reject = spec.on_reject if spec is not None else None
    if on_reject is not None and not isinstance(on_reject, str):
        response = on_reject(request, exception.validation)
    else:
        response = get_config().rejection_handler(request, exception.validation)
    # The rejection was already logged with full details on the "uploadshield"
    # logger; this stops Django from logging it again with a traceback.
    setattr(response, "_has_been_logged", True)  # noqa: B010 - private Django flag
    return response
