"""Responses for rejected uploads."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib import messages
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import resolve_url
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils.translation import gettext as _

from uploadshield import web

from .conf import get_config
from .service import message_for

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest

    from .service import UploadValidation

__all__ = ["redirect_with_messages", "reject", "rejection_payload", "status_code_for"]

TEMPLATE_NAME = "uploadshield/rejected.html"


def status_code_for(validation: UploadValidation) -> int:
    """413 if every problem is size, 415 if every problem is the type, else 400."""
    return web.status_code_for(o.result for o in validation.rejected)


def rejection_payload(
    validation: UploadValidation, *, include_details: bool = False
) -> dict[str, Any]:
    """A JSON-serialisable description of the rejected files."""
    return web.rejection_payload(
        (o.result for o in validation.rejected),
        include_details=include_details,
        messages=get_config().messages,
        message=_("The upload was rejected."),
        fields=[o.field for o in validation.rejected],
    )


def _wants_json(request: HttpRequest) -> bool:
    return web.wants_json(request.headers.get("Accept"), request.headers.get("X-Requested-With"))


def reject(request: HttpRequest, validation: UploadValidation) -> HttpResponse:
    """Default ``REJECTION_HANDLER``: JSON for API clients, HTML otherwise.

    The HTML uses the overridable template ``uploadshield/rejected.html``.
    Diagnostics are only included when ``EXPOSE_DETAILS`` is enabled.
    """
    payload = rejection_payload(validation, include_details=get_config().expose_details)
    status = status_code_for(validation)
    if _wants_json(request):
        return JsonResponse(payload, status=status)
    try:
        body = render_to_string(TEMPLATE_NAME, {"rejection": payload}, request=request)
    except TemplateDoesNotExist:
        body = web.html_rejection(payload)
    return HttpResponse(body, status=status)


def redirect_with_messages(
    to: str, *, fallback_message: str | None = None
) -> Callable[[HttpRequest, UploadValidation], HttpResponse]:
    """Build a handler that redirects (URL name or path) and flashes each error.

    Ideal for classic form views::

        @validate_uploads("images", on_reject=redirect_with_messages("gallery"))
    """

    def handler(request: HttpRequest, validation: UploadValidation) -> HttpResponse:
        config = get_config()
        flashed = False
        for outcome in validation.rejected:
            for violation in outcome.result.violations:
                text = f"{outcome.result.name}: {message_for(violation, config)}"
                messages.error(request, text, fail_silently=True)
                flashed = True
        if not flashed and fallback_message:
            messages.error(request, fallback_message, fail_silently=True)
        return HttpResponseRedirect(resolve_url(to))

    return handler
