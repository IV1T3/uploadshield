"""Views exercising every integration style."""

from __future__ import annotations

import hashlib

from django import forms
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt

from uploadshield.django import (
    ValidatedFileField,
    get_upload_validation,
    redirect_with_messages,
    skip_upload_validation,
    validate_uploads,
)

from .models import Document


def describe(request: HttpRequest) -> JsonResponse:
    files = []
    for field in request.FILES:
        for f in request.FILES.getlist(field):
            data = f.read()
            files.append(
                {
                    "field": field,
                    "name": f.name,
                    "content_type": f.content_type,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    validation = get_upload_validation(request)
    return JsonResponse(
        {
            "files": files,
            "post": {k: request.POST.getlist(k) for k in request.POST},
            "validated": validation is not None,
            "rejected": len(validation.rejected) if validation else 0,
        }
    )


def plain(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("images")
def images(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("sanitized_images")
def avatar(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads(fields={"doc": "pdf", "photo": "images", "notes": None})
def multi(request: HttpRequest) -> JsonResponse:
    return describe(request)


@skip_upload_validation
def raw(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("images", mode="report")
def report(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("images", on_reject=redirect_with_messages("/done/"))
def redirecting(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads
def bare(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("tiny_images")
def tiny(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("images")
async def async_images(request: HttpRequest) -> JsonResponse:
    return describe(request)


@validate_uploads("pdf")
class PdfView(View):
    def post(self, request: HttpRequest) -> JsonResponse:
        return describe(request)


@validate_uploads("images")
class AsyncImageView(View):
    async def post(self, request: HttpRequest) -> JsonResponse:
        return describe(request)


class AvatarForm(forms.Form):
    picture = ValidatedFileField(policy="sanitized_images")


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "file"]


@skip_upload_validation
def form_view(request: HttpRequest) -> HttpResponse:
    form = AvatarForm(request.POST, request.FILES)
    if not form.is_valid():
        return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
    picture = form.cleaned_data["picture"]
    data = picture.read()
    return JsonResponse(
        {"name": picture.name, "content_type": picture.content_type, "size": len(data)}
    )


@skip_upload_validation
def model_form_view(request: HttpRequest) -> HttpResponse:
    form = DocumentForm(request.POST, request.FILES)
    if not form.is_valid():
        return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
    return JsonResponse({"ok": True})


def done(request: HttpRequest) -> HttpResponse:
    from django.contrib.messages import get_messages

    return JsonResponse({"messages": [str(m) for m in get_messages(request)]})


@csrf_exempt
@never_cache
@validate_uploads("pdf")
def stacked(request: HttpRequest) -> JsonResponse:
    """Our decorator combined with Django's own (type-checked by ty)."""
    return describe(request)


class PlainUploadForm(forms.Form):
    file = forms.FileField()


@validate_uploads("pdf", on_reject="field")
def field_mode(request: HttpRequest) -> JsonResponse:
    """A form view that reports refused files next to the field."""
    form = PlainUploadForm(request.POST, request.FILES)
    raw = request.FILES.get("file")
    return JsonResponse(
        {
            "valid": form.is_valid(),
            "errors": form.errors.get_json_data(),
            "raw_type": type(raw).__name__,
            "raw_bytes": len(raw.read()) if raw is not None else None,
        }
    )


def kinds(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {field: [type(f).__name__ for f in request.FILES.getlist(field)] for field in request.FILES}
    )


@skip_upload_validation
def store(request: HttpRequest) -> JsonResponse:
    """Legacy code: writes uploads straight to default_storage."""
    from django.core.files.storage import default_storage

    saved = [default_storage.save(f.name, f) for f in request.FILES.getlist("file")]
    return JsonResponse({"saved": saved})


def suspicious(request: HttpRequest) -> HttpResponse:
    from django.core.exceptions import SuspiciousOperation

    raise SuspiciousOperation("not an upload problem")


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(validate_uploads("pdf"), name="post")
class MethodDecoratedView(View):
    """The decorator on a method: URL routing cannot see it, only the request can."""

    def post(self, request: HttpRequest) -> JsonResponse:
        return describe(request)


@method_decorator(validate_uploads("tests.django_site.testapp.policies.ZIPS"), name="post")
class CsrfProtectedZipView(View):
    """CSRF is enforced, so CsrfViewMiddleware parses the body before ``post`` runs."""

    def post(self, request: HttpRequest) -> JsonResponse:
        return describe(request)


def _teapot(request: HttpRequest, validation: object) -> HttpResponse:
    return HttpResponse("teapot", status=418)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(validate_uploads("pdf", on_reject=_teapot), name="post")
class MethodOnRejectView(View):
    def post(self, request: HttpRequest) -> JsonResponse:
        return describe(request)


@validate_uploads("pdf")
def rename_and_store(request: HttpRequest) -> JsonResponse:
    """Validates a PDF, then stores it under a name the client picks ("save as")."""
    from django.core.files.storage import default_storage

    f = request.FILES["file"]
    f.name = request.POST.get("filename", f.name)
    return JsonResponse({"saved": default_storage.save(f.name, f)})


def store_checked(request: HttpRequest) -> JsonResponse:
    """Like ``store`` but protected by the upload handler as well."""
    from django.core.files.storage import default_storage

    saved = [default_storage.save(f.name, f) for f in request.FILES.getlist("file")]
    return JsonResponse({"saved": saved})
