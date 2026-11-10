"""A minimal single-file Django upload app protected by uploadshield.

Run:  uv run python examples/django_app.py runserver 8813                      (WSGI)
      uv run --with uvicorn uvicorn examples.django_app:application --port 8813  (ASGI)
"""

from __future__ import annotations

import hashlib
import sys

import django
from django import forms
from django.conf import settings
from django.core.asgi import get_asgi_application
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.template import engines
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from uploadshield import MB
from uploadshield.django import validate_uploads

SETTINGS = {
    "DEBUG": False,
    "SECRET_KEY": "example-only-not-secret",
    "ALLOWED_HOSTS": ["127.0.0.1", "localhost", "testserver"],
    "ROOT_URLCONF": __name__,
    "INSTALLED_APPS": ["uploadshield.django"],  # system checks + rejection template
    "MIDDLEWARE": ["django.middleware.csrf.CsrfViewMiddleware"],
    "TEMPLATES": [{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True}],
    # Validates every file while Django parses the body (views, forms, admin, DRF):
    # names and types as the data streams in, the full policy once a file is complete.
    "FILE_UPLOAD_HANDLERS": ["uploadshield.django.handlers.ValidatingUploadHandler"],
    "UPLOADSHIELD": {
        "MODE": "enforce",
        "DEFAULT_POLICY": "default",  # every multipart request without a decorator
        "MAX_UPLOAD_SIZE": 100 * MB,  # aborts bigger uploads mid-stream, on every view
    },
}
if not settings.configured:  # the test-suite brings its own settings
    settings.configure(**SETTINGS)
    django.setup()


def summary(request: HttpRequest) -> JsonResponse:
    files = []
    for field in request.FILES:
        for upload in request.FILES.getlist(field):
            data = upload.read()
            files.append(
                {
                    "field": field,
                    "name": upload.name,
                    "content_type": upload.content_type,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    return JsonResponse({"files": files})


@csrf_exempt  # API endpoints; the HTML form below keeps CSRF protection
@validate_uploads("documents")
def documents(request: HttpRequest) -> JsonResponse:
    return summary(request)


@csrf_exempt
@validate_uploads("sanitized_images")  # re-encoded, metadata stripped, random name
def avatar(request: HttpRequest) -> JsonResponse:
    return summary(request)


@csrf_exempt
@validate_uploads("images")
def gallery(request: HttpRequest) -> JsonResponse:  # several files in the field "files"
    return summary(request)


@csrf_exempt
def legacy(request: HttpRequest) -> JsonResponse:  # no decorator: the upload handler's default
    return summary(request)


class ProfileForm(forms.Form):
    nickname = forms.CharField(max_length=50)
    picture = forms.FileField()  # any file field reports refusals inline


PAGE = """<!doctype html>
<title>Profile</title>
<form method="post" enctype="multipart/form-data">
  {% csrf_token %}{{ form.as_p }}
  <button>Upload</button>
</form>
"""


@validate_uploads("sanitized_images", on_reject="field")  # errors appear next to the field
def profile(request: HttpRequest) -> HttpResponse:
    form = ProfileForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        return summary(request)  # request.FILES holds the re-encoded picture
    return HttpResponse(engines["django"].from_string(PAGE).render({"form": form}, request))


urlpatterns = [
    path("documents", documents),
    path("avatar", avatar),
    path("gallery", gallery),
    path("legacy", legacy),
    path("profile", profile),
]
handler400 = "uploadshield.django.views.bad_request"  # 413/415/400 as JSON or HTML

application = get_asgi_application()

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
