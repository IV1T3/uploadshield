"""Minimal Django settings for the library's own test-suite."""

import importlib.util

from uploadshield import MB, Policy, presets

SECRET_KEY = "tests-only-not-secret"
DEBUG = False
ALLOWED_HOSTS = ["testserver"]
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
ROOT_URLCONF = "tests.django_site.urls"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "uploadshield.django",
    "tests.django_site.testapp",
    *(["rest_framework"] if importlib.util.find_spec("rest_framework") else []),
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

# The global safety net: every parser (forms, admin, DRF) stores files through it.
FILE_UPLOAD_HANDLERS = ["uploadshield.django.handlers.ValidatingUploadHandler"]
#: Django's defaults, i.e. "the library's handler is not installed".
DJANGO_UPLOAD_HANDLERS = [
    "django.core.files.uploadhandler.MemoryFileUploadHandler",
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

UPLOADSHIELD = {
    "POLICIES": {
        "tiny_images": presets.IMAGES.replace(name="tiny_images", max_size=2_000),
        "text": Policy(name="text", allowed_types={"text/plain", "text/csv"}, max_size=1 * MB),
    },
    "VIEW_POLICIES": {"legacy-*": "pdf", "unprotected-*": None},
}
