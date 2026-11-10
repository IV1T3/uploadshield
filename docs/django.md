# Django

uploadshield protects Django on several layers: an **upload handler** that checks every
file while the request body streams in, **decorators** for per-view policies, **form
and model field validators**, and a **storage** wrapper that checks whatever is saved.
This page covers setup, every option, Django REST framework, refusals, observability
and testing.

Requirements: Django 4.2 or later. Install with `uv add "uploadshield[django,images]"`
(`images` adds Pillow for image decoding and re-encoding).

**On this page**

- [Quickstart](#quickstart)
- [The layers](#the-layers)
- [How the upload handler works](#how-the-upload-handler-works)
- [Choosing the policy for a request](#choosing-the-policy-for-a-request)
- [The validate_uploads decorator](#the-validate_uploads-decorator)
- [Django REST framework](#django-rest-framework)
- [Forms and model fields](#forms-and-model-fields)
- [Inline form errors: on_reject="field"](#inline-form-errors-on_rejectfield)
- [Storage: the last line of defense](#storage-the-last-line-of-defense)
- [Refusals](#refusals)
- [Modes and gradual adoption](#modes-and-gradual-adoption)
- [Observability](#observability)
- [Settings reference](#settings-reference)
- [System checks](#system-checks)
- [Testing your integration](#testing-your-integration)
- [Good to know](#good-to-know)
- [Troubleshooting](#troubleshooting)

## Quickstart

```python
# settings.py
INSTALLED_APPS += ["uploadshield.django"]  # system checks and the error template

# Every parser stores uploads through upload handlers: Django forms, the admin and
# DRF (POST, PUT, PATCH, raw file bodies) are all covered.
FILE_UPLOAD_HANDLERS = ["uploadshield.django.handlers.ValidatingUploadHandler"]

UPLOADSHIELD = {"MODE": "report"}  # observe first, then switch to "enforce"
```

```python
# urls.py (the root URLconf): answer refusals with 413/415/400 as JSON or HTML
handler400 = "uploadshield.django.views.bad_request"
```

Every uploaded file is now checked against the built-in `default` policy (common
images, PDF, Office and OpenDocument, text and CSV, audio, video; up to 50 MB) while it
streams in. In `report` mode nothing is blocked: would-be refusals are logged on the
`uploadshield` logger and sent as signals. Remove `"MODE": "report"` (the default is
`"enforce"`) to start refusing files.

Run `uv run python manage.py check` afterwards: the [system checks](#system-checks)
report configuration mistakes.

## The layers

| Layer | Configure | Validates | Use it for |
|---|---|---|---|
| `ValidatingUploadHandler` | `FILE_UPLOAD_HANDLERS` | every file any parser stores, while it streams | the project-wide safety net |
| `@validate_uploads` | on a view | the files of that view's requests | a stricter or different policy per view, per-field policies |
| `VIEW_POLICIES` | settings | views matched by URL name | third-party views you do not own (the admin, packages) |
| `FileValidator` / `ValidatedFileField` | on a model or form field | that field's file | precise inline errors, sanitized form values |
| `ValidatingStorage` | `STORAGES` | every file saved to storage | code paths outside requests: tasks, commands, imports |

You can use each layer on its own, but the handler plus storage cover everything; the
other layers refine *which* policy applies.

## How the upload handler works

`ValidatingUploadHandler` wraps Django's own handlers (memory and temporary files, or
whatever you list in [`UPLOAD_HANDLERS`](#settings-reference)) and checks each file in
stages:

| Stage | What is checked |
|---|---|
| A new file starts | The **name**, before a single byte is stored. A refused name never reaches the storage handlers. |
| Data arrives | The policy's **size** limit and the global hard cap [`MAX_UPLOAD_SIZE`](#settings-reference), as bytes arrive. Once the first **8 KiB** are in, the **type** sniffed from them is checked against the allow-list, so a disguised executable is refused without storing the rest. (ZIP and OLE2 containers are judged when complete.) |
| The file is complete | The **full policy**: content checks, scanners, sanitizers. The application receives the **sanitized** file with the detected content type. |

A refusal (in `enforce` mode) aborts the parse: temporary files are deleted and
`UploadRejected` is raised, which Django answers through
[`handler400`](#refusals). Originals that sanitizers replaced are closed straight
away.

`MAX_UPLOAD_SIZE` is a hard cap per file that applies to every view in every mode,
even `report`, `off` and views marked `@skip_upload_validation`, so oversized files
never fill your disk.

The handler only runs when something parses a request body. Django parses lazily
(when a view or form reads `request.POST` or `request.FILES`, or `CsrfViewMiddleware`
reads the CSRF token). To keep anonymous traffic from being parsed at all, put
`django.contrib.auth.middleware.LoginRequiredMiddleware` (Django 5.1+) **before**
`CsrfViewMiddleware` in `MIDDLEWARE`. It must come after `AuthenticationMiddleware`, so
move `AuthenticationMiddleware` above `CsrfViewMiddleware` too (Django's default order
has it below).

## Choosing the policy for a request

For each request, the first of these wins:

1. the view's `@validate_uploads(...)` or `@skip_upload_validation`;
2. the first [`VIEW_POLICIES`](#settings-reference) pattern matching the view's URL
   name;
3. [`DEFAULT_POLICY`](#settings-reference) (`"default"` unless you change it).

```python
UPLOADSHIELD = {
    "DEFAULT_POLICY": "documents",  # None: only views with a policy are checked
    "POLICIES": {"invoices": INVOICES},  # your policies, by name
    "VIEW_POLICIES": {  # globs on URL names
        "billing:*": "invoices",
        "admin:*": "documents",
        "webhooks:*": None,  # None: skip these views
    },
}
```

`VIEW_POLICIES` patterns are `fnmatch` globs, matched case-sensitively against
`request.resolver_match.view_name` (`"namespace:name"`), in the order written. They
let you protect views you cannot decorate, such as the admin or third-party apps,
without touching their code.

If something reads the body **before** URL routing (code in `MIDDLEWARE` that touches
`request.POST`), the handler resolves the URL itself, so the view's decorator and
`VIEW_POLICIES` still apply.

## The validate_uploads decorator

```python
from django.views.generic import FormView

from uploadshield.django import redirect_with_messages, skip_upload_validation, validate_uploads


@validate_uploads("sanitized_images")  # re-encoded, randomly renamed
def avatar(request): ...


@validate_uploads(fields={"cv": "pdf", "photo": "images", "notes": None})
class ApplicationView(FormView): ...  # class-based and async views work too


@validate_uploads("documents", on_reject="field")  # errors next to the form field
def upload_document(request): ...


@validate_uploads("images", on_reject=redirect_with_messages("gallery"))
def gallery_upload(request): ...  # flash messages and redirect


@validate_uploads("pdf", mode="report")  # observe this view only
def statements(request): ...


@skip_upload_validation  # like csrf_exempt: no validation for this view
def internal_import(request): ...
```

`validate_uploads(policy=<default>, /, *, fields=None, mode=None, on_reject=None)`

| Argument | Type | Default | Description |
|---|---|---|---|
| `policy` (positional) | policy, name, dotted path or `None` | `DEFAULT_POLICY` (or the built-in `default` if that is `None`) | Policy for every file field. `None`: only the fields named in `fields` are validated. |
| `fields` | `dict[str, policy \| None]` | `None` | Per-field policies; `None` skips that field. A field's list aliases (`photos[0]`, `photos.0`) get the field's policy, but never skip validation. |
| `mode` | `"enforce"`, `"report"`, `"off"` or `None` | `None` (the `MODE` setting) | Mode for this view. |
| `on_reject` | `"reject"`, `"field"`, a callable or `None` | `None` (the `ON_REJECT` setting) | How to answer refusals: the [error response](#refusals), [inline form errors](#inline-form-errors-on_rejectfield), or `callable(request, validation) -> HttpResponse`. `"field"` only takes effect in `enforce` mode. |

Invalid `mode` or `on_reject` values raise `ValueError` when the module is imported.
The bare form `@validate_uploads` (no parentheses) uses the default policy.

- **Function and async views** are wrapped; checks of async views run in a thread
  (`sync_to_async`).
- **Class-based views**: the decorator patches the class's `dispatch` (a `View`
  subclass is required). On a single method use
  `@method_decorator(validate_uploads("pdf"), name="post")`.
- **`skip_upload_validation`** only marks the view; the hard cap `MAX_UPLOAD_SIZE`
  still applies.

**With the handler installed**, the decorator only tells the handler which policy to
use; validation happens while the body streams. **Without the handler**, the
decorator validates `request.FILES` itself before the view runs, so you can adopt
uploadshield one view at a time. For bodies Django never parses itself (DRF's `PUT`,
`PATCH` and raw uploads) it installs the handler for that one request.

## Django REST framework

Every DRF parser stores files through Django's upload handlers, so the handler covers
`MultiPartParser` (POST, PUT, PATCH) and `FileUploadParser` (raw bodies, which arrive as
the field `file`). Decorate API views like any other view:

```python
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.views import APIView

from uploadshield.django import validate_uploads


@validate_uploads("pdf")
class DocumentAPI(APIView):
    parser_classes = (MultiPartParser,)

    def post(self, request): ...


@api_view(["POST"])
@parser_classes([MultiPartParser])
@validate_uploads("images")  # inside @api_view
def photos(request): ...
```

The view's policy applies however the view is wrapped: class decorator, `@api_view`,
or `method_decorator` on a method. Serializer `ListField`s read `attachments[0]`; such
aliases get the policy of `attachments`.

One ordering to know: with `@api_view` and DRF's `SessionAuthentication`, DRF's CSRF
check reads the body before your function runs. The files are then judged by
`VIEW_POLICIES`/`DEFAULT_POLICY` while they stream in, and by your decorator's policy
before the function runs, so both must accept them. To have only the view's policy
apply, use a class-based `APIView` with the decorator on the class, or name the view
in `VIEW_POLICIES`.

How DRF answers refusals:

- With the upload handler installed and `MultiPartParser`, DRF turns the refusal into
  its own `400 ParseError` with `"detail": "Multipart form parse error - Upload
  rejected: ..."`. With the decorator alone, the refusal is answered before the view
  runs, by `REJECTION_HANDLER` (413, 415 or 400).
- With `FileUploadParser`, the refusal reaches Django's `handler400`, which answers
  with the [usual response](#refusals) (for example 415).
- With `on_reject="field"`, serializer file fields report the reason as a normal
  validation error.

`FileValidator` also works as a validator on serializer file fields.

## Forms and model fields

```python
from django import forms
from django.db import models

from uploadshield import MB, presets
from uploadshield.django import FileValidator, ValidatedFileField


class Document(models.Model):  # models, ModelForms, the admin, DRF serializers
    file = models.FileField(validators=[FileValidator("documents")])


class AvatarForm(forms.Form):  # cleaned_data["picture"] is the sanitized file
    picture = ValidatedFileField(policy=presets.SANITIZED_IMAGES.replace(max_size=2 * MB))
```

**`FileValidator(policy="default")`** validates a file and raises a `ValidationError`
with one entry per violation (its `code` is the violation code). It never sanitizes,
skips files that are already stored, and is `deconstructible`: in migrations refer to
policies by name so the migration stores the name, not a copy of the policy.

**`ValidatedFileField(*args, policy="default", **kwargs)`** is a `forms.FileField` that
validates and **sanitizes**: `cleaned_data` holds the sanitized file with the detected
content type. Empty values pass through, so `required=` works as usual.

Both **always enforce**, whatever `MODE` is: a field that accepted a bad file would be a
silent hole. Their refusals send the [`file_rejected`](#observability) signal and are
logged.

## Inline form errors: on_reject="field"

With `on_reject="field"` (per view, or `ON_REJECT = "field"` globally) a refused file
does not abort the request. It is replaced by an empty `RejectedUpload`: the view still
runs, and reading the placeholder's `size`, which every Django and DRF file field does
while cleaning, raises a `ValidationError` with the precise reason. Plain forms,
ModelForms, the admin and serializers therefore show the error next to the field, with
no library-specific form fields:

```python
from django.shortcuts import render

from uploadshield.django import validate_uploads


@validate_uploads("pdf", on_reject="field")
def upload(request):
    form = UploadForm(request.POST or None, request.FILES or None)
    if form.is_valid():  # False for a PNG: "PNG image files are not allowed."
        ...
    return render(request, "upload.html", {"form": form})
```

The refused bytes never reach your code: a `RejectedUpload` reads as `b""`, and its
`.result` holds the `ValidationResult`. The global hard cap `MAX_UPLOAD_SIZE` still
aborts the request.

## Storage: the last line of defense

```python
STORAGES = {
    "default": {
        "BACKEND": "uploadshield.django.storage.ValidatingStorage",
        "OPTIONS": {
            "backend": "django.core.files.storage.FileSystemStorage",  # or S3, GCS, ...
            "options": {},
            "policy": "default",
            "path_policies": {"avatars/": "sanitized_images", "thumbnails/": None},
        },
    },
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
```

Every `storage.save()` is validated against the policy for its path. That includes
legacy views that write `request.FILES` directly, Celery tasks, management commands,
base64 payloads saved as `ContentFile`, and stored files copied under a new name.

**`ValidatingStorage(backend=..., options=None, policy="default", path_policies=None)`**

| Option | Default | Description |
|---|---|---|
| `backend` | `"django.core.files.storage.FileSystemStorage"` | Dotted path of the storage class to wrap. |
| `options` | `{}` | Keyword arguments for that class. |
| `policy` | `"default"` | Policy for every path without a more specific entry; `None` disables validation. |
| `path_policies` | `{}` | Name prefixes and their policies; the **longest** matching prefix wins; `None` skips validation (for files your code generates, like thumbnails). |

**`ValidatingStorageMixin`** adds the same to your own storage classes, configured by
two class attributes: `upload_policy` (the policy for every path, default `"default"`;
`None` disables validation) and `path_policies` (prefixes to policies, as above):

```python
from storages.backends.s3 import S3Storage

from uploadshield.django.storage import ValidatingStorageMixin


class ValidatedS3(ValidatingStorageMixin, S3Storage):
    upload_policy = "default"
    path_policies = {"avatars/": "sanitized_images", "exports/": None}
```

How saving works:

- The **stored name** is judged (its last path component), not the upload's original
  name, so an `upload_to` that turns `cat.png` into `cat.html` is caught.
- Sanitizing policies change what is stored: the name becomes the sanitized one and
  rewritten content replaces the original.
- Files already validated against the same policy under the same name (by the handler
  or `ValidatedFileField`) are not checked again. Files checked only by `FileValidator`
  are validated again, because `FileValidator` does not sanitize.
- Storage follows the global `MODE`: `report` logs and stores, `off` stores without
  checking. A `RejectedUpload` placeholder is refused wherever a policy applies.
- A refusal raises `UploadRejected` from `save()`; inside a request Django answers it
  through `handler400`.
- `storage.open(name, mode)` with a write mode (`w`, `a`, `x` or `+`) on a validated
  path raises `PermissionError`, because writing directly would bypass validation. Use
  `save()`, or a `path_policies` entry of `None` for files your code writes itself.
- `path_policies` prefixes are plain string prefixes: `"avatars"` also matches
  `avatars2/`. End directory prefixes with `/`.

> On Django 4.2 and 5.0, `override_settings(STORAGES=...)` and `settings.configure()`
> drop `OPTIONS` (a side effect of Django's `DEFAULT_FILE_STORAGE` compatibility shim).
> A normal settings module is not affected. In tests on those versions, configure the
> storage through a subclass, or assign it to `default_storage` directly.

## Refusals

In `enforce` mode a refused request is answered with **413** (too large), **415**
(wrong type) or **400** (everything else); see [Refusals](refusals.md) for every code.

The upload handler and storage raise `UploadRejected`, a subclass of both
`MultiPartParserError` and `SuspiciousOperation`. Like Django's own `TooManyFilesSent`,
it is raised while the body is parsed, and Django answers it through `handler400`, also
with `DEBUG = True`:

```python
# urls.py
handler400 = "uploadshield.django.views.bad_request"
```

`bad_request` hands `UploadRejected` to the view's callable `on_reject`, if it has one,
otherwise to [`REJECTION_HANDLER`](#settings-reference); every other bad request goes
to Django's default handler. Without this `handler400`, Django answers refusals with
its generic 400 page (system check `uploadshield.I002` reminds you).

The default `REJECTION_HANDLER`, `uploadshield.django.responses.reject`, returns:

- **JSON** when `Accept` contains `json` but not `text/html`, or the request sends
  `X-Requested-With: XMLHttpRequest`;
- **HTML** otherwise, rendered from the template `uploadshield/rejected.html`. Override
  it in your own templates directory; its context variable `rejection` is the
  [payload](refusals.md#the-error-payload) (`rejection.message`, `rejection.files`,
  each with `name` and `errors`, each with `code` and `message`). Without the app in
  `INSTALLED_APPS` a minimal built-in page is used.

Your own handler is any callable `(request, validation) -> HttpResponse`:

```python
from django.http import JsonResponse


def reject_as_problem_json(request, validation):
    return JsonResponse(
        {"type": "upload-rejected", "files": [o.result.as_dict() for o in validation.rejected]},
        status=422,
    )


UPLOADSHIELD = {"REJECTION_HANDLER": "myproject.uploads.reject_as_problem_json"}
```

`redirect_with_messages(to, *, fallback_message=None)` builds a handler for classic
form views: it adds one `messages.error()` per violation (`"cat.png: PHP script files
are not allowed."`) and redirects to `to` (a URL name or path, as `resolve_url`
accepts). `fallback_message` is flashed when there is nothing more specific.

Messages can be replaced per code with [`MESSAGES`](#settings-reference), and
`EXPOSE_DETAILS = True` adds diagnostic details to the payload; see
[Exposing details](refusals.md#exposing-details).

## Modes and gradual adoption

`MODE` (globally) or `mode=` (per view) is `"enforce"`, `"report"` or `"off"`; see
[Modes](concepts.md#modes-enforce-report-off). In `report` mode refused files reach
the view unchanged, while the log records and signals say what would have been
refused. Field validators (`FileValidator`, `ValidatedFileField`) always enforce.

A safe way to adopt uploadshield in an existing project:

1. Add the app, `FILE_UPLOAD_HANDLERS` and `handler400`, with `MODE = "report"`.
   Nothing is blocked; every would-be refusal is logged (with its SHA-256) and
   signalled.
2. Watch the logs, then tune `POLICIES` and `VIEW_POLICIES` (for example
   `"admin:*"`), so third-party views need no changes. `uploadshield validate FILE
   --django --policy NAME` shows exactly why a file is refused; see
   [CLI](cli.md#choosing-the-policy).
3. Switch to `MODE = "enforce"`, and add `ValidatingStorage` so code paths outside
   requests (tasks, imports) are covered too.
4. Tighten single endpoints with decorators and fields with validators where a precise
   allow-list or inline errors matter.

## Observability

**Signals** (`from uploadshield.django import ...`), all sent with `sender=None`:

| Signal | Keyword arguments | Sent when |
|---|---|---|
| `upload_validated` | `request`, `validation` | after every request whose upload body was parsed and checked (also when all files passed, or none needed checking), except in `off` mode |
| `upload_rejected` | `request`, `validation`, `enforced` | when at least one file was refused; `enforced` is `False` in `report` mode |
| `file_rejected` | `result`, `policy` | when `FileValidator`, `ValidatedFileField` or `ValidatingStorage` refuses a file (no request is available there) |

```python
from django.dispatch import receiver

from uploadshield.django import upload_rejected


@receiver(upload_rejected)
def audit(sender, request, validation, enforced, **kwargs):
    for outcome in validation.rejected:
        AuditLog.objects.create(
            user=request.user,
            name=outcome.result.name,
            codes=list(outcome.result.codes),
            sha256=outcome.sha256(),
        )
```

**`get_upload_validation(request)`** returns the request's `UploadValidation` (empty if
no file needed checking), or `None` if the request was not validated. Views can use it to see what happened, for example in
`report` mode.

`UploadValidation`

| Member | Description |
|---|---|
| `outcomes` | tuple of `FileOutcome`, one per validated file |
| `mode` | the mode the request was validated in |
| `ok` | `True` if every file passed |
| `rejected` | the `FileOutcome`s that failed |
| `enforced` | `True` in `enforce` mode |
| `for_field(name)` | the outcomes of one form field |

`FileOutcome`

| Member | Description |
|---|---|
| `field` | form field name |
| `index` | position within that field (multiple files) |
| `result` | the [`ValidationResult`](python-api.md#results) |
| `policy_name` | name of the policy that judged the file |
| `ok` | `result.ok` |
| `sha256()` | hex SHA-256 of the uploaded bytes, or `None` for files refused while streaming |

**Logging**: every refusal is a WARNING on the `uploadshield` logger with structured
data in `record.upload`; see [The log record](refusals.md#the-log-record). Accepted
files are logged at DEBUG level.

## Settings reference

All settings live in one dict, `UPLOADSHIELD`, in your settings module. Unknown keys
raise `ImproperlyConfigured` ("Unknown UPLOADSHIELD keys: ... Valid keys: ..."), which
also shows up as system check `uploadshield.E001`.

| Key | Type | Default | Description |
|---|---|---|---|
| `MODE` | `"enforce"`, `"report"`, `"off"` | `"enforce"` | What request-level validation does with refused files. `off` disables request-level validation; field validators still enforce. |
| `DEFAULT_POLICY` | policy, name, dotted path or `None` | `"default"` | Policy for views without a decorator or `VIEW_POLICIES` match. `None`: such views are not validated. |
| `POLICIES` | `dict[str, Policy]` | `{}` | Your policies by name, added to the built-in ones; a built-in name (even `"default"`) is replaced. Values must be `Policy` objects. |
| `VIEW_POLICIES` | `dict[str, policy \| None]` | `{}` | Glob on URL names to policy; `None` skips; first match wins; decorators take precedence. |
| `REJECTION_HANDLER` | dotted path or callable | `"uploadshield.django.responses.reject"` | `(request, validation) -> HttpResponse` used by `handler400`. |
| `EXPOSE_DETAILS` | `bool` | `False` | Include detection details in error responses. |
| `NORMALIZE_CONTENT_TYPE` | `bool` | `True` | Set `UploadedFile.content_type` of accepted files to the detected type, so the client's claim never reaches your code. |
| `MAX_UPLOAD_SIZE` | `int` or `None` | `None` | Hard cap per file in bytes, enforced by the handler in every mode, even for skipped views. |
| `ON_REJECT` | `"reject"` or `"field"` | `"reject"` | Default for `on_reject`: an error response, or inline form errors. |
| `UPLOAD_HANDLERS` | list of dotted paths | Django's `MemoryFileUploadHandler` and `TemporaryFileUploadHandler` | Where `ValidatingUploadHandler` stores incoming data. Must not be empty, nor list `ValidatingUploadHandler` itself. |
| `MESSAGES` | `dict[str, str]` | `{}` | User-facing messages per violation code; lazy translations are fine. |

Policy references (`DEFAULT_POLICY`, `VIEW_POLICIES` values, decorator and field
arguments) may be a `Policy`, a registered name, or a dotted path to a module-level
`Policy`. Unknown references raise `ImproperlyConfigured` ("Unknown upload policy 'x'.
Known policies: ..."). `DEFAULT_POLICY` and `VIEW_POLICIES` are resolved when the
settings are loaded; decorator, validator and storage references when they are first
used. The configuration is reloaded when `UPLOADSHIELD` changes (for example with
`override_settings` in tests).

## System checks

Registered under the `security` tag; run them with `uv run python manage.py check`.

| ID | Level | Meaning |
|---|---|---|
| `uploadshield.E001` | Error | The `UPLOADSHIELD` setting is invalid (unknown key, bad value, unknown policy). |
| `uploadshield.E002` | Error | A policy's extra checks or sanitizers need a missing optional dependency (e.g. `YaraRules` without `yara-python`, or `ReencodeImage` without Pillow, which makes the built-in `sanitized_images` an error until you install the `images` extra). |
| `uploadshield.E003` | Error | A policy's YARA rules do not compile. |
| `uploadshield.W001` | Warning | Other handlers are listed next to `ValidatingUploadHandler` in `FILE_UPLOAD_HANDLERS`; those after it never receive data. Put them in `UPLOAD_HANDLERS`. |
| `uploadshield.W002` | Warning | A policy accepts images and uses `ImageIntegrity`, but Pillow is not installed, so images are not decoded. |
| `uploadshield.W003` | Warning | `MAX_UPLOAD_SIZE` is set but has no effect without the handler. |
| `uploadshield.W004` | Warning | `ValidatingUploadHandler` is not the first entry of `FILE_UPLOAD_HANDLERS`. |
| `uploadshield.I001` | Info | The handler is not installed: only decorated views, field validators and `ValidatingStorage` are protected. |
| `uploadshield.I002` | Info | The handler is installed but `handler400` is not `uploadshield.django.views.bad_request`, so refusals get Django's generic 400 page. |

The checks cover the policies in `POLICIES` (and the built-in ones), `DEFAULT_POLICY`
and `VIEW_POLICIES`. Policies passed directly to decorators, validators or storage are
not inspected.

## Testing your integration

Django's test client goes through the upload handler like a real request:

```python
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings


def test_disguised_script_is_refused():
    shell = SimpleUploadedFile("cat.png", b"<?php system($_GET['c']); ?>", "image/png")
    response = Client().post("/avatar/", {"picture": shell}, headers={"Accept": "application/json"})
    assert response.status_code == 415
    assert response.json()["files"][0]["errors"][0]["code"] == "type_not_allowed"


@override_settings(UPLOADSHIELD={"MODE": "report"})
def test_report_mode_lets_files_through(): ...
```

Ask for JSON (`Accept: application/json`) to get the machine-readable payload. To test
a policy without HTTP, call `uploadshield.validate()` directly; see
[Python API](python-api.md). To see why a file is refused under your project's
settings, run `uv run uploadshield validate FILE --django --policy NAME`.

## Good to know

- **Async views and ASGI** work. Django parses request bodies synchronously; async views
  that read `request.FILES` directly run the checks on the event loop. Wrap the access
  in `sync_to_async` if uploads are large.
- **Request size**: Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` limits non-file form data,
  not files; use the policy's `max_size` and `MAX_UPLOAD_SIZE` for files, and a limit
  in your web server for the whole request.
- **Replacing `request.upload_handlers` in a view** (as Django's documentation shows for
  progress bars) removes the handler for that request. Wrap your handlers instead:
  `request.upload_handlers = [ValidatingUploadHandler(request, inner=[MyHandler(request)])]`.
  `ValidatingStorage` still checks what such a view saves.
- **Base64 in JSON bodies** never passes through upload handlers. Validate it with
  `FileValidator` on the serializer field, and with `ValidatingStorage` when saved.
- **The app in `INSTALLED_APPS`** is needed for the system checks and the HTML template,
  not for validation itself.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Refusals show Django's generic "Bad Request (400)" page | `handler400` is not set | `handler400 = "uploadshield.django.views.bad_request"` in the root URLconf |
| Uploads are not validated at all | the handler is not installed, `MODE` is `"off"`, `DEFAULT_POLICY` is `None`, or a `VIEW_POLICIES` entry maps the view to `None` | check `manage.py check` (`I001`), the settings, and `get_upload_validation(request)` |
| Files are refused by the default policy although the view's policy allows them | something parsed the body before the view's decorator ran, and routing could not see the decorator (`@api_view` with `SessionAuthentication`) | decorate the view class, or name the view in `VIEW_POLICIES` |
| Files pass that should be refused, and a warning is logged | `MODE = "report"` | switch to `"enforce"` |
| `ImproperlyConfigured: Unknown upload policy` | a name that is neither built in nor in `POLICIES` | register it in `POLICIES` or use a dotted path |
| `PermissionError` from `storage.open(..., "wb")` | writing directly would bypass validation | use `storage.save()`, or `path_policies={"generated/": None}` |
| Images are never decoded or re-encoded, or `manage.py check` reports `E002` for `sanitized_images` | Pillow is missing (`W002`, `E002`) | `uv add "uploadshield[images]"` |
