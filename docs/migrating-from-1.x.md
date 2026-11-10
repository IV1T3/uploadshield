# Migrating from django-middleware-fileuploadvalidation 1.x

`uploadshield` is the successor of `django-middleware-fileuploadvalidation`. Version 2
replaces the middleware with Django's own extension points (an upload handler,
decorators, field validators and a storage wrapper) and adds Flask, FastAPI and a
command line. This page maps the 1.x options to their replacements.

## Steps

1. Replace the dependency: `uv remove django-middleware-fileuploadvalidation` and
   `uv add "uploadshield[django,images]"`.
2. Remove `FileUploadValidationMiddleware` from `MIDDLEWARE`.
3. Add the app, the upload handler and the error view, as in the
   [Django quickstart](django.md#quickstart):

   ```python
   INSTALLED_APPS += ["uploadshield.django"]
   FILE_UPLOAD_HANDLERS = ["uploadshield.django.handlers.ValidatingUploadHandler"]
   UPLOADSHIELD = {"MODE": "report"}  # observe first, then "enforce"
   ```

   and `handler400 = "uploadshield.django.views.bad_request"` in the root URLconf.
4. Replace `@file_upload_config(...)` decorators with `@validate_uploads(...)`, using the
   table below.
5. Run `uv run python manage.py check` and watch the logs in `report` mode before
   switching to `enforce`.

## Options

| 1.x option | uploadshield |
|---|---|
| `@file_upload_config(...)` | `@validate_uploads(policy)`; see [the decorator](django.md#the-validate_uploads-decorator) |
| `whitelist=[...]` / `whitelist_name="IMAGE_ALL"` | `Policy(allowed_types=...)` / the preset `"images"`; see [Policies](policies.md) |
| `file_size_limit` (kB) | `max_size` (bytes; use `KB`/`MB`) |
| `filename_length_limit` | `FilenameCheck(max_length=...)` |
| `keep_original_filename=False` | `sanitizers=(RandomizeFilename(),)` |
| `sanitization=True` | `presets.SANITIZED_IMAGES` / `ReencodeImage()` |
| `clamav=True` | `checks=(ClamAV(address=...),)` |
| `vendor/yara/*.yar` | `checks=(YaraRules(rules=("/path/to/rules",)),)` |
| `response_config={...}` | `handler400` plus `on_reject=` / `REJECTION_HANDLER` / `redirect_with_messages()`; see [Refusals](django.md#refusals) |
| `uploadlogs_mode` and `./uploadlogs/*.json` | the `upload_rejected` signal and the `uploadshield` logger; see [Observability](django.md#observability) |

## What behaves differently

- **Validation streams**: the upload handler refuses dangerous names before a byte is
  stored and wrong types after the first 8 KiB, instead of after the whole request was
  read.
- **Every parser is covered**: Django forms, the admin and Django REST framework (POST,
  PUT, PATCH, raw bodies) all store files through upload handlers.
- **The type comes from the content**, and your code receives the detected content
  type (`NORMALIZE_CONTENT_TYPE`).
- **Refusals fail closed** and use stable codes; see [Refusals](refusals.md).
