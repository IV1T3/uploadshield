# How uploadshield works

This page explains the ideas behind uploadshield: what a policy is, how a file is
judged, what "fail closed" means, and when each framework runs the checks. Read it
once before configuring anything. The framework guides ([Django](https://github.com/IV1T3/uploadshield/blob/main/docs/django.md),
[Flask](https://github.com/IV1T3/uploadshield/blob/main/docs/flask.md), [FastAPI](https://github.com/IV1T3/uploadshield/blob/main/docs/fastapi.md)) and the [policy guide](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md) build on
these terms.

**On this page**

- [The problem](#the-problem)
- [The model: upload, policy, result](#the-model-upload-policy-result)
- [How the type is detected](#how-the-type-is-detected)
- [Allow-lists and wildcards](#allow-lists-and-wildcards)
- [The pipeline](#the-pipeline)
- [Fail closed](#fail-closed)
- [Sanitization](#sanitization)
- [Modes: enforce, report, off](#modes-enforce-report-off)
- [When validation happens in each framework](#when-validation-happens-in-each-framework)
- [Glossary](#glossary)

## The problem

When a browser uploads a file it sends three things the server cannot trust: the
**filename**, the **`Content-Type` header**, and the bytes. Web frameworks hand the
first two to your code as if they were facts. A PHP web shell named `cat.png` with
`Content-Type: image/png` arrives as an image in Django, Flask and FastAPI alike.

| | Django | Flask / Werkzeug | FastAPI / Starlette |
|---|---|---|---|
| Type check by content | Pillow for `ImageField` only | none (`mimetype` is client-declared) | none (`content_type` is client-declared) |
| Safe filenames | path components stripped | only via `secure_filename()` | raw `UploadFile.filename` |
| Per-file size limit | none (whole request only) | none (`MAX_CONTENT_LENGTH` is whole request) | none (`max_part_size` skips files) |
| Allow-list | `FileExtensionValidator` (name only) | Flask-WTF `FileAllowed` (name only) | none |

uploadshield judges the **bytes**. It detects the real format from the content, checks
it against an allow-list, makes sure the name agrees with the content, looks inside
formats for active content (macros, PDF JavaScript, SVG scripts, archive bombs, hidden
code) and can rewrite files so that hidden payloads are destroyed.

## The model: upload, policy, result

Everything goes through one function, whichever framework you use:

```python
from uploadshield import Upload, presets, validate

result = validate(Upload.from_bytes(b"<?php system($_GET[0]); ?>", "cat.png"), presets.IMAGES)
result.ok  # False
result.codes  # ('type_not_allowed',)
```

- **`Upload`** holds the raw facts: a binary stream, the client's filename, the size,
  the declared content type and the form field. The name and declared type are
  untrusted.
- **`Policy`** says what is acceptable: allowed types, a size limit, filename rules,
  the checks to run and the sanitizers to apply. Policies are immutable values. You
  derive new ones from old ones and refer to them by name. See [Policies](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md).
- **`ValidationResult`** is the outcome: `ok`, the list of **violations** (each with a
  stable `code`, a user-safe `message` and private `details`), the detected
  `file_type`, the checks that ran and, if the policy sanitizes, the sanitized file.

The framework adapters only decide *where* in the request this happens and turn a
result into the framework's own response. Everything that decides whether a file is
safe is written and tested once, in the engine.

While checks run, the file is wrapped in an `InspectedFile`. It reads the head bytes,
detects the type, computes the SHA-256 and parses ZIP directories at most once, and
always restores the stream position, so your code can still read the file afterwards.

## How the type is detected

The type comes from the **content**, never from the name or the header:

1. A built-in, dependency-free sniffer reads the first bytes and matches multi-field
   signatures (PNG, JPEG, PDF, ZIP, OOXML, ODF, EPUB, ELF, PE, Mach-O, MP4, ...) and
   classifies text (PHP, shell scripts, SVG, HTML, XML, plain text).
2. Some formats cannot be told apart by content: CSV, TSV, Markdown and JSON are all
   text. For these the extension may **narrow** a proven parent type: content that is
   `text/plain` named `data.csv` becomes `text/csv`. The extension can never *change*
   the type, only refine it.
3. The answer is looked up in a deterministic registry of 61 types (see
   [Registered file types](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md#registered-file-types)). Python's `mimetypes`
   module is not used, because its answers depend on the machine.

If no type is found the file fails with `type_unknown`. You can register your own
formats or plug in libmagic; see [Types and sniffers](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md#types-and-sniffers).

## Allow-lists and wildcards

A policy lists the types it accepts: exact MIME types (`"image/png"`) or wildcards
(`"image/*"`). Wildcards **never** match executables or formats that run script in a
browser: `text/html`, `image/svg+xml` and `application/xml`. These must be named
explicitly, so `"image/*"` does not quietly accept SVG.

The presets (`images`, `pdf`, `documents`, `media`, `default`, ...) contain no
executable or script-capable format at all.

## The pipeline

A policy turns into an ordered list of checks, cheapest first:

1. **size** (`FileSize`): empty files and the size limit;
2. **filename** (`FilenameCheck`): dangerous extensions, reserved names, path tricks;
3. **type** (`AllowedTypes`): the detected type against the allow-list;
4. **extension** (`ExtensionMatchesType`): the name's extension must belong to the type;
5. **declared type** (`DeclaredTypeMatches`, off by default): the client's header must
   match;
6. **content checks**: archives, Office documents, XML, PDF, SVG, embedded code,
   images;
7. **your checks**: ClamAV, YARA, Magika or custom ones.

A check that does not apply to the file (for example the PDF check on a PNG) is
skipped. With `fail_fast=True` (the default) the pipeline stops after the first check
that finds a problem, so a forbidden name is refused before any content is read and
expensive parsers only see files that passed the cheap checks. With `fail_fast=False`
every check runs and you get every problem at once.

The full list of checks and their options is in [Checks](https://github.com/IV1T3/uploadshield/blob/main/docs/checks.md).

## Fail closed

When uploadshield cannot be sure, the file is refused:

- A check that crashes (a parser bug, a corrupt file that trips a library) becomes the
  violation `check_failed` with `details["reason"] == "crashed"`. The traceback is
  logged.
- A file too large for a check to inspect (beyond its memory budget) becomes
  `check_failed` with `details["reason"] == "too_large"`. It is not skipped.
- An unreachable virus scanner is `scanner_unavailable`, unless you explicitly set
  `ClamAV(fail_open=True)`.
- Encrypted archives and PDFs cannot be inspected and are refused unless you allow
  them.
- An object stream in a PDF that cannot be decoded is refused rather than ignored.

What failing closed does **not** cover, because nothing is inspected:

- A check whose optional dependency is missing does nothing: without Pillow
  (`uv add "uploadshield[images]"`) images are not decoded, and AVIF and HEIC also need
  Pillow's plugins. Django's system checks and the command line warn about this.
- 7-Zip and RAR archives are detected but not opened; wildcards never match them and
  no preset allows them. ZIP and tar archives (plain, gzip, bzip2, xz) are opened.
- The contents of archive members are not validated against a policy; only their names,
  sizes and paths are.
- `ClamAV(fail_open=True)` accepts files when the scanner is down.

## Sanitization

Sanitizers run only after every check has passed. They can rewrite the content
(`ReencodeImage` decodes and re-encodes images, dropping EXIF/GPS metadata, comments
and anything appended after the image data) and the name (`RandomizeFilename`,
`SafeFilename`).

What a sanitizer produces is checked again: a new name must pass the filename rules
and new content must pass the content checks. Otherwise the file is refused with the
violation found in the sanitized output (`details["in_sanitized_output"] == True`), or
with `sanitization_failed` if the sanitizer itself fails. The sanitized type must be
the same as the original type.

Your view receives the sanitized file, with the content type detected from the bytes.

## Modes: enforce, report, off

Every integration has a mode:

| Mode | What happens to a refused file |
|---|---|
| `enforce` (default) | The request is answered with 400, 413 or 415; the view never sees the file. (With Django's `on_reject="field"` the view runs and the form field reports the error instead.) |
| `report` | The refusal is logged and signalled, but the file reaches the view unchanged. Use it to roll out uploadshield on an existing site. |
| `off` | Request-level validation does nothing. |

Django's per-file hard cap `MAX_UPLOAD_SIZE` applies in every mode.

**Field-level validators always enforce**, whatever the mode: Django's `FileValidator`
and `ValidatedFileField` and Flask's `ShieldedFile` refuse a bad file even in `report`
or `off` mode, because a form or model field that accepts it would be a silent hole.

## When validation happens in each framework

| | When files are checked | Early abort |
|---|---|---|
| **Django** | While the body streams in, through an upload handler: the name before the first byte is stored, the type after the first 8 KiB, the size as bytes arrive, the rest when the file is complete. | Yes, for name, size and type: such files are refused without being stored in full. Content checks run once the file is complete. |
| **Flask** | In a `before_request` hook (or a decorator), after Werkzeug has parsed the body. | No: cap requests with `MAX_CONTENT_LENGTH`. |
| **FastAPI** | In dependencies, after Starlette has parsed the form. | No: cap request sizes in the ASGI server or proxy. |

Django's upload handlers are a public streaming API; Werkzeug's per-file hook is
private and deprecated, and Starlette has none. Every check and sanitizer still
applies in Flask and FastAPI. Only the early abort does not.

## Glossary

| Term | Meaning |
|---|---|
| **upload** | A file as the client sent it: stream, name, size, declared type, field. |
| **policy** | An immutable value that says which files are acceptable and how to sanitize them. |
| **check** | One rule of a policy (`FileSize`, `PdfActiveContent`, ...). It reports violations. |
| **sanitizer** | A step that rewrites an accepted file (`ReencodeImage`, `RandomizeFilename`). |
| **violation** | One problem found by a check: a `code`, a `message` and `details`. |
| **code** | The stable identifier of a violation, e.g. `type_not_allowed`. See [Refusals](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md). |
| **mode** | `enforce`, `report` or `off`: what an integration does with refused files. |
| **verdict** | The command line's summary of a file: clean, dangerous, refused or not verified. See [CLI](https://github.com/IV1T3/uploadshield/blob/main/docs/cli.md). |
| **preset** | A built-in policy: `default`, `images`, `sanitized_images`, `pdf`, `documents`, `media`. |
