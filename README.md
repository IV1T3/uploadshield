# uploadshield

[![PyPI](https://img.shields.io/pypi/v/uploadshield)](https://pypi.org/project/uploadshield/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://pypi.org/project/uploadshield/)
[![License](https://img.shields.io/pypi/l/uploadshield)](https://github.com/IV1T3/uploadshield/blob/main/LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](https://github.com/IV1T3/uploadshield#add-it-to-your-app)
[![OWASP](https://img.shields.io/badge/OWASP-cheat%20sheet%20mapped-000000?logo=owasp)](https://github.com/IV1T3/uploadshield/blob/main/docs/OWASP.md)

Content-aware validation and sanitization of file uploads for Django, Flask and FastAPI.

Web frameworks hand you the filename and `Content-Type` of an upload as if they were
facts. They are whatever the client sent: a PHP web shell named `cat.png` with
`Content-Type: image/png` arrives as an image in Django, Flask and FastAPI alike.
uploadshield judges the **bytes** instead. It detects the real format, checks it
against what the endpoint accepts, looks inside documents and archives for active
content, and can rewrite images so that hidden payloads and metadata are destroyed.

## Try it in 10 seconds

No code needed; [uv](https://docs.astral.sh/uv/) runs it straight from PyPI:

```console
$ uvx uploadshield scan uploads/
uploads/
  ✗ avatar.png  PHP script · 30 bytes
      type_not_allowed  PHP script files are not allowed.
      embedded_code  The file contains embedded code.  <?php
  ? backup.7z  7-Zip archive · 187 bytes
      type_not_allowed  Its contents cannot be inspected: unpack it and scan the files, or add --clamav.
  ! holiday.png  JPEG image · 14.6 KB
      extension_mismatch  The file extension '.png' does not match its content (JPEG image).
  ✗ invoice.pdf  PDF document · 293 bytes
      pdf_active_content  The PDF contains active content such as scripts or embedded files.  JS, JavaScript
  ✓ notes.txt  Plain text · 14 bytes
  ✓ report.pdf  PDF document · 180 KB

6 files in 0.0 s: 2 clean, 2 dangerous, 1 refused, 1 not verified.
```

`uploadshield validate FILE --policy NAME` shows exactly why a policy accepts or
refuses a file. See the [command line guide](docs/cli.md).

## What it protects against

- **Disguised files**: scripts and executables named `.png` or `.pdf`. The format
  comes from the content, never from the name.
- **Dangerous names**: `shell.php.jpg`, `.htaccess`, `../../etc/passwd`, `CON.txt`,
  bidi-override tricks, and their percent-encoded and fullwidth variants.
- **Active documents**: PDFs with JavaScript or embedded files, Office files with
  macros, DDE fields or remote templates, SVGs with scripts, XML with entity bombs.
- **Archive attacks** in ZIP and tar (`.tar.gz`, `.tar.bz2`, `.tar.xz`): bombs, zip
  slip, links, deeply nested archives, and members a server would run once extracted.
- **Hidden payloads**: PHP in image metadata, polyglots such as GIFAR, CSV cells that
  run commands through DDE (`=cmd|' /C calc'!A0`).
- **Malware**, with ClamAV or your own YARA rules, and optionally Google's Magika model
  for scripts disguised as data.

It fails closed: a check that crashes, a file too large to inspect, an encrypted file
or an unreachable virus scanner means a refusal. Image decoding needs Pillow, the
`images` extra (`uvx --from "uploadshield[images]" uploadshield scan ...`); without it
the command line warns that image checks are inactive. The
[checks reference](docs/checks.md) lists everything each check catches, and what it
does not.

## Add it to your app

```bash
uv add "uploadshield[django,images]"    # or [flask,images] or [fastapi,images]
```

**Django**: every file is checked while the request body streams in, in views, forms,
the admin and Django REST framework.

```python
# settings.py
INSTALLED_APPS += ["uploadshield.django"]
FILE_UPLOAD_HANDLERS = ["uploadshield.django.handlers.ValidatingUploadHandler"]

# urls.py (root URLconf): answer refusals with 413/415/400, as JSON or HTML
handler400 = "uploadshield.django.views.bad_request"
```

**Flask**: every multipart request is checked before it reaches a view.

```python
from flask import Flask

from uploadshield.flask import UploadShield

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # Werkzeug parses the body first
UploadShield(app)
```

**FastAPI**: dependencies validate and sanitize uploads; `all_files()` covers the
whole app.

```python
from typing import Annotated

from fastapi import Depends, FastAPI, UploadFile

from uploadshield.fastapi import UploadShield

shield = UploadShield()
app = FastAPI(dependencies=[Depends(shield.all_files())])


@app.post("/avatar")
async def avatar(
    file: Annotated[UploadFile, Depends(shield.file("sanitized_images"))],
): ...  # re-encoded, renamed, with the content type detected from the bytes
```

That's it: every upload is now checked against the built-in `default` policy (common
images, PDF, Office and OpenDocument files, text and CSV, audio and video, up to
50 MB). Your code only receives files that passed; the others are answered with 413,
415 or 400. On an existing site, start with `"MODE": "report"` to log would-be
refusals without blocking anything.

The guides cover every option: [Django](docs/django.md), [Flask](docs/flask.md),
[FastAPI](docs/fastapi.md).

## Decide what to accept

A **policy** says which files an endpoint accepts. Pick a built-in one, or derive your
own:

```python
from uploadshield import MB, Policy, presets

AVATARS = presets.SANITIZED_IMAGES.replace(name="avatars", max_size=2 * MB)
INVOICES = Policy(
    name="invoices",
    allowed_types={"application/pdf", "image/png", "image/jpeg"},
    max_size=5 * MB,
)
```

| Built-in policy | Accepts | Size limit |
|---|---|---|
| `default` | everything below | 50 MB |
| `images` | JPEG, PNG, GIF, WebP | 10 MB |
| `sanitized_images` | the same, re-encoded and randomly renamed | 10 MB |
| `pdf` | PDF | 25 MB |
| `documents` | PDF, Word, Excel, PowerPoint, OpenDocument, text, CSV | 25 MB |
| `media` | common audio and video formats | 500 MB |

Use one per view (`@validate_uploads("pdf")` in Django and Flask,
`shield.file("pdf")` in FastAPI), per URL pattern, or per form field. The
[policy guide](docs/policies.md) covers allowed types, filename rules, tuning checks,
virus scanners and sanitizers.

## How it works

![The client's upload is parsed by Django, Flask or FastAPI, which hands every file to
uploadshield. uploadshield checks size, filename, the type proven by the bytes, the
allow-list and the content, then sanitizes. Passing files reach your view; refused
files never do, and the client receives a 400, 413 or 415.](docs/images/upload-flow.svg)

- **Cheapest checks first.** A forbidden name is refused before any content is read;
  expensive parsers only see files that passed the cheap checks.
- **Your code only sees files that passed**, sanitized if the policy says so, with the
  content type detected from the bytes.
- **Every refusal is answered and recorded**: a stable code, a 400/413/415 response, a
  structured log record and a signal or callback.

[Concepts](docs/concepts.md) explains the model; [Architecture](docs/ARCHITECTURE.md)
how it is built.

## Documentation

| Page | What you find there |
|---|---|
| [Concepts](docs/concepts.md) | how uploadshield works, in one read |
| [Django](docs/django.md) · [Flask](docs/flask.md) · [FastAPI](docs/fastapi.md) | setup, every option, refusals, testing |
| [Command line](docs/cli.md) | `scan`, `validate`, JSON output for CI |
| [Policies](docs/policies.md) | choosing and configuring what to accept |
| [Checks and sanitizers](docs/checks.md) | every check with all its options |
| [Refusals](docs/refusals.md) | codes, status codes, messages, logs |
| [Python API](docs/python-api.md) | using the engine directly, custom checks and types |
| [All docs](docs/README.md) | the full map, and [`llms.txt`](llms.txt) for AI agents |

## Security and compatibility

- **Mapped to OWASP**: every recommendation of OWASP's File Upload Cheat Sheet and
  every test case of its Unrestricted File Upload page, with its coverage and the tests
  that prove it, is in [docs/OWASP.md](docs/OWASP.md).
- **Supported**: Python 3.11+, Django 4.2+, Flask 2.3+, FastAPI 0.110+.
- **No required dependencies.** Pillow, YARA, Magika and libmagic are optional extras.
- **Typed** (`py.typed`), with about 2500 tests including property-based fuzzing.
- **Coming from django-middleware-fileuploadvalidation 1.x?** See
  [Migrating from 1.x](docs/migrating-from-1.x.md).

Contributing: see [Development](docs/development.md). License: Apache-2.0.
