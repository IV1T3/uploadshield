# Architecture

This document describes how uploadshield is built. It starts with the architecture all
frameworks share, then shows how it is integrated into Django, Flask and FastAPI, and
ends with the reasoning behind the design. How OWASP's recommendations and test cases
for file uploads are covered is in [OWASP.md](OWASP.md).

## 1. Overview

uploadshield is one validation engine with a thin adapter per web framework.

![Applications built with Django, Flask or FastAPI hook into the matching adapter. Each
adapter hands the engine an Upload and gets a ValidationResult back. No web framework is
imported below the adapters: the engine runs the policy's checks and sanitizers on top of
the core.](images/architecture.svg)

- **The engine** knows nothing about HTTP. It takes an `Upload` (a stream, the client's
  filename, the size and the declared content type) and a `Policy`, and returns a
  `ValidationResult`: stable codes, user-safe messages, private details and, if the
  policy sanitizes, the sanitized file.
- **An adapter** connects the engine to one framework. It turns the framework's file
  object into an `Upload`, decides *where* in the request validation happens (using the
  framework's own extension points), delivers the sanitized file and turns refusals into
  the framework's own errors.
- **`uploadshield.web`** holds what every adapter shares without importing a framework:
  status codes, error payloads, content negotiation, policy lookup and the structured
  log line.
- **The command line** (`uploadshield scan`/`validate`) is one more client of the
  engine, for people instead of requests. It is described in [3.4](#34-command-line).

Because of this split, everything that decides whether a file is safe is written and
tested once. The engine also works without any framework: in Celery tasks, management
commands, or on e-mail attachments.

### Principles

1. **A pure engine, thin adapters.** The engine (`core`, `checks`, `policy`, `engine`,
   `presets`, `web`) imports no web framework, and each adapter imports only its own.
   The command line sits on top: nothing imports it, and it reaches Django only through
   `django/cli.py`. `tests/meta/test_architecture.py` enforces these rules, so the
   engine is unit-testable without HTTP.
2. **Policies are values.** A `Policy` is a frozen, hashable dataclass. You can compare,
   cache and derive policies (`.replace()`, `.extend()`) and serialise them into Django
   migrations (`deconstruct()`). There is no global mutable configuration.
3. **Checks are small and single-purpose.** Each check is a frozen dataclass whose fields
   are its parameters, with `applies(file)` and `run(file) -> violations`. New checks need
   no changes anywhere else.
4. **Facts are computed once.** `InspectedFile` lazily caches the head bytes, detected
   type, SHA-256 and ZIP directory that several checks share. The upload's stream
   position is always restored, so the application can still read the file.
5. **Deterministic type detection.** A built-in, dependency-free sniffer with
   multi-field signatures, a registry of types and extensions, and WHATWG-style
   text/HTML sniffing. `mimetypes` is banned by lint because its answers depend on
   `/etc/mime.types` and differ between machines.
6. **Structured, stable outcomes.** Every refusal carries a stable `code`, a user-safe
   `message` and private `details`. Clients see codes and messages; logs and signals
   see the details (detected type, matched signature, SHA-256).
7. **Secure defaults, explicit escape hatches.** Presets never include script-capable or
   executable formats, and wildcards (`image/*`) never match them either. Loosening is
   always an explicit argument.
8. **Fail closed.** A crashing parser, an unreachable scanner or a file that cannot be
   inspected (an encrypted archive or PDF) is a refusal, not a pass.

### Package layout

```
uploadshield/
├── core/            primitives; imports nothing from the layers above
│   ├── types.py         FileType registry (MIME, extensions, aliases, container, parent)
│   ├── upload.py        Upload (raw facts) and InspectedFile (lazy, cached analysis)
│   ├── sniffing.py      Sniffer protocol, BuiltinSniffer, MagicSniffer, ChainedSniffer
│   ├── containers.py    shared, cached ZIP access
│   ├── check.py         Check / Sanitizer base classes
│   ├── violations.py    Violation and stable Code values
│   └── result.py        ValidationResult and SanitizedFile
├── checks/          the rules (pure Python; Pillow, yara and Magika are optional)
├── sanitizers.py    ReencodeImage, RandomizeFilename, SafeFilename
├── policy.py        Policy: allow-list plus ordered pipeline
├── engine.py        validate(upload, policy): run, fail closed, sanitize
├── presets.py       IMAGES, SANITIZED_IMAGES, PDF, DOCUMENTS, MEDIA, DEFAULT
├── web.py           framework-neutral status codes, error payloads, policy lookup, logging
├── cli/             the uploadshield command (standard library only)
│   ├── __init__.py      main(): arguments, exit status, engine logs kept out of the report
│   ├── _commands.py     scan, validate, policies, explain
│   ├── _scan.py         the scan policy and the optional scanners
│   ├── _verdicts.py     what each code means for a person: verdicts and explanations
│   ├── _walk.py         paths to regular files: sorted walks, links, FIFOs, stdin
│   ├── _render.py       human output (and the JSON reporter)
│   ├── _style.py        colour decisions, glyphs, escaping of untrusted names
│   └── _json.py         the --json document
├── django/          the only package that imports Django
│   ├── conf.py          UPLOADSHIELD parsing and validation
│   ├── service.py       orchestration shared by the Django layers (+ RejectedUpload)
│   ├── handlers.py      ValidatingUploadHandler: the project-wide safety net
│   ├── decorators.py    @validate_uploads / @skip_upload_validation
│   ├── validators.py    FileValidator (models, forms, DRF serializers)
│   ├── forms.py         ValidatedFileField (validates and sanitizes)
│   ├── storage.py       ValidatingStorage / ValidatingStorageMixin (STORAGES)
│   ├── exceptions.py    UploadRejected (MultiPartParserError + SuspiciousOperation)
│   ├── views.py         bad_request, for handler400
│   ├── responses.py     content-negotiated 400/413/415 responses
│   ├── signals.py       upload_validated / upload_rejected / file_rejected
│   ├── checks.py        Django system checks
│   └── cli.py           configure(): django.setup() for uploadshield --django
├── flask/           the only package that imports Flask/Werkzeug
│   ├── core.py          UploadShield extension, request validation, UploadRejected, signals
│   ├── decorators.py    @validate_uploads / @skip_upload_validation
│   └── wtforms.py       ShieldedFile (Flask-WTF / WTForms validator)
└── fastapi/         the only package that imports FastAPI/Starlette
    └── shield.py        UploadShield: file(), files(), all_files() dependencies
```

## 2. The engine

### The pipeline

`Policy.pipeline` is assembled in cost order. It stops at the first failure
(`fail_fast=True`):

1. `FileSize` (free)
2. `FilenameCheck` (free)
3. `AllowedTypes` (reads 8 KiB)
4. `ExtensionMatchesType`
5. `DeclaredTypeMatches` (opt-in; browsers derive the header from the OS)
6. `content_checks`, each format-specific and self-selecting via `applies()`:
   `ArchiveSafety`, `OfficeMacros`, `XmlSafety`, `PdfActiveContent`,
   `SvgActiveContent`, `EmbeddedContent`, `ImageIntegrity`
7. your `checks`, e.g. `ClamAV`, `YaraRules`, `MagikaCheck`

Only if all of them pass do the `sanitizers` run. The sanitized output is sniffed again
and must still be the same type, and the content checks run on it again: a payload
crafted to appear only after an image library re-compresses the pixels is refused too. The adapters can also run single stages on a file that
is still arriving (`preflight()`); Django uses this to refuse names and types while the
body streams in.

### Type resolution

The sniffer proves the format from the bytes. The extension may only **refine** a
generic type, never contradict it: content proves `text/plain`, and `.csv` narrows it
to `text/csv`. Short magic numbers are verified with extra structure (`BM` needs a valid
DIB header size; `MZ` needs a `PE\0\0` header or binary content; a ZIP polyglot needs a
structurally valid end record pointing at a central directory). This keeps text such as
"BMW cars…" from being called a bitmap.

### Names and archives are judged as they will be read

- **Filenames** are judged as sent *and* as later layers may decode them:
  percent-decoded, repeatedly, and NFKC-normalised. Storage backends, servers and
  Windows' "best fit" code-page mapping turn `shell%2ephp.png` or a fullwidth `ｐｈｐ`
  into `.php`, so a check that only sees the raw string can be bypassed.
- **Archive sizes are measured, not read.** The central directory is attacker-written.
  The cheap header checks (count, total, ratio, overlapping entries) still run first.
  Then every member is inflated as a stream, without storing it, and must produce
  exactly its declared size and CRC. Decompression stops one byte past the declared
  size, so a lying archive costs no more than it claims. Nested archives are walked the
  same way, to `max_depth`, within one shared budget.

## 3. Integrations

Every adapter fills the same three roles:

1. turn the framework's file object (`UploadedFile`, `FileStorage`, `UploadFile`) into
   an `Upload`;
2. validate at the point the framework offers for it; and
3. deliver the sanitized file, or turn the refusal into the framework's own error.

| | Django | Flask | FastAPI |
|---|---|---|---|
| Safety net for every upload | `FILE_UPLOAD_HANDLERS` | `UploadShield(app)` → `before_request` | `FastAPI(dependencies=[Depends(shield.all_files())])` |
| Per endpoint | `@validate_uploads` | `@validate_uploads` | `Depends(shield.file(...))` |
| When files are checked | while the body streams in | after Werkzeug parsed the body | after Starlette parsed the form |
| Inline form errors | `FileValidator`, `on_reject="field"` | `ShieldedFile` (WTForms) | n/a (API framework) |
| Refusal | `UploadRejected` → `handler400` | `UploadRejected` (`HTTPException`) | `HTTPException` |
| Audit hooks | Django signals | blinker signals | `on_rejected` callback |
| Configuration | `settings.UPLOADSHIELD` | `app.config["UPLOADSHIELD"]` | `UploadShield(...)` arguments |

The safety net never overrides a more specific policy. Django's handler and Flask's
request hook use the view's decorator; FastAPI's `all_files()` leaves the fields an
endpoint declares through its own `shield.file()`/`files()` dependencies to those.

### 3.1 Django

![When the CSRF check or the view first reads request.POST or request.FILES, Django's
parser streams the body through ValidatingUploadHandler: the name is checked on
new_file, size and type on the incoming chunks, the full policy on file_complete. The
view receives the sanitized file; a refusal goes to handler400.](images/django.svg)

Django parses request bodies lazily, through the upload handlers in
`FILE_UPLOAD_HANDLERS`. uploadshield's `ValidatingUploadHandler` sits in front of
Django's own storage handlers (memory or temporary file) and sees each file in three
steps:

1. `new_file()`: the **name** is checked before a single byte is stored.
2. `receive_data_chunk()`: **size limits** are enforced as data arrives, and once the
   first 8 KiB are in, the **type** is checked against the allow-list. (ZIP-based formats
   such as DOCX are only told apart once complete.) A refused file stops being passed
   on, so it is never stored in full.
3. `file_complete()`: the **full policy** runs (format checks, sanitizers), and the
   sanitized file is what the parser puts into `request.FILES`.

The policy comes from the view being called: `@validate_uploads`, a `VIEW_POLICIES` glob
on its URL name, or `DEFAULT_POLICY`. That works because `request.resolver_match` is set
before the CSRF check parses the body.

The other layers reuse the same engine, configuration and policies:

| Layer | Django hook | Runs when | Purpose |
|---|---|---|---|
| `ValidatingUploadHandler` | `FILE_UPLOAD_HANDLERS` | a parser stores a file: Django forms, admin, DRF (POST/PUT/PATCH, `FileUploadParser`) | the global safety net, streaming |
| `@validate_uploads` / `VIEW_POLICIES` | view attribute / URL name | read by the handler via `resolver_match` | per-view policy, mode, `on_reject` |
| `FileValidator` / `ValidatedFileField` | validators / form fields | `is_valid()`, `full_clean()`, serializer validation | per-field policy, inline errors |
| `ValidatingStorage` | `STORAGES` | every `storage.save()`, in or outside requests | last line of defense |
| `views.bad_request` | `handler400` | a refusal was raised | 413/415/400, JSON or HTML |

Results are memoised on each file object per policy. The handler, field validators and
the storage layer therefore validate a file once. Sanitized files carry their result,
so they are not re-encoded on save.

#### Why an upload handler

Validating `request.FILES` after Django has parsed the body would be simpler. Upload
handlers are the better primary mechanism, for four reasons:

- **Coverage.** Every parser stores files through `request.upload_handlers`: Django's
  own `request.POST`/`FILES`, and DRF's `MultiPartParser` and `FileUploadParser`.
  Checking `request.FILES` afterwards only sees what Django parsed for POST requests.
- **Laziness.** The handler runs only when something actually parses the body (the
  CSRF check or the view). Checking `request.FILES` up front forces every multipart
  POST to be parsed.
- **Streaming.** The handler sees the data as it arrives, so a disguised executable is
  refused without being written to disk. Measured with `runserver` and a 120 MiB
  executable named `report.pdf`: validating after parsing answered 413 after writing
  22.5 MiB of temporary files (only the size cap stopped it), while the handler answers
  415 after the first chunk with no temporary file at all (0.19 s vs 0.04 s). Under
  ASGI, Django spools the raw request body before any application code runs, so only
  the per-file copy is saved there.
- **No after-the-fact mutation.** Sanitized files are what the handler returns to the
  parser; nothing is swapped in `request.FILES` afterwards.

A refusal raises `UploadRejected`. It subclasses both `MultiPartParserError` and
`SuspiciousOperation`, like Django's own `TooManyFilesSent`, which is also raised during
parsing. Django answers through `handler400`, also with `DEBUG=True`, and marks the body
as unparseable, so code that catches the exception cannot read the files anyway. DRF's
multipart parser turns it into its standard 400 `ParseError`.

The handler finds the view's policy itself. If something reads the body before URL
routing (code in `MIDDLEWARE` reading `request.POST`), it resolves the URL on its own, so the
view's decorator and `VIEW_POLICIES` still decide. Decorators that routing cannot see
(DRF's `@api_view`, `method_decorator`) hand their policy to the handler before the
body is parsed; if the body was parsed earlier, the decorator validates the files again
with its own policy before the view runs. Field names DRF reads as lists (`photos[0]`,
`photos.0`) get the policy of their base field, and a raw body (`FileUploadParser`) is
the field `file`.

Projects that cannot change `FILE_UPLOAD_HANDLERS` yet can start with
`@validate_uploads` alone. Without the handler, it validates `request.FILES` before the
view runs. For bodies Django never parses itself (DRF's `PUT`/`PATCH` and raw uploads)
it installs the handler for that one request.

#### Presenting refusals

- Default (`ON_REJECT = "reject"`): the request is answered with 400/413/415.
- `on_reject="field"` (per view, or globally): the refused file is replaced by an empty
  `RejectedUpload`. Its `size` raises the precise `ValidationError`, and every Django and
  DRF file field reads `size` while cleaning. So plain forms, ModelForms, the admin and
  serializers all show the real reason next to the field, without library-specific form
  fields. The refused bytes never reach application code.
- `on_reject=callable`, e.g. `redirect_with_messages("gallery")`, rendered by
  `handler400`.

#### Adoption path for an existing project

1. Add the app, `FILE_UPLOAD_HANDLERS` and `handler400`, with `MODE = "report"`. Nothing
   is blocked; every would-be refusal is logged (with SHA-256) and signalled.
2. Watch the logs, then tune `POLICIES` and `VIEW_POLICIES`. These are globs on URL names
   (e.g. `"admin:*"`), so third-party view code needs no changes.
3. Switch to `MODE = "enforce"`. Add `ValidatingStorage` so that code paths outside
   requests (tasks, imports) are covered too.
4. Tighten single endpoints with decorators and fields with validators where a precise
   allow-list or inline form errors matter.

#### Cost and authorization

Validation runs while the body is parsed. For forms, that happens in
`CsrfViewMiddleware`, before view-level permission checks. Several things keep this
cheap:

- Cheap checks come first.
- Deep checks only run on files that passed them, within byte and pixel budgets.
- External scanners (ClamAV, YARA) are opt-in per policy.

To keep anonymous traffic away entirely, place
`django.contrib.auth.middleware.LoginRequiredMiddleware` (Django 5.1+) before
`CsrfViewMiddleware`, with `AuthenticationMiddleware` above both. Anonymous requests are
then redirected before any body is parsed.

### 3.2 Flask

![The UploadShield extension registers a before_request hook. Reading request.files makes
Werkzeug parse the whole body, capped by MAX_CONTENT_LENGTH. The hook picks the view's
policy, validates and sanitizes every file and replaces request.files; a refusal is an
UploadRejected HTTP error.](images/flask.svg)

`UploadShield(app)`, or `init_app(app)` in an application factory, reads
`app.config["UPLOADSHIELD"]` and registers a `before_request` hook. The hook runs for
every multipart request, whatever the method: Werkzeug fills `request.files` for `GET`
and `DELETE` bodies too.

- **Policy.** The view's `@validate_uploads` (functions, async views,
  `MethodView.decorators`), else the first `ENDPOINT_POLICIES` glob on the endpoint name
  (`"admin.*"` matches a blueprint), else `DEFAULT_POLICY`. `@skip_upload_validation`
  exempts a view.
- **Parsing.** Reading `request.files` makes Werkzeug parse the whole body before the
  hook sees any file. `MAX_CONTENT_LENGTH` is therefore the limit that stops oversized
  requests early, with Werkzeug's own 413.
- **Validation.** Each `FileStorage` is validated, and the result is memoised per policy
  on the object. A file input left empty (no name, no content) is skipped. A part
  without a name but with content is refused.
- **Delivery.** `request.files` is replaced by sanitized `FileStorage` objects that carry
  the detected content type. Originals that were replaced are closed straight away;
  Werkzeug closes the rest when the request ends.
- **Refusal.** `UploadRejected` is a Werkzeug `HTTPException` with status 400, 413 or
  415. It renders as JSON for API clients and as escaped HTML otherwise. You can
  customise it app-wide with `@app.errorhandler(UploadRejected)`, or per view with
  `validate_uploads(..., on_reject=...)`. The blinker signals `upload_validated` and
  `upload_rejected` feed audit logs, and `get_upload_results()` gives views the outcome.

Without the extension, `@validate_uploads` validates inside its own wrapper, so views
can adopt it one at a time. For HTML forms, the WTForms validator `ShieldedFile`
validates and sanitizes a single field and turns refusals into ordinary form errors.

### 3.3 FastAPI

![Starlette parses the form. The optional app or router dependency all_files() checks
every file field without a dependency of its own and sets the detected content type. An
endpoint dependency shield.file(policy) validates its field and sanitizes the UploadFile
in place. Refusals are HTTPExceptions.](images/fastapi.svg)

FastAPI's extension point is dependency injection. `UploadShield(...)` takes its
configuration as arguments (`policies`, `default_policy`, `mode`, `expose_details`,
`messages`, `on_rejected`) and builds dependencies from it.

- **`shield.file(policy, alias=...)` / `shield.files(...)`** declare a `File()` parameter
  for their form field. They validate in Starlette's thread pool, so the event loop
  stays free, and sanitize the `UploadFile` in place: sanitized bytes, the detected
  content type and, with `sanitized_images`, a random name. The endpoint's own
  parameter for the field and `request.form()` hold the same object, so nothing can
  reach the unsanitized original.
- **`shield.all_files(policy)`** goes into `FastAPI(dependencies=...)` or a router.
  - It validates every file field the endpoint does not validate itself. It finds those
    in the route's dependency tree, so the endpoint's own policy always wins. File
    inputs left empty are skipped.
  - Starlette's form data is immutable, so `all_files()` cannot swap files. It sets the
    detected content type on each passing `UploadFile` instead; use `shield.file()`
    where you want sanitized files.
  - A field taken by `shield.file()` exempts only the part FastAPI hands it (the last
    one); further parts under the same name are checked. A part without a filename
    sent to a `File()` parameter is checked too, and refused for its missing name:
    FastAPI would hand its content to a `bytes` parameter.
  - It decides "multipart" the way Starlette's parser does (any case and spacing), and
    leaves WebSocket routes alone. Mounted sub-applications (`app.mount(...)`) and
    plain Starlette routes are separate ASGI apps that never run the outer app's
    dependencies: give each its own `all_files()`.
  - If the endpoint declares no form parameters, `all_files()` parses the form itself,
    and closes it once the response is done.
- **Refusal.** An `HTTPException` with status 400, 413 or 415 and
  `{"detail": {"error": "upload_rejected", ...}}`. The `on_rejected(request, rejected)`
  callback (sync or async) feeds audit logs, also in `"report"` mode.

FastAPI parses the form before any dependency runs, so request size limits belong in
the ASGI server or the proxy in front of it.

### Why only Django streams

Django's upload handlers are a public, documented streaming API. Werkzeug's per-file
hook (`Request._get_file_stream`) is private and deprecated on its main branch, and
Starlette has none. So Flask and FastAPI validate a file once it has been received. All
checks and sanitizers still apply, but early abort does not: requests must be capped
with `MAX_CONTENT_LENGTH` or at the server or proxy. Building on a private, deprecated
hook would trade a small efficiency gain for breakage on the next Werkzeug release.

### 3.4 Command line

`uploadshield` (also `python -m uploadshield`) runs the engine on files on disk or on
standard input. It uses the standard library only (argparse), so the core install
ships it.

- **`scan`: is this dangerous to accept?** It builds a policy at run time from the type
  registry:
  - It accepts every registered format except executables and HTML, which are dangerous
    as uploads whatever they contain.
  - Archives the checks cannot open (gzip, tar, 7z, ...) are left out, so they are
    reported as *not verified* instead of passing uninspected.
  - Names are judged only for danger: hidden or extensionless names are fine.
  - There is no size limit; a file too large for a check is *not verified*, never
    skipped. It does not sanitize.
- **`validate`: what would this policy do?** It runs the policy unchanged (built-in,
  dotted path, or from Django settings with `--django`). It then lines up
  `policy.pipeline` with `checks_run` to show each check as passed, failed, not
  applicable, not run after a fail-fast stop, or inactive for want of an extra.
- **Verdicts.** `cli/_verdicts.py` maps every `Code` to *dangerous*, *refused* or *not
  verified*, with a meaning, a typical cause and the option that relaxes it (`explain`).
  A test makes sure no code is missing. Some verdicts depend on the file: a type
  refusal is dangerous for executables and HTML, and a PDF that cannot be decoded is
  not verified. A file takes its worst verdict.
- **Files, not surprises.**
  - Directories are walked in sorted order.
  - Links named on the command line are followed; links inside directories are
    skipped unless `--follow-symlinks`, with cycle detection.
  - Files are opened non-blocking and checked with `fstat`, so FIFOs and devices are
    skipped instead of hanging the scan.
  - Standard input is spooled, so `--save` still has the bytes.
- **Untrusted names.**
  - Names are printed with control characters, bidi overrides and undecodable bytes
    escaped.
  - Engine logs (tracebacks of crashed checks) go to a handler of the command's own,
    shown with `-v`, so they never interleave with the report.
  - Code is imported from the current directory only when asked for (`--django`, a
    dotted `--policy`), and then after installed packages: a scanned folder cannot
    shadow Pillow.
- **Exit status** 0 (clean or accepted), 1 (anything else), 2 (usage or setup errors,
  checked before the first file is read: missing paths, unknown policies, clamd not
  answering, YARA rules that do not compile, missing extras), 130 (interrupted; the
  summary so far is still printed). `--json` prints one document with a `schema` number.

## 4. Design rationale

### What frameworks already do

Django ships building blocks, but no content-aware upload policy. Flask and FastAPI
offer even less: neither looks at file contents, and both hand the client's raw
filename to the application ([Concepts](concepts.md#the-problem) compares all three).

| Django feature | What it does | What it does not do |
|---|---|---|
| `FileExtensionValidator` | checks the *name* ends in an allowed extension | look at the content (`evil.php` renamed to `.png` passes) |
| `forms.ImageField` | opens the file with Pillow, sets `content_type` from the decoded format | anything for non-images; strip metadata; stop polyglots (a valid GIF with a ZIP appended passes) |
| `UploadedFile.name` / storage `get_valid_name` | strips path components, NUL bytes, truncates | catch `shell.php.jpg`, `.htaccess`, `web.config`, Windows device names |
| `DATA_UPLOAD_MAX_MEMORY_SIZE` | caps non-file form data | limit file sizes. A 10 GB upload is streamed to a temp file before any validator runs |
| `DATA_UPLOAD_MAX_NUMBER_FILES` | caps the file count | anything per file |
| `FILE_UPLOAD_HANDLERS` | lets you hook into streaming parsing | anything out of the box |

The gaps are all the same kind: frameworks trust what the client *says* (name,
`Content-Type`) and offer no single place to declare "this endpoint accepts these
formats". That is the gap this library fills.

### Threat model

Uploads are attacker-controlled bytes plus attacker-controlled metadata. What goes
wrong in practice:

1. **Executable content stored where something executes it.** For example a PHP or JSP
   web shell, or a server config file (`.htaccess`, `web.config`, `.user.ini`). It is
   often disguised (`shell.php.jpg`, `shell.asp;.jpg`, `a.aspx::$DATA`).
2. **Script content served from your origin.** HTML, SVG and XML uploads become stored
   XSS. So does a file whose extension makes browsers render it as HTML.
3. **Malicious documents.** Office macros, DDE fields, remote templates, and PDFs with
   JavaScript, launch actions or embedded files.
4. **Parser attacks.** Decompression bombs (pixel, ZIP and XML), path traversal inside
   archives ("zip slip"), symlinks, XXE, and malformed files that crash parsers.
5. **Polyglots.** Files that are valid in two formats at once, such as a GIF that is also
   a JAR, or a JPEG with a PDF inside.
6. **Privacy leaks.** EXIF GPS coordinates and camera serials in user images.
7. **Resource exhaustion.** Huge files, or many files in one request.

Derived requirements:

- Decide by **content**, never by name or header alone.
- Use an **allow-list** of formats per endpoint, never a deny-list.
- The **name and the content must agree**, because servers and browsers act on the name.
- **Fail closed**: a crashing check, an unreachable scanner or an un-inspectable
  (encrypted) file is a refusal, not a pass.
- Run cheap checks before expensive ones, and never hand a file that already failed a
  basic check to a complex parser (Pillow, zipfile).
- Optionally **disarm**: re-encode media and replace names, so whatever slipped through
  cannot survive.

### What was deliberately left out

- **Response monitoring.** Version 1.x scanned every response for `phpinfo()` and Django
  debug pages. That is unrelated to uploads, surprising global behaviour, and the real
  fix is `DEBUG = False`.
- **QuickSand, pdfid and oletools as hard dependencies.** Built-in PDF and Office checks
  cover the common attack classes without unmaintained dependencies. The `YaraRules`
  check can load QuickSand's or any other rule set.
- **Random pixel noise on images.** Re-encoding already destroys hidden payloads. Noise
  only degrades legitimate images.
- **Filesystem JSON upload logs.** A library should not write to `./uploadlogs`. Use the
  signals or the `uploadshield` logger, which carries structured
  `extra={"upload": {...}}` data.

### Why Magika is a veto, not a sniffer

Google Magika classifies 200+ formats and is strongest where magic numbers do not exist:
telling CSV from Python, PowerShell or batch. It is available as the opt-in
`MagikaCheck`.

It is deliberately not a `Sniffer`, because a sniffer decides what a file *is* and
therefore what gets accepted. Magika is probabilistic, it only reads the first and last
KiB (so an attacker can steer it by controlling those bytes), it makes no claims about
adversarial robustness, and its answers change with model upgrades. Used only to
*refuse* (content it confidently calls code, executables or active markup), its errors
cost availability but never let a file through that the deterministic layers would
refuse.

## 5. Known limits

- Detection is format-aware, not an antivirus. For hostile environments, add
  `ClamAV(...)` and/or `YaraRules(...)` to `checks`.
- PDF inspection decodes object streams, where actions can hide, within a byte budget:
  Flate (any window, zlib or raw), ASCIIHex and ASCII85. An object stream in any other
  encoding, or with a predictor, is refused rather than skipped. Page content and image
  streams are not decoded: they hold drawing operators and pixels, not objects.
- Legacy OLE2 Office files (`.doc`/`.xls`): VBA macros are detected, XLM (Excel 4.0)
  macros are not. These formats are not in any preset.
- Active PDF and Office content is refused, not disarmed. Use a dedicated CDR product if
  you must accept it.
- Django's upload handler covers every parser that uses Django's upload handlers.
  Parsers that bypass them entirely (e.g. base64 strings in JSON bodies) are covered by
  `FileValidator` on the serializer field and by `ValidatingStorage` when saved.
- A Django view that replaces `request.upload_handlers` itself (as Django's docs show
  for progress bars) removes the handler for that request. Wrap your handlers instead:
  `[ValidatingUploadHandler(request, inner=[MyHandler(request)])]`. `ValidatingStorage`
  still validates whatever such a view saves.
- Async Django views that read `request.FILES` directly run the checks on the event
  loop, because Django parses request bodies synchronously. Wrap the access in
  `sync_to_async` if uploads are large.
- Flask and FastAPI validate after the body is parsed; cap request sizes in front of
  them. Parsing (and in Flask and FastAPI, validation) happens before your view, so
  authenticate first, as [OWASP.md](OWASP.md) describes: anonymous requests then cost
  nothing.

---

The diagrams are generated by [images/diagrams.py](images/diagrams.py):
`uv run python docs/images/diagrams.py`.
