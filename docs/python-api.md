# Python API

The engine is plain Python and imports no web framework. Use it directly to validate
files in background jobs, management commands, e-mail pipelines or tests; to write
your own checks, sanitizers and file types; or to integrate another web framework.

**On this page**

- [Validating a file](#validating-a-file)
- [Results](#results)
- [InspectedFile: what checks see](#inspectedfile-what-checks-see)
- [Writing a check](#writing-a-check)
- [Writing a sanitizer](#writing-a-sanitizer)
- [Types and sniffers](#types-and-sniffers)
- [Registering a file type](#registering-a-file-type)
- [Integrating another framework](#integrating-another-framework)
- [Where to import things](#where-to-import-things)

## Validating a file

```python
from uploadshield import Upload, presets, validate

with open("upload.bin", "rb") as fh:
    result = validate(Upload(fh, name="upload.pdf"), presets.PDF)
result.ok, result.codes, result.file_type
```

`validate(upload, policy, *, sanitize=True) -> ValidationResult`

- runs the policy's [pipeline](https://github.com/IV1T3/uploadshield/blob/main/docs/concepts.md#the-pipeline) and, if every check passes and
  `sanitize` is true, its sanitizers;
- **never raises** for bad input: a check that crashes or runs out of budget becomes
  the violation `check_failed`, a sanitizer that fails becomes `sanitization_failed`
  (see [Fail closed](https://github.com/IV1T3/uploadshield/blob/main/docs/concepts.md#fail-closed));
- re-checks what sanitizers produced (new names against the filename rules, new
  content against the content checks);
- leaves your stream open and at the position where it was. Non-seekable streams are
  copied to a temporary file first (in memory up to 8 MiB), and that copy is closed.

**`Upload`** holds the raw facts about one file. Only the stream and the name are
required; the name and the declared type are untrusted client data.

| Field | Type | Default | Description |
|---|---|---|---|
| `stream` | binary file object | required | The content. |
| `name` | `str` | required | The client's filename. |
| `size` | `int \| None` | `None` | Size in bytes; measured from the stream when `None`. |
| `declared_type` | `str \| None` | `None` | The client's `Content-Type`. |
| `field` | `str \| None` | `None` | The form field, for reports. |

`Upload.from_bytes(data, name, *, declared_type=None, field=None)` builds one from
bytes, which is handy in tests:

```python
from uploadshield import Upload, presets, validate

result = validate(Upload.from_bytes(b"%PDF-1.4\n%%EOF\n", "a.pdf"), presets.PDF)
assert result.ok
```

## Results

**`ValidationResult`**

| Member | Description |
|---|---|
| `ok` | `True` if there are no violations |
| `codes` | tuple of the violations' codes |
| `violations` | tuple of `Violation` |
| `name`, `field`, `size`, `declared_type` | the upload's facts |
| `file_type` | the `FileType` detected from the content, or `None` |
| `checks_run` | names of the checks that applied and ran, in order |
| `sanitized` | a `SanitizedFile`, or `None` if nothing was sanitized |
| `as_dict(include_details=False)` | `{field, name, ok, errors: [...]}`; with details also `size`, `detected_type`, `declared_type`, `checks_run`, `sanitized` (names of the sanitizers applied) |

**`Violation`**

| Member | Description |
|---|---|
| `code` | stable identifier, e.g. `"type_not_allowed"` (a `Code` for built-in checks) |
| `message` | user-safe text |
| `check` | the `name` of the check that reported it |
| `details` | read-only mapping with diagnostic data (see [Checks](https://github.com/IV1T3/uploadshield/blob/main/docs/checks.md)) |
| `as_dict(include_details=False)` | `{code, message}`, plus `check` and `details` |

**`SanitizedFile`**

| Member | Description |
|---|---|
| `name` | the new filename |
| `content_type` | the detected MIME type of the output |
| `data` | the new content as bytes, or `None` if only the name changed (keep the original content) |
| `applied` | names of the sanitizers that ran, in order |

Storing a validated upload:

```python
import shutil
from pathlib import Path

from uploadshield import Upload, presets, validate


def store(fh, client_name: str, target: Path) -> Path | None:
    result = validate(Upload(fh, name=client_name), presets.SANITIZED_IMAGES)
    if not result.ok:
        return None
    sanitized = result.sanitized
    destination = target / (sanitized.name if sanitized else client_name)
    with destination.open("xb") as out:
        if sanitized is not None and sanitized.data is not None:
            out.write(sanitized.data)
        else:
            fh.seek(0)
            shutil.copyfileobj(fh, out)
    return destination
```

## InspectedFile: what checks see

Checks receive an `InspectedFile`: a read-only, lazily analysed view of the upload.
Expensive facts are computed at most once and shared between checks, and every read
restores the stream position.

| Member | Description |
|---|---|
| `name`, `size`, `declared_type`, `field` | the upload's facts (`name` is `""` if none was sent) |
| `upload` | the original `Upload` |
| `head(n=8192)` | the first `n` bytes |
| `tail(n)` | the last `n` bytes |
| `read(limit)` | the whole content; raises `ContentTooLargeError` if the file is larger than `limit` (the engine reports that as `check_failed` with reason `too_large`) |
| `iter_chunks(chunk_size=1 MiB)` | the content in chunks, for streaming checks |
| `open()` | context manager yielding the stream positioned at the start |
| `stream` | the (seekable) stream |
| `extensions` | every lowercase dotted suffix: `"a.tar.GZ"` gives `(".tar", ".gz")` |
| `extension` | the last one, or `""` |
| `detected_type` | the `FileType` the sniffer found in the content, or `None` |
| `file_type` | `detected_type`, narrowed by the extension where the content cannot tell (`text/plain` named `.csv` is `text/csv`) |
| `sha256` | hex digest of the content |
| `cache` | a `dict` checks can use to share parse results for this file |

## Writing a check

A check is a frozen dataclass that subclasses `Check`. Its fields are its options.

```python
from collections.abc import Iterator
from dataclasses import dataclass

from uploadshield import InspectedFile, Violation, presets
from uploadshield.checks import Check


@dataclass(frozen=True)
class NoPortraitImages(Check):
    name = "no_portrait"
    requires = ("PIL",)

    min_ratio: float = 1.0  # an option, set per policy

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None and file.file_type.category == "image"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        from PIL import Image

        with file.open() as fh, Image.open(fh) as im:
            if im.width / im.height < self.min_ratio:
                yield self.violation(
                    "portrait", "Please upload a landscape image.", width=im.width, height=im.height
                )


POLICY = presets.IMAGES.extend(checks=[NoPortraitImages()], name="landscape_images")
```

The rules:

- **Class attributes without annotations** describe the check: `name` (shown in
  `checks_run` and violations; required), `stage` (`"name"`, `"size"`, `"type"` or
  `"content"`, the default; Django runs `name`, `size` and `type` checks while a file is
  still streaming), and `requires` (modules it needs; Django's system check
  `uploadshield.E002` reports missing ones for checks added through `checks=` and for
  sanitizers).
- **Annotated attributes are options** (dataclass fields) and need defaults.
- **`applies(file)`** decides whether the check is relevant (default: always). Checks
  that do not apply are not run and not listed in `checks_run`.
- **`run(file)`** yields violations, built with `self.violation(code, message,
  **details)`. Codes are strings; reuse a built-in `Code` where one fits.
- **Exceptions are fine**: anything raised becomes `check_failed` (fail closed), and the
  traceback is logged. Use `file.read(limit)` or `file.iter_chunks()` to stay within a
  memory budget.
- **Keep it hashable**: use tuples and frozensets for collection options, so policies
  stay hashable values.
- **Django migrations**: a check used in a model field's policy is serialized by its
  import path. Set `_deconstruct_module = "myproject.checks"` if the class is importable
  from somewhere other than its defining module.

Add your check to a policy with `checks=` or `policy.extend(checks=[...])`; it runs
after the content checks.

## Writing a sanitizer

A sanitizer is a frozen dataclass that subclasses `Sanitizer` and returns a
`Replacement` with new content, a new name, or both (`None` keeps the original):

```python
from dataclasses import dataclass

from uploadshield import InspectedFile, presets
from uploadshield.core.check import Replacement
from uploadshield.sanitizers import Sanitizer


@dataclass(frozen=True)
class LowercaseName(Sanitizer):
    name = "lowercase_name"

    def sanitize(self, file: InspectedFile) -> Replacement:
        return Replacement(name=file.name.lower())


POLICY = presets.PDF.replace(sanitizers=(LowercaseName(),), name="pdf_lowercase")
```

Sanitizers run only after every check passed, in order, each on the previous one's
output. Their output is checked again: new names against the filename rules, new
content against the content checks. If a sanitizer raises, or its output has a
different type than the input, the file is refused (`sanitization_failed`).

## Types and sniffers

The type of a file is detected from its content by the policy's `sniffer`:

| Sniffer | Description |
|---|---|
| `BuiltinSniffer()` | The default: pure Python, deterministic, no dependencies. |
| `MagicSniffer(head_size=64 * 1024)` | Uses libmagic (`uv add "uploadshield[magic]"`, plus the system library). Results that are not [registered types](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md#registered-file-types) count as unidentified. |
| `ChainedSniffer(sniffers)` | Tries several sniffers in order; the first identification wins. Pass a **tuple**, so the policy stays hashable. |

```python
from uploadshield import BuiltinSniffer, ChainedSniffer, MagicSniffer, presets

WITH_LIBMAGIC = presets.DEFAULT.replace(
    name="default_libmagic", sniffer=ChainedSniffer((BuiltinSniffer(), MagicSniffer()))
)
```

A sniffer is any object with `sniff(file: InspectedFile) -> FileType | None` (the
`Sniffer` protocol); make it a frozen dataclass so policies stay hashable.

## Registering a file type

To accept a format uploadshield does not know, register a `FileType` and teach a
sniffer to recognise it:

```python
from dataclasses import dataclass

from uploadshield import (
    BuiltinSniffer,
    ChainedSniffer,
    FileType,
    InspectedFile,
    Policy,
    Upload,
    get_type,
    register_type,
    validate,
)

register_type(FileType(mime="application/x-acme-model", extensions=(".acm",), label="ACME model"))


@dataclass(frozen=True)
class AcmeSniffer:
    def sniff(self, file: InspectedFile) -> FileType | None:
        return get_type("application/x-acme-model") if file.head(4) == b"ACM1" else None


MODELS = Policy(
    name="models",
    allowed_types={"application/x-acme-model"},
    sniffer=ChainedSniffer((AcmeSniffer(), BuiltinSniffer())),
)
assert validate(Upload.from_bytes(b"ACM1 data", "part.acm"), MODELS).ok
```

`FileType` fields:

| Field | Default | Description |
|---|---|---|
| `mime` | required | Canonical lowercase MIME type. |
| `extensions` | required | Lowercase extensions with the dot; the first is canonical (used by `RandomizeFilename`). |
| `label` | required | Human-readable name, shown in messages. |
| `aliases` | `()` | Other MIME strings clients send for it. |
| `container` | `None` | `"zip"` or `"ole"` if the format is built on one, so `ArchiveSafety` and `OfficeMacros` inspect it. |
| `is_text` | `False` | Text formats get `EmbeddedContent`'s text scan. |
| `parent` | `None` | A type the content proves, which this type refines by extension (as `text/csv` refines `text/plain`). |
| `executable` | `False` | Executables are never matched by wildcards. |

`register_type()` is global and raises `ValueError` if a different type is already
registered under the same MIME type. Register types at import time (for example in
the module that defines your policies). `get_type(mime)` returns a registered type or
`None`.

## Integrating another framework

`uploadshield.web` holds what every adapter shares, without importing a framework.
An integration for another framework turns its file objects into `Upload`s, calls
`validate()`, and uses these helpers for the response and the log:

| Helper | Description |
|---|---|
| `resolve_policy(ref, policies)` | A `Policy` from a `Policy`, a registered name or a dotted path (`PolicyLookupError` otherwise). |
| `status_code_for(results)` | 413, 415 or 400 for a list of refused results. |
| `rejection_payload(results, *, include_details=False, messages=None, fields=None)` | The [error payload](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#the-error-payload) as a `dict`. |
| `wants_json(accept, requested_with=None)` | Content negotiation: JSON or HTML. |
| `html_rejection(payload)` | A minimal escaped HTML page for the payload. |
| `json_safe(value)` | Details made JSON-compatible (sets become sorted lists, bytes hex). |
| `log_rejection(result, *, field, policy_name, mode, path=None, sha256=None)` | The standard [log record](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#the-log-record). |
| `sha256_of(stream)` | Hex SHA-256 of a seekable stream, restoring its position. |
| `is_unused_file_input(name, stream)` | `True` for an empty `<input type="file">` (no name, no content). |

```python
from uploadshield import Upload, presets, validate, web


def check_request_files(files, accept_header):
    """files: (field, filename, content_type, stream) tuples from your framework."""
    results = [
        validate(Upload(stream, name or "", declared_type=ctype, field=field), presets.DEFAULT)
        for field, name, ctype, stream in files
        if not web.is_unused_file_input(name, stream)
    ]
    rejected = [r for r in results if not r.ok]
    for result in rejected:
        web.log_rejection(result, field=result.field, policy_name="default", mode="enforce")
    if rejected:
        return web.status_code_for(rejected), web.rejection_payload(rejected)
    return None
```

To check files while they are still arriving (as the Django handler does),
`uploadshield.engine.preflight(policy, *, stages, name, head=b"", size=0,
declared_type=None, field=None)` runs only the checks of the given stages (`"name"`,
`"size"`, `"type"`) against what has arrived so far.

## Where to import things

| Name | Import from |
|---|---|
| `validate`, `Upload`, `InspectedFile`, `Policy`, `ValidationResult`, `SanitizedFile`, `Violation`, `Code`, `FileType`, `register_type`, `get_type`, `BuiltinSniffer`, `MagicSniffer`, `ChainedSniffer`, `Sniffer`, `KB`, `MB`, `GB`, `KiB`, `MiB`, `GiB` | `uploadshield` |
| `presets` (`DEFAULT`, `IMAGES`, ...), `checks`, `sanitizers` | `uploadshield` (modules) |
| every check, `Check`, the constants | `uploadshield.checks` |
| `ReencodeImage`, `RandomizeFilename`, `SafeFilename`, `Sanitizer` | `uploadshield.sanitizers` |
| `Replacement`, `Stage` | `uploadshield.core.check` |
| `ContentTooLargeError`, `HEAD_SIZE` | `uploadshield.core.upload` |
| `all_types`, `resolve_mime`, `types_for_extension`, `format_size` | `uploadshield.core.types` |
| `preflight`, `SanitizationError` | `uploadshield.engine` |
| `clamd_ping`, `ClamdError` | `uploadshield.checks.scanners` |
| the helpers above | `uploadshield.web` |
| the adapters | `uploadshield.django`, `uploadshield.flask`, `uploadshield.fastapi` |
