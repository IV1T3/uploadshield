# Refusals: codes, responses and logs

When a file is refused, uploadshield reports it in four ways: a stable **violation
code**, an **HTTP response** (400, 413 or 415), a **log record**, and a framework
**hook** (signals or a callback). This page is the reference for all four, across
Django, Flask, FastAPI and the command line.

**On this page**

- [Violation codes](#violation-codes)
- [HTTP status codes](#http-status-codes)
- [The error payload](#the-error-payload)
- [Custom messages and translations](#custom-messages-and-translations)
- [Exposing details](#exposing-details)
- [The log record](#the-log-record)
- [Hooks per framework](#hooks-per-framework)

## Violation codes

Codes are stable: they are part of the public API (`uploadshield.Code`, a `StrEnum`)
and safe to match in client code and tests. Messages are for people and may change.

| Code | Reported by | Status | CLI verdict | Meaning |
|---|---|---|---|---|
| `file_empty` | `size` | 400 | refused | The file has no content. |
| `file_too_large` | `size` | 413 | refused | The file is larger than the policy's `max_size`. |
| `filename_invalid` | `filename` | 400 | dangerous | The name contains path separators, `..`, control or bidi characters, or characters Windows forbids. |
| `filename_too_long` | `filename` | 400 | refused | The name is longer than `FilenameCheck.max_length` bytes (UTF-8). |
| `filename_hidden` | `filename` | 400 | refused | The name starts with a dot. |
| `filename_reserved` | `filename` | 400 | dangerous | The name is a Windows device name (`CON`, `NUL`, `COM1`, ...), a server configuration file (`.htaccess`, `web.config`) or an 8.3 short name (`PROGRA~1`). |
| `filename_dangerous_extension` | `filename` | 400 | dangerous | An extension in the name makes servers or clients run the file (`.php`, `.jsp`, `.exe`, `.bat`, ...), wherever it appears (`shell.php.png`). |
| `filename_missing_extension` | `filename` | 400 | refused | The name has no extension. |
| `type_unknown` | `type` | 415 | not verified | The content matches no file format uploadshield knows. |
| `type_not_allowed` | `type` | 415 | refused* | The format detected from the content is not in the policy's `allowed_types`. |
| `extension_mismatch` | `extension` | 415 | refused | The name's extension does not belong to the format detected from the content. |
| `content_mismatch` | `magika` | 415 | dangerous | Magika's model identifies the content as a forbidden format. |
| `declared_type_mismatch` | `declared_type` | 415 | refused | The client's `Content-Type` header contradicts the content. |
| `image_corrupt` | `image` | 400 | refused | Pillow cannot decode the image completely. |
| `image_too_large` | `image` | 400 | dangerous | The image's dimensions, frame count or total pixels exceed the limits. |
| `pdf_active_content` | `pdf` | 400 | dangerous* | The PDF contains JavaScript, launch actions, embedded files or forms that submit data, or it is encrypted, or stores objects in a form that cannot be checked. |
| `archive_corrupt` | `archive` | 400 | refused | The ZIP container cannot be read consistently. |
| `archive_unsafe_path` | `archive` | 400 | dangerous | A member would be extracted outside the target directory (`../`, absolute paths, drive letters) or is a symbolic link. |
| `archive_bomb` | `archive` | 400 | dangerous | The archive expands far beyond its size, has too many members, overlapping entries or too deep nesting. |
| `archive_encrypted` | `archive` | 400 | not verified | Encrypted members cannot be inspected. |
| `archive_dangerous_member` | `archive` | 400 | dangerous | A member has a dangerous extension or a server configuration name (`shell.php`, `.htaccess`, ...). |
| `office_macros` | `office` | 400 | dangerous | The document contains macros, ActiveX controls or DDE fields that run commands. |
| `office_external_reference` | `office` | 400 | dangerous | The document loads a remote template or object when it is opened. |
| `svg_active_content` | `svg` | 400 | dangerous | The SVG contains scripts, event handlers, `javascript:` links, `foreignObject`, entities or external references. |
| `xml_dtd` | `xml` | 400 | dangerous | The XML declares a DTD, which enables entity expansion and external entities. |
| `embedded_code` | `embedded` | 400 | dangerous | Code (PHP, script tags, JSP, SSI) is hidden inside the file. |
| `polyglot` | `embedded` | 400 | dangerous | The file is also a valid ZIP archive or PDF document. |
| `malware_detected` | `clamav` | 400 | dangerous | ClamAV found a malware signature. |
| `signature_match` | `yara` | 400 | dangerous | One of your YARA rules matched. |
| `scanner_unavailable` | `clamav` | 400 | not verified | An external scanner could not be reached or refused the file. |
| `sanitization_failed` | `sanitizer` | 400 | not verified | A sanitizer could not process the file, or what it produced failed the checks. |
| `check_failed` | any check | 400 | not verified | A check could not finish: the file needs more memory than it may use (`details["reason"] == "too_large"`), or the check crashed (`"crashed"`). |

"Reported by" is the check's `name` (the `check` field of the violation). The
`details` of every code are listed with its check in [Checks](checks.md). The "CLI
verdict" column is how [`uploadshield scan`](cli.md#verdicts) summarizes the code;
those marked * depend on the file. `type_not_allowed` is dangerous when the content is
an executable or HTML; otherwise it is "refused" by `uploadshield validate` and "not
verified" by `uploadshield scan` (a format the scan cannot open, such as a 7-Zip
archive). `pdf_active_content` is "not verified" when the PDF is encrypted or cannot be
decoded. In a scan, `type_unknown` on an empty file is clean. `uploadshield explain CODE` prints the meaning, a
typical cause and the option that allows it.

Custom checks may report their own codes (any string).

## HTTP status codes

One status is chosen for the whole request, from the codes of every refused file:

| Status | When |
|---|---|
| **413** Payload Too Large | every violation is `file_too_large` |
| **415** Unsupported Media Type | every violation is about what the file *is*: `type_not_allowed`, `type_unknown`, `extension_mismatch`, `content_mismatch`, `declared_type_mismatch` |
| **400** Bad Request | anything else, including a mix of the above |

## The error payload

All three adapters send the same structure. As JSON:

```json
{
  "error": "upload_rejected",
  "message": "The upload was rejected.",
  "files": [
    {
      "field": "file",
      "name": "cat.png",
      "errors": [
        {
          "code": "type_not_allowed",
          "message": "PHP script files are not allowed."
        }
      ]
    }
  ]
}
```

`files` lists every refused file of the request: its form `field`, the client's
`name`, and one entry per violation.

How each integration delivers it:

| | JSON when | Otherwise | Customise with |
|---|---|---|---|
| **Django** | `Accept` contains `json` but not `text/html`, or `X-Requested-With: XMLHttpRequest` | HTML, rendered from the template `uploadshield/rejected.html` | `REJECTION_HANDLER`, `on_reject=`, your own template; see [Django](django.md#refusals) |
| **Flask** | the same rule | a minimal escaped HTML page (no template) | `@app.errorhandler(UploadRejected)`, `on_reject=`; see [Flask](flask.md#refusals) |
| **FastAPI** | always | | an exception handler for `HTTPException`; see [FastAPI](fastapi.md#refusals) |
| **CLI** | `--json` | human-readable report | see [CLI](cli.md#json-output) |

FastAPI wraps the payload in `HTTPException.detail`, so the response body is
`{"detail": {"error": "upload_rejected", ...}}`. A client sending `Accept: */*` (curl's
default) gets HTML from Django and Flask.

Django's default HTML, from the shipped template (context variable `rejection`, the
payload above):

```html
<h1>The upload was rejected.</h1>
<ul>
  <li><strong>cat.png</strong>
    <ul><li>PHP script files are not allowed.</li></ul>
  </li>
</ul>
<p><a href="javascript:history.back()">Go back</a></p>
```

Flask's HTML is a single line:
`<h1>The upload was rejected.</h1><ul><li>cat.png: PHP script files are not allowed.</li></ul>`.

## Custom messages and translations

Replace the message of any code. Values may be lazy translation strings; they are
converted with `str()` when the response is built.

```python
from django.utils.translation import gettext_lazy as _

UPLOADSHIELD = {
    "MESSAGES": {
        "type_not_allowed": _("Please upload a PDF or an image."),
        "file_too_large": _("The file is too large."),
    },
}
```

| Integration | Where |
|---|---|
| Django | `UPLOADSHIELD["MESSAGES"]`: used in responses, `RejectedUpload` form errors and `redirect_with_messages`. |
| Flask | `app.config["UPLOADSHIELD"]["MESSAGES"]`: used in responses and `ShieldedFile` form errors. |
| FastAPI | `UploadShield(messages={...})`. |

Messages are never applied to log records; logs keep the original message.

## Exposing details

By default, clients only see codes and messages. Detection details (the detected
type, matched signatures, member names) stay in your logs, because they help
attackers probe your checks. For debugging, or for trusted internal clients, enable
them: `UPLOADSHIELD["EXPOSE_DETAILS"] = True` (Django and Flask) or
`UploadShield(expose_details=True)` (FastAPI). Each error then also has `check` and
`details`, and each file `size`, `detected_type`, `declared_type`, `checks_run` and
`sanitized`:

```json
{
  "error": "upload_rejected",
  "message": "The upload was rejected.",
  "files": [
    {
      "field": "avatar",
      "name": "cat.png",
      "errors": [
        {
          "code": "type_not_allowed",
          "message": "PHP script files are not allowed.",
          "check": "type",
          "details": {
            "detected_type": "application/x-httpd-php",
            "declared_type": "image/png"
          }
        }
      ],
      "size": 30,
      "detected_type": "application/x-httpd-php",
      "declared_type": "image/png",
      "checks_run": ["size", "filename", "type"],
      "sanitized": []
    }
  ]
}
```

## The log record

Every refusal by a request-level integration (Django's handler and decorators, Flask's
hook and decorator, FastAPI's dependencies) is logged as a **WARNING** on the
`uploadshield` logger:

```
Upload rejected: field='file' name='cat.png' type=application/x-httpd-php codes=type_not_allowed
```

In `report` mode the line starts with `Upload would be rejected (report mode)`. Field
and file names are logged with `repr()`, so control characters in them cannot forge
log lines.

The record also carries structured data in `record.upload` (`extra={"upload": ...}`),
for JSON log formatters and audit pipelines:

| Key | Content |
|---|---|
| `field` | form field |
| `name` | the client's filename |
| `ok` | always `false` for these records |
| `errors` | `[{code, message, check, details}]` |
| `size` | bytes |
| `detected_type` | MIME type detected from the content, or `null` |
| `declared_type` | the client's `Content-Type` |
| `checks_run` | names of the checks that ran |
| `sanitized` | names of the sanitizers applied (empty for refused files) |
| `policy` | the policy's name |
| `path` | the request path |
| `sha256` | the file's SHA-256, or `null` (see below) |
| `violations` | `[{code, message, check, details}]` with full details |
| `mode` | `enforce` or `report` |

`sha256` is `null` when the file was refused before it was complete: in Django, a
name refused before the first byte was stored, a size limit hit while streaming, or a
type refused after the first 8 KiB of a larger file. Django's field validators and
storage, and Flask's `ShieldedFile`, log `Upload rejected by field validator: ...` (or
the usual line) with the result's data and the policy, but without `path` and
`sha256`. In `report` mode `ValidatingStorage` logs and signals the refusal and stores
the file anyway.

Accepted files are logged at DEBUG level (`Upload accepted: ...`) by Django.
Exceptions in checks are logged with their traceback (`logger.exception`); files too
large for a check are logged as warnings.

## Hooks per framework

| | Every validated request | Refused files | Field validators and storage |
|---|---|---|---|
| **Django** | signal `upload_validated(request, validation)` | signal `upload_rejected(request, validation, enforced)` | signal `file_rejected(result, policy)` |
| **Flask** | signal `upload_validated` (sender `app`, `results`) | signal `upload_rejected` (sender `app`, `results`, `enforced`) | none (`ShieldedFile` only raises the form error) |
| **FastAPI** | none | callback `on_rejected(request, [(field, result), ...])`, sync or async, in `enforce` and `report` mode | n/a |
| **CLI** | | `--json` document, exit status 1 | n/a |

Views can also read the outcome of the current request:
`get_upload_validation(request)` in Django and `get_upload_results()` in Flask. Exact
signatures and object fields are in the framework guides:
[Django](django.md#observability), [Flask](flask.md#observability),
[FastAPI](fastapi.md#refusals).
