# Flask

uploadshield integrates with Flask as an extension: a `before_request` hook validates
every multipart request, decorators choose policies per view, a Flask-WTF validator
gives inline form errors, and refusals are Werkzeug HTTP errors. This page covers
setup, every option, refusals, observability and testing.

Requirements: Flask 2.3 or later. Install with `uv add "uploadshield[flask,images]"`
(`images` adds Pillow for image decoding and re-encoding).

**On this page**

- [Quickstart](#quickstart)
- [How the safety net works](#how-the-safety-net-works)
- [Choosing the policy for a request](#choosing-the-policy-for-a-request)
- [The validate_uploads decorator](#the-validate_uploads-decorator)
- [What your view receives](#what-your-view-receives)
- [Refusals](#refusals)
- [Flask-WTF forms: ShieldedFile](#flask-wtf-forms-shieldedfile)
- [Observability](#observability)
- [Configuration reference](#configuration-reference)
- [Testing your integration](#testing-your-integration)
- [Good to know](#good-to-know)
- [Troubleshooting](#troubleshooting)

## Quickstart

```python
from flask import Flask, request

from uploadshield.flask import UploadShield, validate_uploads

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # Werkzeug parses the whole body first
app.config["UPLOADSHIELD"] = {"MODE": "report"}  # observe first, then "enforce"
UploadShield(app)


@app.post("/avatar")
@validate_uploads("sanitized_images")  # request.files holds the sanitized file
def avatar():
    picture = request.files["picture"]
    ...
```

`UploadShield(app)` (or `shield = UploadShield()` and later `shield.init_app(app)` in an
application factory) registers a `before_request` hook: every multipart request to any
view is now checked against the built-in `default` policy (common images, PDF, Office
and OpenDocument, text and CSV, audio, video; up to 50 MB). In `report` mode nothing is
blocked: would-be refusals are logged on the `uploadshield` logger and sent as signals.
Remove `"MODE": "report"` (the default is `"enforce"`) to start refusing files.

Set `MAX_CONTENT_LENGTH`: Werkzeug parses the whole body before any hook runs, so the
request size limit is what protects your disk and memory; Werkzeug answers larger
requests with its own 413.

## How the safety net works

The hook registered by `UploadShield(app)`:

- runs for every request whose body is `multipart/form-data`, whatever the HTTP method
  (`POST`, `PUT`, `PATCH`, even `GET`). URL-encoded, JSON and raw bodies carry no files
  and are left alone;
- covers every view and blueprint of the app;
- runs in registration order with your other `before_request` hooks. Register
  authentication hooks **before** `UploadShield(app)` so anonymous requests are refused
  before their files are validated;
- validates every file part of the request (`request.files`), in order. Empty file
  inputs (no filename, no content) are skipped; a part with content but no filename is
  refused (`filename_invalid`).

Set `PROTECT_ALL` to `False` to disable the hook and protect only decorated views.

## Choosing the policy for a request

For each request, the first of these wins:

1. the view's `@validate_uploads(...)` or `@skip_upload_validation`;
2. the first [`ENDPOINT_POLICIES`](#configuration-reference) pattern matching the
   request's endpoint name;
3. [`DEFAULT_POLICY`](#configuration-reference) (`"default"` unless you change it).

```python
app.config["UPLOADSHIELD"] = {
    "DEFAULT_POLICY": "documents",  # None: only views with a policy are checked
    "POLICIES": {"invoices": INVOICES},  # your policies, by name
    "ENDPOINT_POLICIES": {  # globs on endpoint names
        "billing.*": "invoices",
        "admin.*": "documents",
        "webhooks.*": None,  # None: skip these endpoints
    },
}
```

`ENDPOINT_POLICIES` patterns are `fnmatch` globs, matched case-sensitively against
`request.endpoint` (`"blueprint.view"`), in the order written. They only apply through
the hook (`PROTECT_ALL`). Requests that match no route (404s) use `DEFAULT_POLICY`.

## The validate_uploads decorator

```python
from flask import redirect, url_for
from flask.views import MethodView

from uploadshield.flask import skip_upload_validation, validate_uploads


@app.post("/application")
@validate_uploads(fields={"cv": "pdf", "photo": "images", "notes": None})
def application(): ...


@app.post("/gallery")
@validate_uploads("images", on_reject=lambda outcomes: redirect(url_for("gallery_form")))
def gallery(): ...


@app.post("/statements")
@validate_uploads("pdf", mode="report")  # observe this view only
def statements(): ...


@app.post("/internal/import")
@skip_upload_validation
def internal_import(): ...


class DocumentView(MethodView):
    decorators = [validate_uploads("documents")]

    def post(self): ...
```

`validate_uploads(policy=<default>, /, *, fields=None, mode=None, on_reject=None)`

| Argument | Type | Default | Description |
|---|---|---|---|
| `policy` (positional) | policy, name, dotted path or `None` | `DEFAULT_POLICY` (or the built-in `default` if that is `None`) | Policy for every file field. `None`: only the fields named in `fields` are validated. |
| `fields` | `dict[str, policy \| None]` | `None` | Per-field policies; `None` skips that field. |
| `mode` | `"enforce"`, `"report"`, `"off"` or `None` | `None` (the `MODE` setting) | Mode for this view. |
| `on_reject` | `callable(outcomes) -> response` or `None` | `None` | Builds the response for a refusal (enforce mode only), for example a redirect. It receives the list of refused [`FileOutcome`](#observability)s; its return value goes through `make_response`. |

- Put `@validate_uploads` **below** the route decorator (`@app.post` registers the
  decorated function). The bare form `@validate_uploads` uses the default policy.
- It wraps sync and async views, and works without `UploadShield(app)` (then with the
  built-in defaults), so you can adopt uploadshield one view at a time.
- For `MethodView` classes use `decorators = [...]`.
- Policy names are resolved per request, so a misspelled name fails on the first
  request to that view; invalid `mode` values raise `ValueError` at import time.
- When the hook and the decorator both apply, files are validated once.

`skip_upload_validation` marks a view (function or view class) as exempt; it does not
wrap it.

## What your view receives

After validation `request.files` is replaced, in the same order, by:

- **passing files** as new `FileStorage` objects with the sanitized content and name
  (if the policy sanitizes) and the content type **detected from the bytes**, never
  the client's;
- **untouched** files for skipped fields, empty inputs and, in `report` mode, refused
  files.

Originals that sanitizers replaced are closed. Werkzeug keeps the client's raw filename
(`../../x.png`); the filename checks refuse such names, and `RandomizeFilename` or
`SafeFilename` give you safe ones.

## Refusals

In `enforce` mode a refused request raises `UploadRejected`, a Werkzeug
`HTTPException` with status **413** (too large), **415** (wrong type) or **400**
(everything else); see [Refusals](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md) for every code. It renders as:

- **JSON** when `Accept` contains `json` but not `text/html`, or the request sends
  `X-Requested-With: XMLHttpRequest`:
  `{"error": "upload_rejected", "message": ..., "files": [...]}`
  ([payload](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#the-error-payload));
- **HTML** otherwise: a minimal escaped page (no template). Clients sending
  `Accept: */*` (curl's default) get HTML.

Customise it app-wide with an error handler for the exception class. Status-code
handlers such as `@app.errorhandler(415)` do **not** catch it, because its status
varies per refusal:

```python
from flask import jsonify

from uploadshield.flask import UploadRejected


@app.errorhandler(UploadRejected)
def upload_rejected(error: UploadRejected):
    return jsonify(error.payload), error.code
```

| `UploadRejected` attribute | Description |
|---|---|
| `code` | 400, 413 or 415 |
| `payload` | the error payload as a `dict` |
| `outcomes` | the refused `FileOutcome`s |
| `response` | the `on_reject` response, if the view has one |
| `description` | `"The upload was rejected."` |

Replace messages per code with [`MESSAGES`](#configuration-reference); set
`EXPOSE_DETAILS` to include diagnostic details
([Exposing details](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#exposing-details)).

## Flask-WTF forms: ShieldedFile

For inline errors in forms, validate the field with `ShieldedFile`:

```python
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired

from uploadshield.flask.wtforms import ShieldedFile


class AvatarForm(FlaskForm):
    picture = FileField(validators=[FileRequired(), ShieldedFile("sanitized_images")])
```

`ShieldedFile(policy="default")` needs Flask-WTF (or WTForms), which the `flask` extra
does not install (`uv add flask-wtf`). It:

- refuses a bad file with a normal form error (the violation messages, with
  `MESSAGES` applied); after the first refused file validation stops;
- replaces `form.picture.data` with the **sanitized** `FileStorage` (a list for
  `MultipleFileField`);
- resolves the policy by name from `POLICIES` and the presets (not `DEFAULT_POLICY`);
- leaves empty fields to `FileRequired` / `FileAllowed`;
- **always enforces**, whatever `MODE` is, and sends no signals. Refusals are logged,
  without the request path and SHA-256.

If the hook already validated the file under the same policy, `ShieldedFile` reuses
that result instead of validating again.

## Observability

**Signals** (blinker, `from uploadshield.flask import ...`), sent with the app as
sender:

| Signal | Keyword arguments | Sent when |
|---|---|---|
| `upload_validated` | `results` (all `FileOutcome`s) | after every request whose files were validated, in `enforce` and `report` mode |
| `upload_rejected` | `results` (the refused ones), `enforced` | when at least one file was refused; `enforced` is `False` in `report` mode |

```python
from uploadshield.flask import upload_rejected


@upload_rejected.connect_via(app)
def audit(sender, results, enforced, **kwargs):
    for outcome in results:
        app.logger.warning("refused %s: %s", outcome.result.name, outcome.result.codes)
```

**`get_upload_results()`** returns the current request's `FileOutcome`s (passing and
refused; an empty list when the request had no files to check), or `None` when nothing
was validated (no multipart body, skipped view, `off` mode). Call it inside a request.

`FileOutcome`

| Member | Description |
|---|---|
| `field` | form field name |
| `result` | the [`ValidationResult`](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md#results), with `result.sanitized` when the file was sanitized |
| `policy_name` | name of the policy that judged the file |
| `storage` | the original `FileStorage` as received |
| `ok` | `result.ok` |

**Logging**: every refusal is a WARNING on the `uploadshield` logger with structured
data in `record.upload`, including the SHA-256 for refusals by the hook and the
decorator; see
[The log record](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#the-log-record).

## Configuration reference

All settings live in `app.config["UPLOADSHIELD"]`, read **once** by `init_app`; change
them before calling `UploadShield(app)`. Unknown keys raise `ValueError` ("Unknown
UPLOADSHIELD keys: ... Valid keys: ...").

| Key | Type | Default | Description |
|---|---|---|---|
| `MODE` | `"enforce"`, `"report"`, `"off"` | `"enforce"` | What validation does with refused files. `ShieldedFile` always enforces. |
| `DEFAULT_POLICY` | policy, name, dotted path or `None` | `"default"` | Policy for views without a decorator or `ENDPOINT_POLICIES` match. `None`: such views are not validated. |
| `POLICIES` | `dict[str, Policy]` | `{}` | Your policies by name, added to the built-in ones; a built-in name (even `"default"`) is replaced. Values must be `Policy` objects (`TypeError` otherwise). |
| `ENDPOINT_POLICIES` | `dict[str, policy \| None]` | `{}` | Glob on endpoint names to policy; `None` skips; first match wins; decorators take precedence. Needs `PROTECT_ALL`. |
| `EXPOSE_DETAILS` | `bool` | `False` | Include detection details in error responses. |
| `MESSAGES` | `dict[str, str]` | `{}` | User-facing messages per violation code; lazy translations are fine. |
| `PROTECT_ALL` | `bool` | `True` | Register the `before_request` hook that validates every multipart request. |

Unknown policy names in `DEFAULT_POLICY` and `ENDPOINT_POLICIES` raise `ValueError`
when `init_app` runs ("Unknown upload policy 'x'. Known policies: ..."). Without
`init_app` the decorators use the defaults above.

## Testing your integration

```python
import io


def test_disguised_script_is_refused(app):
    client = app.test_client()
    data = {"picture": (io.BytesIO(b"<?php system($_GET['c']); ?>"), "cat.png")}
    response = client.post("/avatar", data=data, headers={"Accept": "application/json"})
    assert response.status_code == 415
    assert response.get_json()["files"][0]["errors"][0]["code"] == "type_not_allowed"
```

Ask for JSON (`Accept: application/json`) to get the machine-readable payload. Results
are kept per request (in `request.environ`), so several requests inside one pushed
`app.app_context()` are each validated. To test a policy without HTTP, call
`uploadshield.validate()` directly; see [Python API](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md).

## Good to know

- **No streaming**: Werkzeug parses the whole body before validation; files are checked
  once they have been received. `MAX_CONTENT_LENGTH` is the size protection.
- **Async views** are supported; validation runs before the view.
- **`ShieldedFile` and the hook** use the same per-policy cache on the `FileStorage`, so
  using both costs nothing extra.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `@app.errorhandler(415)` never runs for refusals | the handler is looked up by exception class | `@app.errorhandler(UploadRejected)` |
| curl gets HTML instead of JSON | `Accept: */*` | send `Accept: application/json` |
| A view's decorator policy is ignored (the default policy decides) | `@validate_uploads` is above `@app.post`, so the route has the undecorated function | put it below the route decorator |
| `ENDPOINT_POLICIES` has no effect | `PROTECT_ALL` is `False`, or the view has its own decorator | enable `PROTECT_ALL`; decorators win |
| `ValueError: Unknown UPLOADSHIELD keys` | Django-only keys (`VIEW_POLICIES`, `MAX_UPLOAD_SIZE`, ...) | use the [Flask keys](#configuration-reference); `ENDPOINT_POLICIES` replaces `VIEW_POLICIES` |
| Large uploads exhaust memory or disk | no request size limit | set `MAX_CONTENT_LENGTH` |
