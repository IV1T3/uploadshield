# FastAPI

uploadshield integrates with FastAPI through dependencies: `shield.file()` and
`shield.files()` validate and sanitize an endpoint's upload fields, and
`shield.all_files()` is an app- or router-wide safety net for every other file. This
page covers setup, every option, refusals and testing.

Requirements: FastAPI 0.110 or later with `python-multipart`. Install with
`uv add "uploadshield[fastapi,images]"` (`images` adds Pillow for image decoding and
re-encoding).

**On this page**

- [Quickstart](#quickstart)
- [UploadShield](#uploadshield)
- [Validating an endpoint's files: file() and files()](#validating-an-endpoints-files-file-and-files)
- [The safety net: all_files()](#the-safety-net-all_files)
- [Refusals](#refusals)
- [Modes](#modes)
- [Authentication and request size](#authentication-and-request-size)
- [Testing your integration](#testing-your-integration)
- [Good to know](#good-to-know)
- [Troubleshooting](#troubleshooting)

## Quickstart

```python
from typing import Annotated

from fastapi import Depends, FastAPI, UploadFile

from uploadshield.fastapi import UploadShield

shield = UploadShield()  # module level: see "Good to know"
app = FastAPI(dependencies=[Depends(shield.all_files())])  # every file, app-wide


@app.post("/avatar")
async def avatar(file: Annotated[UploadFile, Depends(shield.file("sanitized_images"))]):
    # validated and sanitized; file.content_type comes from the bytes
    return {"name": file.filename}


@app.post("/gallery")
async def gallery(files: Annotated[list[UploadFile], Depends(shield.files("images"))]):
    return [f.filename for f in files]
```

Refused files are answered with **413**, **415** or **400** and a JSON body under
`detail`; the endpoint never runs. Validation runs in Starlette's threadpool, so the
event loop stays free.

## UploadShield

`UploadShield(*, policies=None, default_policy="default", mode="enforce",
expose_details=False, messages=None, on_rejected=None)` holds the configuration and
builds the dependencies. All arguments are keyword-only.

| Argument | Type | Default | Description |
|---|---|---|---|
| `policies` | `dict[str, Policy]` | `None` | Your policies by name, added to the built-in ones; a built-in name (even `"default"`) is replaced. |
| `default_policy` | policy, name or dotted path | `"default"` | Policy for `file()`, `files()` and `all_files()` called without one. Resolved immediately; unknown names raise `ValueError`. |
| `mode` | `"enforce"`, `"report"`, `"off"` | `"enforce"` | What validation does with refused files; see [Modes](#modes). Invalid values raise `ValueError`. |
| `expose_details` | `bool` | `False` | Include detection details in error responses ([Exposing details](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#exposing-details)). |
| `messages` | `dict[str, str]` | `None` | User-facing messages per violation code. |
| `on_rejected` | `callable(request, rejected)` | `None` | Called with the request and a list of `(field, ValidationResult)` pairs for refused files, in `enforce` **and** `report` mode, before the error is raised. May be `async`. Use it for audit logs. |

`shield.resolve(ref)` turns a policy name, dotted path or `Policy` into a `Policy`
(`ValueError` if unknown). Policy references are resolved when you build a
dependency, so a misspelled name fails at import time.

## Validating an endpoint's files: file() and files()

```python
@app.post("/documents")
async def documents(
    cv: Annotated[UploadFile, Depends(shield.file("pdf", alias="cv"))],
    attachments: Annotated[
        list[UploadFile], Depends(shield.files("documents", alias="attachments"))
    ],
): ...
```

`shield.file(policy=None, *, alias="file")` and `shield.files(policy=None, *,
alias="files")` return dependencies that read the form field `alias` (one file, or a
list), validate it against `policy` (default: `default_policy`) and return it.

- **Sanitized in place.** The returned `UploadFile` is the same object FastAPI parsed:
  its content, `filename`, `size` and `Content-Type` header are replaced by the
  sanitized ones (with the type detected from the bytes). The endpoint's own parameter
  for the field, `dependencies=[Depends(shield.file(...))]` and `request.form()` all see
  the sanitized file.
- **The field is required**: a request without it gets FastAPI's own 422. Unlike
  `all_files()`, `file()` and `files()` do not skip empty file inputs: whatever FastAPI
  hands them is validated.
- **`files()`** validates every file of the field; one refusal answers for all refused
  files together.
- In `report` mode refused files are returned untouched; in `off` mode nothing is
  validated.

## The safety net: all_files()

```python
from fastapi import APIRouter, Depends, FastAPI

app = FastAPI(dependencies=[Depends(shield.all_files())])  # the whole app
admin = APIRouter(dependencies=[Depends(shield.all_files("documents"))])  # one router
```

`shield.all_files(policy=None)` validates every file of a multipart request against
`policy` (default: `default_policy`) and refuses the request if one fails.

What it checks:

- every file part, except fields the route validates itself with `file()`/`files()`
  (found anywhere in the route's dependency tree), so the endpoint's own policy always
  wins. `file()` exempts only the part FastAPI hands it (the last one of its field);
  further parts with the same name are checked here;
- parts **without a filename** sent to a field the route declares as `File()`
  (FastAPI would pass their content to a `bytes` parameter): they are checked as files
  and refused for their missing name;
- multipart is recognised the way Starlette's parser does (any case, extra spaces).

What it leaves alone:

- requests that are not multipart, and empty file inputs;
- WebSocket routes;
- **mounted sub-applications** (`app.mount(...)`), which are separate ASGI apps that
  never run the outer app's dependencies, and plain Starlette routes
  (`app.add_route(...)`), which run no dependencies at all. Give each FastAPI
  sub-application its own `all_files()`.

`all_files()` cannot replace files (Starlette's form data is immutable): passing files
keep their content and only get the detected content type. Use `file()`/`files()`
where you want sanitized files. If the endpoint declares no form parameters,
`all_files()` parses the form itself and closes it (deleting temporary files) once the
response is done.

## Refusals

In `enforce` mode a refusal raises `HTTPException` with status **413** (too large),
**415** (wrong type) or **400** (everything else); see [Refusals](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md) for
every code. The body is always JSON:

```json
{
  "detail": {
    "error": "upload_rejected",
    "message": "The upload was rejected.",
    "files": [
      {
        "field": "file",
        "name": "cat.png",
        "errors": [{"code": "type_not_allowed", "message": "PHP script files are not allowed."}]
      }
    ]
  }
}
```

To change the response, add an exception handler for `HTTPException` and check for
`detail["error"] == "upload_rejected"`:

```python
from fastapi import HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse


@app.exception_handler(HTTPException)
async def uploads_as_problem_json(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict) and exc.detail.get("error") == "upload_rejected":
        return JSONResponse({"type": "upload-rejected", **exc.detail}, status_code=422)
    return await http_exception_handler(request, exc)
```

For audit logs use `on_rejected`:

```python
async def audit(request, rejected):
    for field, result in rejected:
        await store_audit_entry(path=request.url.path, field=field, codes=result.codes)


shield = UploadShield(on_rejected=audit)
```

Every refusal is also logged as a WARNING on the `uploadshield` logger with structured
data in `record.upload`, including the SHA-256; see
[The log record](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md#the-log-record). FastAPI has no signals.

## Modes

| `mode` | Refused files |
|---|---|
| `"enforce"` | `HTTPException`; the endpoint does not run. |
| `"report"` | logged and passed to `on_rejected`, then delivered untouched. |
| `"off"` | not validated at all. |

## Authentication and request size

FastAPI parses the whole form before any dependency runs, so:

- **Cap request sizes** in the ASGI server or the proxy in front of it; uploadshield's
  `max_size` refuses files only after they were received.
- **Authenticate first**: list your authentication dependency before the shield's, both
  app-wide (`FastAPI(dependencies=[Depends(auth), Depends(shield.all_files())])`) and in
  each endpoint's signature (before its `shield.file()` parameter). Dependencies run in
  order, so anonymous requests are refused before their files are validated.

## Testing your integration

```python
from fastapi.testclient import TestClient


def test_disguised_script_is_refused():
    client = TestClient(app)
    files = {"file": ("cat.png", b"<?php system($_GET['c']); ?>", "image/png")}
    response = client.post("/avatar", files=files)
    assert response.status_code == 415
    assert response.json()["detail"]["files"][0]["errors"][0]["code"] == "type_not_allowed"
```

To test a policy without HTTP, call `uploadshield.validate()` directly; see
[Python API](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md).

## Good to know

- **Define the shield at module level.** With `from __future__ import annotations`,
  FastAPI cannot evaluate dependencies that refer to local variables (for example a
  shield created inside a test function).
- **Validation runs in the threadpool** (`run_in_threadpool`), and so does hashing
  refused files for the log, so large files do not block the event loop.
- **`all_files()` and `file()` together** validate each file once: fields with their own
  dependency are left to it.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| A route under `app.mount(...)` is not validated | mounted apps do not run the outer app's dependencies | add `dependencies=[Depends(shield.all_files())]` to the sub-application |
| `422 Unprocessable Entity` instead of a refusal | the form field the dependency expects is missing | send the field under its `alias`, or use `files()` / an optional parameter |
| `NameError` or odd 422s with locally defined shields | `from __future__ import annotations` | define the shield at module level |
| The endpoint still sees the client's `content_type` | the file was refused in `report` mode, `mode` is `"off"`, or no dependency covers it | use `shield.file()` or `all_files()`, which set the detected type on accepted files |
| Files are validated before authentication | the shield's dependency comes first | list the authentication dependency first |
