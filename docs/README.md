# uploadshield documentation

uploadshield validates and sanitizes file uploads by their content, for Django, Flask,
FastAPI and the command line. Start with the path that matches what you want to do;
every page also works on its own.

## Where to start

| I want to... | Read |
|---|---|
| understand how it works and what "policy", "check" and "mode" mean | [Concepts](https://github.com/IV1T3/uploadshield/blob/main/docs/concepts.md) |
| protect a **Django** project, including DRF, forms and storage | [Django](https://github.com/IV1T3/uploadshield/blob/main/docs/django.md) |
| protect a **Flask** app, including Flask-WTF forms | [Flask](https://github.com/IV1T3/uploadshield/blob/main/docs/flask.md) |
| protect a **FastAPI** app | [FastAPI](https://github.com/IV1T3/uploadshield/blob/main/docs/fastapi.md) |
| check a folder for dangerous files, or debug why a file is refused | [Command line](https://github.com/IV1T3/uploadshield/blob/main/docs/cli.md) |
| decide which files to accept, and configure that | [Policies](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md) |
| know exactly what each check catches and how to tune it | [Checks and sanitizers](https://github.com/IV1T3/uploadshield/blob/main/docs/checks.md) |
| handle refusals: codes, status codes, messages, logs | [Refusals](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md) |
| validate files in my own code, or write my own checks and types | [Python API](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md) |
| upgrade from django-middleware-fileuploadvalidation 1.x | [Migrating from 1.x](https://github.com/IV1T3/uploadshield/blob/main/docs/migrating-from-1.x.md) |

AI agents and other tools: [`llms.txt`](https://github.com/IV1T3/uploadshield/blob/main/llms.txt) at the repository root lists
every page with a one-line summary.

## All pages

| Page | Contents |
|---|---|
| [Concepts](https://github.com/IV1T3/uploadshield/blob/main/docs/concepts.md) | the model (upload, policy, result), type detection, wildcards, the pipeline, fail closed, sanitization, modes, when each framework validates, glossary |
| [Policies](https://github.com/IV1T3/uploadshield/blob/main/docs/policies.md) | built-in policies, every `Policy` option, allowed types, filename rules, tuning content checks, scanners, sanitizers, deriving and registering policies, recipes, all registered file types |
| [Checks and sanitizers](https://github.com/IV1T3/uploadshield/blob/main/docs/checks.md) | every check and sanitizer with all options, violation codes and details; ClamAV, YARA and Magika setup; exported constants |
| [Refusals](https://github.com/IV1T3/uploadshield/blob/main/docs/refusals.md) | every violation code, HTTP status rules, the error payload, custom messages, exposed details, the log record, hooks per framework |
| [Django](https://github.com/IV1T3/uploadshield/blob/main/docs/django.md) | the upload handler, `VIEW_POLICIES`, `@validate_uploads`, DRF, form and model fields, inline errors, `ValidatingStorage`, refusals, signals, all settings, system checks, testing |
| [Flask](https://github.com/IV1T3/uploadshield/blob/main/docs/flask.md) | the extension and its hook, `ENDPOINT_POLICIES`, `@validate_uploads`, refusals, `ShieldedFile`, signals, all settings, testing |
| [FastAPI](https://github.com/IV1T3/uploadshield/blob/main/docs/fastapi.md) | `UploadShield`, `file()`, `files()`, `all_files()`, refusals, `on_rejected`, authentication and request size, testing |
| [Command line](https://github.com/IV1T3/uploadshield/blob/main/docs/cli.md) | `scan`, `validate`, `policies`, `explain`, verdicts, JSON output, exit status, every option, recipes |
| [Python API](https://github.com/IV1T3/uploadshield/blob/main/docs/python-api.md) | `validate()`, `Upload`, results, `InspectedFile`, writing checks and sanitizers, sniffers, registering file types, integrating other frameworks |
| [Migrating from 1.x](https://github.com/IV1T3/uploadshield/blob/main/docs/migrating-from-1.x.md) | the 1.x options and their replacements |
| [Architecture](https://github.com/IV1T3/uploadshield/blob/main/docs/ARCHITECTURE.md) | how uploadshield is built, framework by framework, with diagrams and design rationale |
| [OWASP coverage](https://github.com/IV1T3/uploadshield/blob/main/docs/OWASP.md) | every recommendation of OWASP's File Upload Cheat Sheet and Unrestricted File Upload page, and how uploadshield covers it |
| [Development](https://github.com/IV1T3/uploadshield/blob/main/docs/development.md) | working on uploadshield: setup, tests, example apps, generated docs |
