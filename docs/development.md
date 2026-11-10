# Development

How to work on uploadshield itself: setting up, running the tests, the layout of the
test suite, the example apps, and the generated parts of the documentation.

## Setup

```bash
uv sync --all-extras
uv run pytest --cov          # about 2500 tests
uv run ruff check . && uv run ruff format --check .
uv run ty check
```

`--all-extras` installs Pillow, yara-python, Magika and python-magic. On Python
versions without wheels for them (yara-python and onnxruntime lag behind new Python
releases), install the extras you can instead:
`uv run --extra django --extra flask --extra fastapi --extra images pytest`.

## Supported versions and dependency floors

uploadshield supports Python 3.11+ and, for the framework extras, the oldest release
line each framework still patches: Django 4.2 LTS, Flask 2.3, and the FastAPI line.
Those **framework** floors stay low on purpose — raising a minor floor buys little, since
resolvers install the newest compatible patch anyway.

The **non-framework** floors are set higher, to the first release that is free of a known
upload-relevant advisory, chosen so the floor version still runs on Python 3.11 (so the
higher floor costs no compatibility):

- `python-multipart>=0.0.18` — CVE-2024-53981 (multipart denial of service).
- `fastapi>=0.115.4` — the first FastAPI that requires `starlette>=0.40`, which fixes
  CVE-2024-47874 (multipart denial of service).
- `pillow>=11.0` — excludes the 10.x line (CVE-2023-50447 arbitrary code execution via
  `ImageMath.eval`, CVE-2024-28219 buffer overflow).
- `werkzeug>=2.3.8` (declared because the Flask adapter imports it directly) — CVE-2023-46136
  (multipart denial of service).
- `flask>=2.3.2` — CVE-2023-30861 (session-cookie caching).

A floor is the minimum we vouch for, not the installed version: a normal install on a
current Python resolves to the newest compatible release (see `uv.lock`). The advisories
above were checked against the [OSV](https://osv.dev) database.

### The version matrix

Run after any change, especially to the floors or engine:

- **Oldest stack** — a separate Python 3.11 environment pinned to the floors:
  `django==4.2.*`, `flask==2.3.2`, `werkzeug==2.3.8`, `fastapi==0.115.4`,
  `python-multipart==0.0.18`, `pillow==11.0.*`, plus `djangorestframework==3.15.*`,
  `flask-wtf==1.2.*`, `wtforms<3.2`, `httpx<0.28`, `anyio<4` for the test client (Starlette
  0.41's `TestClient` otherwise trips anyio 4's deprecation warnings under `-W error`), and
  `pytest`/`pytest-django`/`hypothesis`. Install the project with `--no-deps` on top.
- **Newest** — Python 3.14 and 3.15 with `--extra django --extra flask --extra fastapi
  --extra images --extra magika` (not `--all-extras`: yara-python and onnxruntime lag the
  newest interpreters).

## The test suite

The tests are organised by what they cover, and marked the same way
(`uv run pytest -m flask`, `-m "engine or owasp"`, ...):

| Directory | Marker | Covers |
|---|---|---|
| `tests/engine/` | `engine` | sniffing, every check and sanitizer, the pipeline, property-based fuzzing |
| `tests/scanners/` | `scanners` | ClamAV (against a fake clamd), YARA, Magika |
| `tests/cli/` | `cli` | the `uploadshield` command: verdicts, walking, output, JSON, exit status |
| `tests/adapters/{django,flask,fastapi}/` | `django`, `flask`, `fastapi` | each adapter's integration styles |
| `tests/conformance/` | `conformance` | the three example apps, sent byte-identical requests |
| `tests/owasp/` | `owasp` | OWASP's File Upload Cheat Sheet and Unrestricted File Upload test cases, section by section, in every framework |
| `tests/meta/` | `meta` | layering, the documentation (examples, links, completeness), OWASP traceability |
| `tests/support/` | | the file corpus, the cross-framework harness, the fake clamd |
| `tests/django_site/` | | the Django test project (settings, URLs, views, models) |

`@pytest.mark.owasp("<id>")` links any test to an OWASP item
(`tests/owasp/registry.py`); `tests/meta/test_owasp_matrix.py` fails if a covered item
has no test or `docs/OWASP.md` is out of date.

`tests/meta/test_docs.py` keeps the documentation honest: the examples in the docs run,
every link and anchor resolves, and every option of every public class, setting and
command-line flag is documented on its page.

## Example apps

`examples/django_app.py`, `examples/flask_app.py` and `examples/fastapi_app.py` are
runnable single-file apps with the same endpoints (`/documents`, `/avatar`, `/gallery`
and an unconfigured `/legacy`); the Django one adds an HTML form with inline errors.

```bash
uv run python examples/django_app.py runserver 8813     # Flask: uv run python examples/flask_app.py
uv run --with uvicorn uvicorn examples.fastapi_app:app --port 8812
examples/smoke.sh http://127.0.0.1:8813 SAMPLES_DIR     # attacks it over real HTTP
```

`tests/conformance/test_examples.py` sends all three apps byte-identical multipart
requests (Django under WSGI and ASGI) and checks that they accept, refuse and deliver
the same files.

## Generated documentation

- **The OWASP matrices** in `docs/OWASP.md` are rendered from `tests/owasp/registry.py`:
  `uv run python -m tests.owasp.registry --write`.
- **The diagrams** in `docs/images/` are generated: `uv run python docs/images/diagrams.py`.
  Do not edit the SVG files by hand.

## Conventions

- The engine (`core`, `checks`, `policy`, `engine`, `presets`, `web`) imports no web
  framework; each adapter imports only its own; nothing imports the CLI.
  `tests/meta/test_architecture.py` enforces this.
- Documentation and messages use `uv add` / `uv run` / `uvx`.
- See [Architecture](https://github.com/IV1T3/uploadshield/blob/main/docs/ARCHITECTURE.md) for the design and its rationale.
