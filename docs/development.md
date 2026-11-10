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
