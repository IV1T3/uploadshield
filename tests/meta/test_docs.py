"""The documentation must stay true: examples run, links resolve, every option is there.

* Examples: every ``python`` block in README.md and docs/ compiles; the blocks of the
  reference pages run in a fresh interpreter, and a few are checked for what they do.
* Links: every relative link (and ``#anchor``) in README.md, llms.txt and docs/ points
  to an existing file and heading.
* Completeness: every public option - Policy fields, check and sanitizer fields,
  violation codes, Django and Flask settings, FastAPI arguments, CLI flags - appears on
  its page.
* House rules: ``uv`` instead of pip, no "middleware" components, no invisible
  characters, and a README short enough to read.
"""

from __future__ import annotations

import argparse
import dataclasses
import inspect
import os
import re
import subprocess
import sys
import textwrap
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from tests.support import corpus
from uploadshield import Code, Policy, Upload, checks, sanitizers, validate

ROOT = Path(__file__).parents[2]
README = ROOT / "README.md"
LLMS = ROOT / "llms.txt"
DOCS = ROOT / "docs"
PAGES = [README, LLMS, *sorted(DOCS.glob("*.md"))]
#: Pages whose examples are complete programs: they run, not just compile.
RUNNABLE = ["policies.md", "checks.md", "python-api.md"]

_FENCE = re.compile(r"```.*?```", re.DOTALL)
_PYTHON = re.compile(r"```python\n(.*?)^[ \t]*```", re.DOTALL | re.MULTILINE)
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^(#{1,6}) +(.+?) *$", re.MULTILINE)


def text(page: Path) -> str:
    return page.read_text(encoding="utf-8")


def python_blocks(page: Path) -> list[str]:
    return [textwrap.dedent(block) for block in _PYTHON.findall(text(page))]


def page_id(page: Path) -> str:
    return str(page.relative_to(ROOT))


# --------------------------------------------------------------------------- #
# Examples
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("page", PAGES, ids=page_id)
def test_python_examples_compile(page: Path) -> None:
    for index, block in enumerate(python_blocks(page)):
        compile(block, f"{page_id(page)} block {index}", "exec")


_RUNNER = """
import re, sys
from pathlib import Path

page = Path(sys.argv[1])
blocks = re.findall(r"```python\\n(.*?)```", page.read_text(encoding="utf-8"), re.DOTALL)
for index, block in enumerate(blocks):
    exec(compile(block, f"{page.name} block {index}", "exec"), {"__name__": f"block{index}"})
print(f"ran {len(blocks)} blocks")
"""


@pytest.mark.parametrize("name", RUNNABLE)
def test_reference_examples_run(name: str, tmp_path: Path) -> None:
    # A fresh interpreter per page: examples register file types, which is global.
    (tmp_path / "upload.bin").write_bytes(corpus.pdf())
    done = subprocess.run(
        [sys.executable, "-c", _RUNNER, str(DOCS / name)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("ran ")


def block_containing(page: Path, marker: str) -> str:
    return next(b for b in python_blocks(page) if marker in b)


def test_custom_check_example() -> None:
    namespace: dict[str, Any] = {}
    exec(block_containing(DOCS / "python-api.md", "class NoPortraitImages"), namespace)  # noqa: S102
    portrait = corpus.image("PNG", size=(10, 20))
    result = validate(Upload.from_bytes(portrait, "p.png"), namespace["POLICY"])
    assert result.codes == ("portrait",)
    landscape = corpus.image("PNG", size=(20, 10))
    assert validate(Upload.from_bytes(landscape, "p.png"), namespace["POLICY"]).ok


def test_framework_free_example(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "upload.bin").write_bytes(corpus.pdf_with_javascript())
    namespace: dict[str, Any] = {}
    exec(block_containing(DOCS / "python-api.md", 'with open("upload.bin"'), namespace)  # noqa: S102
    assert namespace["result"].codes == ("pdf_active_content",)


def test_policy_example() -> None:
    namespace: dict[str, Any] = {}
    exec(block_containing(DOCS / "policies.md", "INVOICES = Policy("), namespace)  # noqa: S102
    invoices = namespace["INVOICES"]
    assert invoices.types == frozenset({"application/pdf", "image/png", "image/jpeg"})
    assert invoices.checks[0].name == "clamav"


def test_readme_policies_build() -> None:
    namespace: dict[str, Any] = {}
    exec(block_containing(README, "AVATARS = "), namespace)  # noqa: S102
    assert namespace["AVATARS"].max_size == 2_000_000
    assert namespace["INVOICES"].name == "invoices"


# --------------------------------------------------------------------------- #
# Links
# --------------------------------------------------------------------------- #


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    plain = heading.replace("`", "")
    plain = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", plain)
    kept = "".join(c for c in plain.lower() if c.isalnum() or c in " -_")
    return kept.replace(" ", "-")


def anchors(page: Path) -> set[str]:
    seen: dict[str, int] = {}
    found: set[str] = set()
    for _, heading in _HEADING.findall(_FENCE.sub("", text(page))):
        base = slug(heading)
        count = seen.get(base, 0)
        found.add(base if count == 0 else f"{base}-{count}")
        seen[base] = count + 1
    return found


def links(page: Path) -> list[str]:
    return _LINK.findall(_FENCE.sub("", text(page)))


@pytest.mark.parametrize("page", PAGES, ids=page_id)
def test_links_and_anchors_resolve(page: Path) -> None:
    broken = []
    for target in links(page):
        if re.match(r"[a-z]+:", target):  # https:, mailto:
            continue
        path, _, anchor = target.partition("#")
        destination = (page.parent / path).resolve() if path else page
        if not destination.exists():
            broken.append(f"{target}: no such file")
        elif anchor and destination.suffix == ".md" and anchor not in anchors(destination):
            broken.append(f"{target}: no heading #{anchor}")
    assert broken == []


def test_every_page_is_listed() -> None:
    pages = {p.name for p in DOCS.glob("*.md")}
    index = {Path(t).name for t in links(DOCS / "README.md")}
    agents = {Path(t.partition("#")[0]).name for t in links(LLMS)}
    assert pages - {"README.md"} <= index
    assert pages <= agents


# --------------------------------------------------------------------------- #
# Completeness: every option is documented on its page
# --------------------------------------------------------------------------- #


def mentioned(name: str, page_text: str) -> bool:
    return f"`{name}`" in page_text or f"`{name}=" in page_text or f"`{name}(" in page_text


def section(page_text: str, title: str) -> str:
    """The text under the heading ``title`` up to the next heading of the same level."""
    match = re.search(rf"^(#+) {re.escape(title)}\s*$", page_text, re.MULTILINE)
    assert match, f"no heading {title!r}"
    level = len(match.group(1))
    rest = page_text[match.end() :]
    end = re.search(rf"^#{{1,{level}}} ", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def init_fields(cls: type) -> list[str]:
    return [f.name for f in dataclasses.fields(cls) if f.init]


def test_policy_page_documents_every_field() -> None:
    page = text(DOCS / "policies.md")
    assert [f for f in init_fields(Policy) if not mentioned(f, page)] == []
    for name in ("pipeline", "types", "allows", "allows_mime", "replace", "extend"):
        assert f"policy.{name}" in page, name


def _components(module: Any, base: type) -> list[type]:
    return [
        obj
        for name in module.__all__
        if isinstance(obj := getattr(module, name), type)
        and issubclass(obj, base)
        and obj is not base
    ]


@pytest.mark.parametrize(
    "cls",
    _components(checks, checks.Check) + _components(sanitizers, sanitizers.Sanitizer),
    ids=lambda c: c.__name__,
)
def test_checks_page_documents_every_option(cls: type) -> None:
    body = section(text(DOCS / "checks.md"), cls.__name__)
    assert [f for f in init_fields(cls) if not mentioned(f, body)] == []


def test_checks_page_documents_every_constant() -> None:
    page = text(DOCS / "checks.md")
    constants = [n for n in checks.__all__ if n.isupper()]
    assert [c for c in constants if not mentioned(c, page)] == []


def test_refusals_page_documents_every_code() -> None:
    page = text(DOCS / "refusals.md")
    assert [c.value for c in Code if not mentioned(c.value, page)] == []


def test_django_page_documents_every_setting_name_and_check() -> None:
    pytest.importorskip("django")
    import uploadshield.django
    from uploadshield.django import conf

    page = text(DOCS / "django.md")
    assert [k for k in conf._DEFAULTS if not mentioned(k, page)] == []
    assert [n for n in uploadshield.django.__all__ if n not in page] == []
    source = (Path(uploadshield.django.__file__).parent / "checks.py").read_text()
    ids = set(re.findall(r"uploadshield\.[EWI]\d{3}", source))
    assert ids
    assert sorted(i for i in ids if f"`{i}`" not in page) == []
    for name in ("upload_policy", "path_policies", "fallback_message"):
        assert f"`{name}`" in page, name


def test_flask_page_documents_every_setting_and_name() -> None:
    pytest.importorskip("flask")
    import uploadshield.flask
    from uploadshield.flask import core

    page = text(DOCS / "flask.md")
    assert [k for k in core._DEFAULTS if not mentioned(k, page)] == []
    assert [n for n in [*uploadshield.flask.__all__, "ShieldedFile"] if n not in page] == []


def test_fastapi_page_documents_every_argument() -> None:
    pytest.importorskip("fastapi")
    from uploadshield.fastapi import UploadShield

    page = text(DOCS / "fastapi.md")
    names = {"resolve", "file", "files", "all_files"}
    for method in (
        UploadShield.__init__,
        UploadShield.file,
        UploadShield.files,
        UploadShield.all_files,
    ):
        names |= {p for p in inspect.signature(method).parameters if p != "self"}
    assert sorted(n for n in names if n not in page) == []


def test_cli_page_documents_every_command_and_option() -> None:
    from uploadshield.cli import build_parser

    page = text(DOCS / "cli.md")
    parser = build_parser()
    commands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    missing = []
    for name, sub in commands.choices.items():
        if f"`{name}" not in page:
            missing.append(name)
        for action in sub._actions:
            missing += [
                o
                for o in action.option_strings
                if o not in ("-h", "--help") and f"`{o}" not in page
            ]
    assert sorted(set(missing)) == []


# --------------------------------------------------------------------------- #
# House rules
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("page", PAGES, ids=page_id)
def test_uv_not_pip(page: Path) -> None:
    assert not re.search(r"\bpip\b", text(page)), "write uv add / uv run / uvx"


_ALLOWED_MIDDLEWARE = re.compile(
    r"MIDDLEWARE|\w+Middleware|[\w.]*\.middleware\.\w+|django-middleware-fileuploadvalidation"
)


@pytest.mark.parametrize("page", PAGES, ids=page_id)
def test_no_middleware_components(page: Path) -> None:
    if page.name == "migrating-from-1.x.md":
        return  # the one place that talks about the old package's middleware
    stray = [
        token
        for token in re.findall(
            r"[\w.\-]*[Mm][Ii][Dd][Dd][Ll][Ee][Ww][Aa][Rr][Ee][\w.\-]*", text(page)
        )
        if not _ALLOWED_MIDDLEWARE.fullmatch(token.strip(".-"))
    ]
    assert stray == []


@pytest.mark.parametrize("page", PAGES, ids=page_id)
def test_no_invisible_characters(page: Path) -> None:
    # Control, format (bidi overrides, zero-width) and surrogate characters hide text.
    hidden = {
        f"U+{ord(c):04X}"
        for c in text(page)
        if c not in "\n\t" and unicodedata.category(c) in ("Cc", "Cf", "Cs")
    }
    assert hidden == set()


def test_readme_stays_short() -> None:
    assert len(text(README).splitlines()) < 220
