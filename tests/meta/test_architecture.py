"""Enforce the layering: the engine is framework-free; each adapter owns one framework;
the command line sits on top of the engine."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import uploadshield

PACKAGE = Path(uploadshield.__file__).parent


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


#: Top-level modules each adapter package may import.
FRAMEWORKS: dict[str, frozenset[str]] = {
    "django": frozenset({"django", "rest_framework"}),
    "flask": frozenset({"flask", "werkzeug", "blinker", "wtforms", "flask_wtf"}),
    "fastapi": frozenset({"fastapi", "starlette"}),
}
ALL_FRAMEWORK_MODULES = frozenset().union(*FRAMEWORKS.values())


@pytest.mark.parametrize("adapter", [None, *FRAMEWORKS])
def test_each_layer_imports_only_its_own_framework(adapter: str | None) -> None:
    allowed = FRAMEWORKS.get(adapter or "", frozenset())
    offenders: dict[str, list[str]] = {}
    for path in PACKAGE.rglob("*.py"):
        parts = path.relative_to(PACKAGE).parts
        owner = parts[0] if parts[0] in FRAMEWORKS else None
        if owner != adapter:
            continue
        bad = sorted(
            m for m in imported_modules(path) if m.split(".")[0] in ALL_FRAMEWORK_MODULES - allowed
        )
        if bad:
            offenders[str(path.relative_to(PACKAGE))] = bad
    assert offenders == {}


def test_core_does_not_depend_on_outer_layers() -> None:
    outer = (
        "uploadshield.checks",
        "uploadshield.policy",
        "uploadshield.engine",
        "uploadshield.presets",
        "uploadshield.django",
        "uploadshield.flask",
        "uploadshield.fastapi",
        "uploadshield.web",
        "uploadshield.sanitizers",
        "uploadshield.cli",
    )
    for path in (PACKAGE / "core").rglob("*.py"):
        bad = [m for m in imported_modules(path) if m.startswith(outer)]
        assert not bad, f"{path.name} imports {bad}"


ADAPTER_PACKAGES = ("uploadshield.django", "uploadshield.flask", "uploadshield.fastapi")


def test_the_command_line_is_a_top_layer() -> None:
    """Nothing imports the CLI; it reaches a framework only through the Django bridge."""
    for path in PACKAGE.rglob("*.py"):
        parts = path.relative_to(PACKAGE).parts
        modules = imported_modules(path)
        if parts[0] != "cli" and path.name != "__main__.py":
            assert not [m for m in modules if m.startswith("uploadshield.cli")], path
        if parts[0] == "cli":
            adapters = {m for m in modules if m.startswith(ADAPTER_PACKAGES)}
            assert adapters <= {"uploadshield.django.cli"}, (path, adapters)


def test_engine_works_without_any_framework_installed() -> None:
    blocked = sorted(ALL_FRAMEWORK_MODULES)
    code = (
        f"import sys; sys.modules.update(dict.fromkeys({blocked!r}))\n"
        "import uploadshield.web\n"
        "from uploadshield import Upload, validate, presets\n"
        "r = validate(Upload.from_bytes(b'%PDF-1.4 /JavaScript', 'a.pdf'), presets.PDF)\n"
        "assert r.codes == ('pdf_active_content',), r.codes\n"
        "from uploadshield.cli import main\n"
        "assert main(['explain', 'file_empty']) == 0\n"
        "assert main(['scan', '-', '--name', 'a.pdf', '--json']) == 1\n"
        "print('ok')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        input="%PDF-1.4 /JavaScript",
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().endswith("ok")


def test_nothing_uses_the_host_dependent_mimetypes_module() -> None:
    for path in PACKAGE.rglob("*.py"):
        assert "mimetypes" not in imported_modules(path), path
