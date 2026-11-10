"""Traceability: the OWASP documents, the tests, and docs/OWASP.md agree.

* Every recommendation the library covers (``enforced``, ``available``, ``partial``)
  has at least one test marked ``@pytest.mark.owasp("<id>")``.
* Every marker names a recommendation of ``tests/owasp/registry.py``.
* Each matrix in ``docs/OWASP.md`` is exactly what the registry renders.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.owasp.registry import (
    ITEMS,
    LEVELS,
    SOURCES,
    TESTED,
    Source,
    coverage,
    documented,
    render,
)

TESTS = Path(__file__).parents[1]


def owasp_marks() -> dict[str, list[str]]:
    """OWASP item -> the tests marked with it, found without importing them."""
    found: dict[str, list[str]] = {}
    for path in sorted(TESTS.rglob("test_*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and ast.unparse(decorator.func) in ("owasp", "pytest.mark.owasp")
                ):
                    continue
                for arg in decorator.args:
                    assert isinstance(arg, ast.Constant), f"{path}: owasp() ids must be literals"
                    test = f"{path.relative_to(TESTS)}::{node.name}"
                    found.setdefault(str(arg.value), []).append(test)
    return found


def test_every_covered_recommendation_has_tests() -> None:
    marks = owasp_marks()
    untested = [
        item_id
        for item_id, item in ITEMS.items()
        if item.see is None and coverage(item_id) in TESTED and item_id not in marks
    ]
    assert untested == []


def test_markers_name_real_recommendations() -> None:
    assert set(owasp_marks()) - set(ITEMS) == set()


@pytest.mark.parametrize("source", SOURCES, ids=[s.key for s in SOURCES])
def test_references_and_levels_are_consistent(source: Source) -> None:
    items = [item for section in source.sections for item in section.items]
    assert len({item.id for item in items}) == len(items)
    for item in items:
        assert item.id.split(".")[0] in source.prefixes, item.id
        if item.see is not None:
            assert item.coverage is None, item.id
            assert item.see in ITEMS, f"{item.id} -> {item.see}"
            assert ITEMS[item.see].see is None, f"{item.id} -> {item.see} -> ..."
        else:
            assert item.coverage in LEVELS, item.id
            assert item.how, item.id


@pytest.mark.parametrize("source", SOURCES, ids=[s.key for s in SOURCES])
def test_the_document_shows_the_current_matrix(source: Source) -> None:
    assert documented(source) == render(source), (
        "Run: uv run python -m tests.owasp.registry --write"
    )
