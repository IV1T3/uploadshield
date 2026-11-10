"""Fixtures for every test, and the suite's markers.

Each test is marked with the part of the suite it belongs to (``engine``, ``scanners``,
``cli``, ``django``, ``flask``, ``fastapi``, ``conformance``, ``owasp``, ``meta``), so
``uv run pytest -m flask`` runs one adapter.  ``@pytest.mark.owasp("<id>")`` links a test
to a recommendation of OWASP's File Upload Cheat Sheet or Unrestricted File Upload page
(``tests/owasp/registry.py``); ``uv run pytest -m owasp`` runs every such test, wherever
it lives.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Callable
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from tests.owasp.registry import ITEMS
from uploadshield import Upload

TESTS = Path(__file__).parent
AREAS = ("engine", "scanners", "cli", "conformance", "owasp", "meta")
ADAPTERS = ("django", "flask", "fastapi")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    unknown: set[str] = set()
    for item in items:
        parts = item.path.relative_to(TESTS).parts
        if parts[0] == "adapters" and parts[1] in ADAPTERS:
            item.add_marker(parts[1])
        elif parts[0] in AREAS and parts[0] != "owasp":
            item.add_marker(parts[0])
        for mark in item.iter_markers("owasp"):
            if not mark.args:
                raise pytest.UsageError(f"{item.nodeid}: owasp() needs a cheat-sheet item id")
            unknown |= {arg for arg in mark.args if arg not in ITEMS}
    if unknown:
        raise pytest.UsageError(
            f"Unknown OWASP item ids: {', '.join(sorted(unknown))} (see tests/owasp/registry.py)"
        )


@pytest.fixture
def make_upload() -> Callable[..., Upload]:
    def factory(data: bytes, name: str = "file.bin", declared_type: str | None = None) -> Upload:
        return Upload(io.BytesIO(data), name, len(data), declared_type)

    return factory


@pytest.fixture
def uploaded() -> Callable[..., SimpleUploadedFile]:
    def factory(data: bytes, name: str, content_type: str = "application/octet-stream"):
        return SimpleUploadedFile(name, data, content_type=content_type)

    return factory


@pytest.fixture
def upload_log(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger="uploadshield")
    return caplog
