"""Fixtures shared by this adapter's tests."""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("flask")

from tests.adapters.flask.app import make_app


@pytest.fixture
def client() -> Any:
    return make_app().test_client()
