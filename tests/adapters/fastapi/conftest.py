"""Fixtures shared by this adapter's tests."""

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from tests.adapters.fastapi.app import make_app
from uploadshield.fastapi import UploadShield


@pytest.fixture
def client() -> TestClient:
    return TestClient(make_app(UploadShield()))
