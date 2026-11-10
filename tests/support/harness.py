"""Send the same raw multipart request to every framework's example app.

``app`` is a fixture parametrized over Django (WSGI and ASGI), Flask and FastAPI;
each runs the matching ``examples/*_app.py`` through its framework's test client.
Bodies are encoded here, byte for byte, the way browsers and curl send them.
"""

from __future__ import annotations

import hashlib
import io
import json
import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from PIL import Image

from uploadshield import Upload, presets, validate

BOUNDARY = "----uploadshield-conformance"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"
JSON = {"Accept": "application/json"}


# --------------------------------------------------------------------------- #
# One request encoder, one reply type, four servers
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Part:
    """One multipart part; ``filename=None`` makes it an ordinary form field."""

    field: str
    filename: str | None
    data: bytes
    content_type: str = "application/octet-stream"


def file(name: str | None, data: bytes, content_type: str = "application/octet-stream") -> Part:
    return Part("file", name, data, content_type)


def encode(parts: tuple[Part, ...]) -> bytes:
    """Browsers send UTF-8 filenames raw inside the quotes, and so do we."""
    body = bytearray()
    for part in parts:
        disposition = f'form-data; name="{part.field}"'
        if part.filename is not None:
            disposition += f'; filename="{part.filename}"'
        body += f"--{BOUNDARY}\r\nContent-Disposition: {disposition}\r\n".encode()
        if part.filename is not None:
            body += f"Content-Type: {part.content_type}\r\n".encode()
        body += b"\r\n" + part.data + b"\r\n"
    body += f"--{BOUNDARY}--\r\n".encode()
    return bytes(body)


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes
    content_type: str

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def rejection(self) -> dict[str, Any] | None:
        """The uploadshield error payload, if this is one (FastAPI nests it in ``detail``)."""
        if "json" not in self.content_type:
            return None
        data = self.json()
        if isinstance(data, dict) and isinstance(data.get("detail"), dict):
            data = data["detail"]
        return data if isinstance(data, dict) and data.get("error") == "upload_rejected" else None

    @property
    def codes(self) -> list[str]:
        assert self.rejection is not None, (self.status, self.body[:300])
        return [e["code"] for f in self.rejection["files"] for e in f["errors"]]

    @property
    def files(self) -> list[dict[str, Any]]:
        assert self.status == 200, (self.status, self.body[:300])
        return self.json()["files"]


Send = Callable[[str, bytes, dict[str, str]], Reply]


@dataclass(frozen=True)
class App:
    name: str
    send: Send

    def post(self, path: str, *parts: Part, headers: dict[str, str] | None = None) -> Reply:
        return self.send(path, encode(parts), JSON if headers is None else headers)

    @property
    def framework(self) -> str:
        return self.name.split("-")[0]


def django_example_settings() -> dict[str, Any]:
    """The example's settings, minus INSTALLED_APPS (the test settings include its app)."""
    from examples import django_app

    return {k: v for k, v in django_app.SETTINGS.items() if k != "INSTALLED_APPS"}


def _django(*, asgi: bool) -> Iterator[Send]:
    from asgiref.sync import async_to_sync
    from django.conf import settings
    from django.test import AsyncClient, Client, override_settings

    assert "uploadshield.django" in settings.INSTALLED_APPS
    with override_settings(**django_example_settings()):
        if asgi:
            client = AsyncClient()

            def send(path: str, body: bytes, headers: dict[str, str]) -> Reply:
                async def request() -> Any:
                    return await client.post(
                        path, data=body, content_type=CONTENT_TYPE, headers=headers
                    )

                response = async_to_sync(request)()
                return Reply(response.status_code, response.content, response["Content-Type"])

        else:
            sync_client = Client()

            def send(path: str, body: bytes, headers: dict[str, str]) -> Reply:
                response = sync_client.post(
                    path, data=body, content_type=CONTENT_TYPE, headers=headers
                )
                return Reply(response.status_code, response.content, response["Content-Type"])

        yield send


def _flask() -> Iterator[Send]:
    pytest.importorskip("flask")
    from examples.flask_app import app

    client = app.test_client()

    def send(path: str, body: bytes, headers: dict[str, str]) -> Reply:
        response = client.post(path, data=body, content_type=CONTENT_TYPE, headers=headers)
        return Reply(response.status_code, response.get_data(), response.content_type or "")

    yield send


def _fastapi() -> Iterator[Send]:
    pytest.importorskip("fastapi")
    from examples.fastapi_app import app
    from fastapi.testclient import TestClient

    client = TestClient(app)

    def send(path: str, body: bytes, headers: dict[str, str]) -> Reply:
        response = client.post(
            path, content=body, headers={"content-type": CONTENT_TYPE, **headers}
        )
        return Reply(response.status_code, response.content, response.headers["content-type"])

    yield send


SERVERS: dict[str, Callable[[], Iterator[Send]]] = {
    "django-wsgi": lambda: _django(asgi=False),
    "django-asgi": lambda: _django(asgi=True),
    "flask": _flask,
    "fastapi": _fastapi,
}


@pytest.fixture(params=list(SERVERS))
def app(request: pytest.FixtureRequest) -> Iterator[App]:
    for send in SERVERS[request.param]():
        yield App(request.param, send)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def noise(size: tuple[int, int], fmt: str, **options: Any) -> bytes:
    """Incompressible image data: large enough to be spooled to disk by every framework."""
    pixels = random.Random(size[0]).randbytes(size[0] * size[1] * 3)
    buf = io.BytesIO()
    Image.frombytes("RGB", size, pixels).save(buf, fmt, **options)
    return buf.getvalue()


def sanitized(data: bytes, name: str) -> bytes:
    """What the engine itself makes of an image under ``sanitized_images``."""
    result = validate(Upload.from_bytes(data, name), presets.SANITIZED_IMAGES)
    assert result.sanitized is not None
    assert result.sanitized.data is not None
    return result.sanitized.data
