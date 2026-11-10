"""A Flask app with one endpoint per integration style, and request helpers."""

from __future__ import annotations

import io
from typing import Any

import pytest

pytest.importorskip("flask")

from flask import Flask, jsonify, redirect, request
from PIL import Image

from uploadshield import presets
from uploadshield.flask import (
    UploadShield,
    get_upload_results,
    skip_upload_validation,
    validate_uploads,
)

PHP = b"<?php system($_GET['cmd']); ?>"
JSON = {"Accept": "application/json"}


def describe() -> Any:
    files = []
    for field, storage in request.files.items(multi=True):
        data = storage.read()
        files.append(
            {
                "field": field,
                "name": storage.filename,
                "content_type": storage.content_type,
                "size": len(data),
                "exif": _exif(data),
                "cam": b"EvilCam" in data,
            }
        )
    results = get_upload_results()
    return jsonify({"files": files, "validated": results is not None})


def _exif(data: bytes) -> int | None:
    try:
        with Image.open(io.BytesIO(data)) as image:
            return len(image.getexif())
    except Exception:
        return None


def make_app(config: dict[str, Any] | None = None, *, extension: bool = True) -> Flask:
    app = Flask(__name__)
    app.config["UPLOADSHIELD"] = {"ENDPOINT_POLICIES": {"legacy*": "pdf"}, **(config or {})}
    if extension:
        UploadShield(app)

    @app.post("/plain")
    def plain():
        return describe()

    @app.post("/documents")
    @validate_uploads("documents")
    def documents():
        return describe()

    @app.post("/avatar")
    @validate_uploads("sanitized_images")
    def avatar():
        return describe()

    @app.post("/multi")
    @validate_uploads(fields={"doc": "pdf", "photo": "images", "notes": None})
    def multi():
        return describe()

    @app.post("/raw")
    @skip_upload_validation
    def raw():
        return describe()

    @app.post("/tiny")
    @validate_uploads(presets.IMAGES.replace(max_size=500))
    def tiny():
        return describe()

    @app.post("/redirecting")
    @validate_uploads("images", on_reject=lambda rejected: redirect("/done"))
    def redirecting():
        return describe()

    @app.post("/legacy-upload")
    def legacy_upload():
        return describe()

    @app.post("/async")
    @validate_uploads("images")
    async def async_view():
        return describe()

    @app.post("/json")
    def json_view():
        return jsonify(request.get_json())

    return app


def send(
    client: Any,
    path: str,
    name: str,
    data: bytes,
    *,
    field: str = "file",
    headers: dict[str, str] | None = None,
) -> Any:
    return client.post(path, data={field: (io.BytesIO(data), name)}, headers=headers or JSON)


BOUNDARY = "flask-boundary"


def raw_multipart(name: str, data: bytes, *, field: str = "file") -> bytes:
    """A part exactly as written here (the test client drops empty filenames)."""
    return (
        (
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + data
        + f"\r\n--{BOUNDARY}--\r\n".encode()
    )


def send_raw(client: Any, path: str, body: bytes, method: str = "post") -> Any:
    content_type = f"multipart/form-data; boundary={BOUNDARY}"
    return getattr(client, method)(path, data=body, content_type=content_type, headers=JSON)


def noise(fmt: str) -> bytes:
    """An incompressible image above Werkzeug's 500 KB in-memory limit."""
    import random

    buf = io.BytesIO()
    pixels = random.Random(0).randbytes(800 * 600 * 3)
    Image.frombytes("RGB", (800, 600), pixels).save(buf, fmt, quality=95)
    assert len(buf.getvalue()) > 500 * 1024
    return buf.getvalue()
