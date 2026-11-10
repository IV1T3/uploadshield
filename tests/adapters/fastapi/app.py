"""A FastAPI app with one endpoint per dependency style, and request helpers.

No ``from __future__ import annotations`` (see the test modules).
"""

from typing import Annotated, Any

import pytest

pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI, UploadFile
from fastapi.testclient import TestClient

from uploadshield import presets
from uploadshield.fastapi import UploadShield

PHP = b"<?php system($_GET['cmd']); ?>"


def describe(upload: UploadFile) -> dict[str, Any]:
    data = upload.file.read()
    return {
        "name": upload.filename,
        "content_type": upload.content_type,
        "size": len(data),
        "data": data.hex() if len(data) < 64 else None,
    }


def make_app(shield: UploadShield, *, safety_net: bool = False) -> FastAPI:
    app = FastAPI(dependencies=[Depends(shield.all_files())] if safety_net else [])

    @app.post("/documents")
    async def documents(file: Annotated[UploadFile, Depends(shield.file("documents"))]):
        return describe(file)

    @app.post("/avatar")
    async def avatar(
        file: Annotated[UploadFile, Depends(shield.file("sanitized_images", alias="picture"))],
    ):
        return describe(file)

    @app.post("/gallery")
    async def gallery(files: Annotated[list[UploadFile], Depends(shield.files("images"))]):
        return [describe(f) for f in files]

    @app.post("/tiny")
    async def tiny(
        file: Annotated[UploadFile, Depends(shield.file(presets.IMAGES.replace(max_size=500)))],
    ):
        return describe(file)

    @app.post("/plain")
    async def plain(file: UploadFile):  # protected only by the safety net
        return describe(file)

    @app.post("/json")
    async def json_endpoint(payload: dict[str, Any]):
        return payload

    return app


def post(
    client: TestClient,
    path: str,
    name: str,
    data: bytes,
    *,
    field: str = "file",
    content_type: str = "application/octet-stream",
) -> Any:
    return client.post(path, files={field: (name, data, content_type)})


def raw(name: str, data: bytes, field: str = "file") -> tuple[bytes, dict[str, str]]:
    """A multipart body written by hand (httpx refuses empty filenames)."""
    boundary = "fastapi-boundary"
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + data
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return body, {"content-type": f"multipart/form-data; boundary={boundary}"}
