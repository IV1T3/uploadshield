"""OWASP File Upload Cheat Sheet - User Permissions.

Authentication is the application's job; what matters here is the order.  Set up as
docs/OWASP.md describes, anonymous requests are refused before their files are parsed
or validated, so they cannot make the server do the work.

No ``from __future__ import annotations``: FastAPI evaluates endpoint annotations at
runtime, and these endpoints use locally imported names.
"""

import io
from typing import Any

import pytest

from tests.support import corpus
from uploadshield import Upload

owasp = pytest.mark.owasp


# --------------------------------------------------------------------------- #
# User permissions: authenticate before anything is parsed or validated
# --------------------------------------------------------------------------- #


@pytest.fixture
def validations(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    import uploadshield.engine

    seen: list[str] = []
    real = uploadshield.engine.validate

    def spy(upload: Upload, *args: Any, **kwargs: Any) -> Any:
        seen.append(upload.name)
        return real(upload, *args, **kwargs)

    for module in ("uploadshield.flask.core", "uploadshield.fastapi.shield"):
        target = pytest.importorskip(module)
        monkeypatch.setattr(target, "validate", spy)
    return seen


@owasp("permissions.authentication")
def test_flask_hooks_registered_first_run_before_validation(validations: list[str]) -> None:
    pytest.importorskip("flask")
    from flask import Flask, abort, request

    from uploadshield.flask import UploadShield

    app = Flask(__name__)

    @app.before_request
    def require_login() -> None:
        if request.headers.get("Authorization") != "Bearer ok":
            abort(401)

    UploadShield(app)  # after the authentication hook

    @app.post("/upload")
    def upload() -> str:
        return "ok"

    client = app.test_client()
    data = {"file": (io.BytesIO(corpus.png()), "a.png")}
    assert client.post("/upload", data=data).status_code == 401
    assert validations == []  # anonymous requests are never validated
    data = {"file": (io.BytesIO(corpus.png()), "a.png")}
    assert (
        client.post("/upload", data=data, headers={"Authorization": "Bearer ok"}).status_code == 200
    )
    assert validations == ["a.png"]


@owasp("permissions.authentication")
def test_fastapi_auth_dependencies_listed_first_run_before_validation(
    validations: list[str],
) -> None:
    pytest.importorskip("fastapi")
    from fastapi import Depends, FastAPI, HTTPException, Request
    from fastapi.testclient import TestClient

    from uploadshield.fastapi import UploadShield

    def require_login(request: Request) -> None:
        if request.headers.get("Authorization") != "Bearer ok":
            raise HTTPException(status_code=401)

    shield = UploadShield()
    app = FastAPI(dependencies=[Depends(require_login), Depends(shield.all_files())])

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    files = {"file": ("a.png", corpus.png())}
    assert client.post("/upload", files=files).status_code == 401
    assert validations == []
    assert (
        client.post("/upload", files=files, headers={"Authorization": "Bearer ok"}).status_code
        == 200
    )
    assert validations == ["a.png"]
