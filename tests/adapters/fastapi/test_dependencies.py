"""shield.file() / shield.files(): validated, sanitized uploads as dependencies.

No ``from __future__ import annotations``: FastAPI evaluates endpoint
annotations at runtime, and these endpoints reference locally created shields.
"""

import asyncio
import io
from typing import Annotated, Any

import pytest

pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI, Request, UploadFile
from fastapi.testclient import TestClient
from PIL import Image

from tests.adapters.fastapi.app import PHP, make_app, post
from tests.support import corpus
from uploadshield import presets
from uploadshield.fastapi import UploadShield
from uploadshield.fastapi import shield as shield_module


def test_valid_file_gets_detected_content_type(client: TestClient) -> None:
    response = post(client, "/documents", "report.pdf", corpus.pdf(), content_type="text/plain")
    assert response.status_code == 200
    assert response.json()["content_type"] == "application/pdf"
    assert response.json()["name"] == "report.pdf"


@pytest.mark.parametrize(
    ("name", "data", "status", "code"),
    [
        ("cat.png", PHP, 415, "type_not_allowed"),
        ("shell.php.pdf", corpus.pdf(), 400, "filename_dangerous_extension"),
        ("../../etc/x.pdf", corpus.pdf(), 400, "filename_invalid"),
        ("invoice.pdf", corpus.pdf_with_javascript(), 400, "pdf_active_content"),
        (
            "report.docx",
            corpus.ooxml("docx", extra={"word/vbaProject.bin": b"x"}),
            400,
            "office_macros",
        ),
    ],
)
def test_attacks_are_refused(
    client: TestClient, name: str, data: bytes, status: int, code: str
) -> None:
    response = post(client, "/documents", name, data)
    assert response.status_code == status
    detail = response.json()["detail"]
    assert detail["error"] == "upload_rejected"
    assert detail["files"][0]["field"] == "file"
    assert detail["files"][0]["errors"][0]["code"] == code
    assert "details" not in detail["files"][0]["errors"][0]


def test_raw_filenames_reach_the_engine(client: TestClient) -> None:
    # Starlette passes the client's filename through untouched; the engine refuses it.
    response = post(client, "/documents", "..\\..\\boot.ini.pdf", corpus.pdf())
    assert response.status_code == 400


def test_size_limit(client: TestClient) -> None:
    response = post(client, "/tiny", "big.png", corpus.image("PNG", size=(300, 300)))
    assert response.status_code == 413


def test_sanitized_avatar(client: TestClient) -> None:
    response = post(client, "/avatar", "me.jpg", corpus.jpeg_with_metadata(), field="picture")
    assert response.status_code == 200
    body = response.json()
    assert body["name"].endswith(".jpg")
    assert body["name"] != "me.jpg"
    assert body["content_type"] == "image/jpeg"


def test_sanitized_bytes_have_no_metadata() -> None:
    shield = UploadShield()
    app = FastAPI()

    @app.post("/raw")
    async def raw(file: Annotated[UploadFile, Depends(shield.file("sanitized_images"))]):
        data = file.file.read()
        with Image.open(io.BytesIO(data)) as image:
            return {"exif": len(image.getexif()), "has_cam": b"EvilCam" in data}

    response = post(TestClient(app), "/raw", "me.jpg", corpus.jpeg_with_metadata())
    assert response.json() == {"exif": 0, "has_cam": False}


def test_alias_is_the_form_field(client: TestClient) -> None:
    response = post(client, "/avatar", "me.jpg", corpus.jpeg_with_metadata(), field="file")
    assert response.status_code == 422  # FastAPI's own "field required"


def test_multiple_files(client: TestClient) -> None:
    files = [
        ("files", ("a.png", corpus.png(), "image/png")),
        ("files", ("b.gif", corpus.image("GIF"), "image/gif")),
    ]
    ok = client.post("/gallery", files=files)
    assert ok.status_code == 200
    assert [f["content_type"] for f in ok.json()] == ["image/png", "image/gif"]
    bad = client.post("/gallery", files=[*files, ("files", ("c.png", PHP, "image/png"))])
    assert bad.status_code == 415
    assert [f["name"] for f in bad.json()["detail"]["files"]] == ["c.png"]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_report_mode_and_callbacks(asynchronous: bool) -> None:
    seen: list[Any] = []

    def sync_callback(request: Any, rejected: list[Any]) -> None:
        seen.append((request.url.path, [(f, r.codes) for f, r in rejected]))

    async def async_callback(request: Any, rejected: list[Any]) -> None:
        sync_callback(request, rejected)

    shield = UploadShield(
        mode="report", on_rejected=async_callback if asynchronous else sync_callback
    )
    response = post(TestClient(make_app(shield)), "/documents", "cat.png", PHP)
    assert response.status_code == 200  # report mode lets it through
    assert seen == [("/documents", [("file", ("type_not_allowed",))])]


def test_off_mode_and_options() -> None:
    off = TestClient(make_app(UploadShield(mode="off")))
    assert post(off, "/documents", "cat.png", PHP).status_code == 200
    detailed = UploadShield(expose_details=True, messages={"type_not_allowed": "Nur PDFs!"})
    response = post(TestClient(make_app(detailed)), "/documents", "cat.png", PHP)
    error = response.json()["detail"]["files"][0]["errors"][0]
    assert error["message"] == "Nur PDFs!"
    assert error["details"]["detected_type"] == "application/x-httpd-php"
    with pytest.raises(ValueError, match="mode must be"):
        UploadShield(mode="strict")
    with pytest.raises(ValueError, match="Unknown upload policy"):
        UploadShield().file("nope")


def test_validation_runs_off_the_event_loop(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_loop: list[bool] = []
    real = shield_module.validate

    def spy(*args: Any, **kwargs: Any) -> Any:
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return real(*args, **kwargs)

    monkeypatch.setattr(shield_module, "validate", spy)
    assert post(client, "/documents", "a.pdf", corpus.pdf()).status_code == 200
    assert on_loop == [False]


def test_rejections_are_logged(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    import logging

    caplog.set_level(logging.WARNING, logger="uploadshield")
    post(client, "/documents", "cat.png", PHP)
    record = next(r for r in caplog.records if r.name == "uploadshield")
    details = record.__dict__["upload"]
    assert details["path"] == "/documents"
    assert details["policy"] == "documents"
    assert len(details["sha256"]) == 64


def test_sync_endpoints_forms_and_several_file_dependencies() -> None:
    from fastapi import Form

    shield = UploadShield()
    app = FastAPI()

    @app.post("/application")
    def application(  # a plain `def`: FastAPI runs it in the thread pool
        name: Annotated[str, Form()],
        cv: Annotated[UploadFile, Depends(shield.file("pdf", alias="cv"))],
        photo: Annotated[UploadFile, Depends(shield.file("sanitized_images", alias="photo"))],
    ):
        return {
            "name": name,
            "cv": (cv.filename, cv.content_type, len(cv.file.read())),
            "photo": (photo.filename, photo.content_type, b"EvilCam" in photo.file.read()),
        }

    client = TestClient(app)
    pdf = corpus.pdf()
    files = {"cv": ("cv.pdf", pdf), "photo": ("me.jpg", corpus.jpeg_with_metadata())}
    body = client.post("/application", data={"name": "Ada"}, files=files).json()
    assert body["name"] == "Ada"
    assert body["cv"] == ["cv.pdf", "application/pdf", len(pdf)]
    assert body["photo"][0] != "me.jpg"
    assert body["photo"][1:] == ["image/jpeg", False]
    swapped = {"cv": ("cv.pdf", corpus.png()), "photo": ("me.jpg", corpus.image("JPEG"))}
    response = client.post("/application", data={"name": "Ada"}, files=swapped)
    assert response.status_code == 415
    assert response.json()["detail"]["files"][0]["field"] == "cv"


def test_large_files_rolled_to_disk_are_validated_and_sanitized() -> None:
    import random

    shield = UploadShield()
    app = FastAPI()

    @app.post("/avatar")
    async def avatar(file: Annotated[UploadFile, Depends(shield.file("sanitized_images"))]):
        data = await file.read()  # the async API works on sanitized files too
        await file.seek(0)
        return {"size": len(data), "again": len(await file.read()), "type": file.content_type}

    @app.put("/scan")
    async def scan(file: Annotated[UploadFile, Depends(shield.file("images"))]):
        return {"size": len(await file.read())}

    pixels = random.Random(1).randbytes(1000 * 800 * 3)
    buf = io.BytesIO()
    Image.frombytes("RGB", (1000, 800), pixels).save(buf, "PNG")
    big = buf.getvalue()
    assert len(big) > 1024 * 1024  # Starlette rolls these over to disk
    client = TestClient(app)
    response = client.post("/avatar", files={"file": ("big.png", big)})
    body = response.json()
    assert body["size"] == body["again"] > 0
    assert body["type"] == "image/png"
    assert client.put("/scan", files={"file": ("big.png", big)}).json() == {"size": len(big)}
    assert client.put("/scan", files={"file": ("cat.png", PHP)}).status_code == 415


def test_report_mode_delivers_the_original_upload() -> None:
    client = TestClient(make_app(UploadShield(mode="report")))
    response = post(client, "/documents", "cat.pdf", PHP, content_type="application/pdf")
    assert response.json() == {
        "name": "cat.pdf",
        "content_type": "application/pdf",  # untouched: the client's own claim
        "size": len(PHP),
        "data": PHP.hex(),
    }


def test_custom_exception_handler_and_policy_registry() -> None:
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    shield = UploadShield(
        policies={"invoices": presets.PDF.replace(name="invoices", max_size=10_000)},
        default_policy="invoices",
    )
    app = FastAPI(dependencies=[Depends(shield.all_files())])

    @app.exception_handler(HTTPException)
    async def problem_json(request: Any, exc: HTTPException) -> JSONResponse:
        detail: Any = exc.detail
        codes = [e["code"] for f in detail["files"] for e in f["errors"]]
        return JSONResponse({"title": "Bad upload", "codes": codes}, status_code=exc.status_code)

    @app.post("/invoices")
    async def invoices(file: Annotated[UploadFile, Depends(shield.file())]):  # default policy
        return {"ok": True}

    @app.post("/dotted")
    async def dotted(
        file: Annotated[
            UploadFile, Depends(shield.file("tests.django_site.testapp.policies.CUSTOM"))
        ],
    ):
        return {"type": file.content_type}

    client = TestClient(app)
    response = post(client, "/invoices", "big.pdf", corpus.pdf() + b"%" + b"x" * 20_000)
    assert (response.status_code, response.json()) == (
        413,
        {"title": "Bad upload", "codes": ["file_too_large"]},
    )
    assert post(client, "/invoices", "a.pdf", corpus.pdf()).json() == {"ok": True}
    assert post(client, "/dotted", "a.txt", b"hello").json() == {"type": "text/plain"}


def test_sanitization_happens_in_place() -> None:
    # The route's own parameter, the dependency and request.form() share one object.
    shield = UploadShield()
    app = FastAPI()

    @app.post("/avatar", dependencies=[Depends(shield.file("sanitized_images"))])
    async def avatar(request: Request, file: UploadFile):
        form = await request.form()
        return {**describe_upload(file), "same": form["file"] is file}

    @app.post("/both")
    async def both(
        file: UploadFile,
        checked: Annotated[UploadFile, Depends(shield.file("sanitized_images"))],
    ):
        return {"same": checked is file, **describe_upload(file)}

    client = TestClient(app)
    for path in ("/avatar", "/both"):
        body = post(client, path, "me.jpg", corpus.jpeg_with_metadata()).json()
        assert body["same"] is True
        assert body["name"] != "me.jpg"  # randomized
        assert body["content_type"] == "image/jpeg"
        assert body["exif"] is False


def describe_upload(upload: UploadFile) -> dict[str, Any]:
    data = upload.file.read()
    with Image.open(io.BytesIO(data)) as image:
        exif = bool(image.getexif())
    return {"name": upload.filename, "content_type": upload.content_type, "exif": exif}


def test_hashing_refused_files_runs_off_the_event_loop(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_loop: list[bool] = []
    real = shield_module.web.sha256_of

    def spy(*args: Any, **kwargs: Any) -> Any:
        try:
            asyncio.get_running_loop()
            on_loop.append(True)
        except RuntimeError:
            on_loop.append(False)
        return real(*args, **kwargs)

    monkeypatch.setattr(shield_module.web, "sha256_of", spy)
    assert post(client, "/documents", "cat.pdf", PHP).status_code == 415
    assert on_loop == [False]
