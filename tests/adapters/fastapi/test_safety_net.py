"""shield.all_files(): the app- or router-wide safety net.

No ``from __future__ import annotations``: FastAPI evaluates endpoint
annotations at runtime, and these endpoints reference locally created shields.
"""

from typing import Annotated, Any

import pytest

pytest.importorskip("fastapi")

from fastapi import APIRouter, Depends, FastAPI, File, Form, UploadFile, WebSocket
from fastapi.testclient import TestClient

from tests.adapters.fastapi.app import PHP, make_app, post, raw
from tests.support import corpus
from uploadshield import presets
from uploadshield.fastapi import UploadShield


def test_app_wide_safety_net() -> None:
    client = TestClient(make_app(UploadShield(), safety_net=True))
    assert post(client, "/plain", "cat.png", PHP).status_code == 415
    assert post(client, "/plain", "a.png", corpus.png()).status_code == 200
    assert client.post("/json", json={"a": 1}).json() == {"a": 1}  # not multipart: untouched


def test_router_wide_safety_net() -> None:
    shield = UploadShield()
    router = APIRouter(dependencies=[Depends(shield.all_files("pdf"))])

    @router.post("/only-pdf")
    async def only_pdf(file: UploadFile):
        return {"ok": True}

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    assert post(client, "/only-pdf", "a.png", corpus.png()).status_code == 415
    assert post(client, "/only-pdf", "a.pdf", corpus.pdf()).status_code == 200


def test_safety_net_leaves_empty_file_inputs_alone() -> None:
    shield = UploadShield()
    app = FastAPI(dependencies=[Depends(shield.all_files())])

    @app.post("/profile")
    async def profile(file: UploadFile | None = None):
        return {"file": None if file is None else file.filename}

    client = TestClient(app)
    body, headers = raw("", b"")  # an <input type="file"> left empty
    response = client.post("/profile", content=body, headers=headers)
    assert response.status_code == 200
    assert not response.json()["file"]  # None (an empty file on older FastAPI)
    body, headers = raw("", PHP)  # no name, but content: an upload
    response = client.post("/profile", content=body, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"]["files"][0]["errors"][0]["code"] == "filename_invalid"


def test_endpoint_policies_win_over_the_safety_net() -> None:
    shield = UploadShield()
    archives = presets.DEFAULT.replace(name="archives", allowed_types={"application/zip"})
    app = FastAPI(dependencies=[Depends(shield.all_files())])  # DEFAULT: no ZIP

    @app.post("/import")
    async def import_archive(
        file: Annotated[UploadFile, Depends(shield.file(archives))],
        attachment: UploadFile | None = None,
    ):
        return {"type": file.content_type, "attachment": attachment and attachment.content_type}

    client = TestClient(app)
    archive = corpus.build_zip({"a.csv": b"a,b\n"})
    ok = client.post("/import", files={"file": ("data.zip", archive)})
    assert ok.status_code == 200
    assert ok.json() == {"type": "application/zip", "attachment": None}
    # Fields without their own dependency are still covered by the safety net.
    sneaky = client.post(
        "/import", files={"file": ("data.zip", archive), "attachment": ("cat.png", PHP)}
    )
    assert sneaky.status_code == 415
    assert [f["field"] for f in sneaky.json()["detail"]["files"]] == ["attachment"]
    good = client.post(
        "/import",
        files={"file": ("data.zip", archive), "attachment": ("a.png", corpus.png(), "x/y")},
    )
    assert good.json()["attachment"] == "image/png"  # normalized in place


def test_endpoint_policies_inside_sub_dependencies_are_found() -> None:
    shield = UploadShield()
    big_media = presets.MEDIA.replace(name="big_media", allowed_types={"audio/wav"})

    async def recording(file: Annotated[UploadFile, Depends(shield.file(big_media))]):
        return file

    app = FastAPI(dependencies=[Depends(shield.all_files("pdf"))])

    @app.post("/voice")
    async def voice(upload: Annotated[UploadFile, Depends(recording)]):
        return {"type": upload.content_type}

    response = TestClient(app).post("/voice", files={"file": ("a.wav", corpus.wav())})
    assert response.json() == {"type": "audio/wav"}


def test_safety_net_normalizes_the_content_type() -> None:
    client = TestClient(make_app(UploadShield(), safety_net=True))
    response = post(client, "/plain", "a.png", corpus.png(), content_type="text/html")
    assert response.json()["content_type"] == "image/png"


def test_forms_parsed_by_the_safety_net_are_closed() -> None:
    from fastapi import Request

    shield = UploadShield()
    app = FastAPI(dependencies=[Depends(shield.all_files())])
    seen: list[Any] = []

    @app.post("/raw")
    async def raw_endpoint(request: Request):  # declares no form parameters
        form = await request.form()  # the form the safety net parsed and validated
        upload = form["file"]
        assert not isinstance(upload, str)
        seen.append(upload)
        return {"type": upload.content_type, "size": len(await upload.read())}

    big = corpus.png() + b"\x00" * (2 * 1024 * 1024)  # spooled to a temporary file
    response = TestClient(app).post("/raw", files={"file": ("a.png", big, "text/plain")})
    assert response.json() == {"type": "image/png", "size": len(big)}
    assert seen[0].file.closed  # no leaked temporary file (and no ResourceWarning)


def multipart(*parts: tuple[str, str | None, bytes], content_type: str | None = None) -> Any:
    """``(field, filename or None, data)`` parts, encoded by hand."""
    boundary = "net-boundary"
    body = b""
    for field, filename, data in parts:
        disposition = f'form-data; name="{field}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        body += f"--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n".encode() + data
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    header = content_type or "multipart/form-data"
    return {"content": body, "headers": {"content-type": f"{header}; boundary={boundary}"}}


@pytest.mark.parametrize(
    "content_type", ["Multipart/Form-Data", "MULTIPART/FORM-DATA", " multipart/form-data "]
)
def test_multipart_is_recognised_in_any_spelling(content_type: str) -> None:
    # Starlette parses these as multipart, so the safety net must check them too.  (Older
    # Starlette releases do not parse mixed case at all: the endpoint then gets no file.)
    client = TestClient(make_app(UploadShield(), safety_net=True))
    request = multipart(("file", "cat.png", PHP), content_type=content_type)
    assert client.post("/plain", **request).status_code in (415, 422)


def test_parts_without_a_filename_for_file_parameters_are_checked() -> None:
    shield = UploadShield()
    app = FastAPI(dependencies=[Depends(shield.all_files())])

    @app.post("/bytes")
    async def as_bytes(file: Annotated[bytes, File()], note: Annotated[str, Form()] = ""):
        return {"size": len(file), "note": note}

    client = TestClient(app)
    # FastAPI hands the content of a part without a filename to a bytes File() parameter.
    refused = client.post("/bytes", **multipart(("file", None, PHP)))
    assert refused.status_code == 400
    assert refused.json()["detail"]["files"][0]["errors"][0]["code"] == "filename_invalid"
    named = client.post("/bytes", **multipart(("file", "a.pdf", corpus.pdf())))
    assert named.json() == {"size": len(corpus.pdf()), "note": ""}
    # Ordinary form fields are text, not files: left alone.
    with_note = client.post(
        "/bytes", **multipart(("file", "a.pdf", corpus.pdf()), ("note", None, PHP))
    )
    assert with_note.status_code == 200


def test_extra_parts_under_a_field_an_endpoint_validates() -> None:
    # file() receives the last "file" part; the others are still in request.form().
    client = TestClient(make_app(UploadShield(), safety_net=True))
    two = multipart(("file", "evil.html", corpus.HTML), ("file", "a.pdf", corpus.pdf()))
    assert client.post("/documents", **two).status_code == 415
    pdfs = multipart(("file", "a.pdf", corpus.pdf()), ("file", "b.pdf", corpus.pdf()))
    assert client.post("/documents", **pdfs).json()["name"] == "b.pdf"


def test_websocket_routes_work_with_an_app_wide_safety_net() -> None:
    shield = UploadShield()
    app = FastAPI(dependencies=[Depends(shield.all_files())])

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    with TestClient(app).websocket_connect("/ws") as connection:
        assert connection.receive_text() == "hi"


def test_mounted_applications_need_their_own_safety_net() -> None:
    # Dependencies of the outer app never run for a mounted sub-application.
    shield = UploadShield()

    def sub_app(*, protected: bool) -> FastAPI:
        sub = FastAPI(dependencies=[Depends(shield.all_files())] if protected else [])

        @sub.post("/upload")
        async def upload(file: UploadFile):
            return {"name": file.filename}

        return sub

    app = FastAPI(dependencies=[Depends(shield.all_files())])
    app.mount("/v1", sub_app(protected=False))
    app.mount("/v2", sub_app(protected=True))
    client = TestClient(app)
    assert client.post("/v1/upload", **multipart(("file", "cat.png", PHP))).status_code == 200
    assert client.post("/v2/upload", **multipart(("file", "cat.png", PHP))).status_code == 415
