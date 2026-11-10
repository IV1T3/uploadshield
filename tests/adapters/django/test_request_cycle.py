"""End-to-end behaviour through Django's request/response cycle."""

from __future__ import annotations

import hashlib
import io
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from asgiref.sync import async_to_sync
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import AsyncClient, Client, override_settings
from PIL import Image

from tests.django_site.settings import (
    DJANGO_UPLOAD_HANDLERS,
    FILE_UPLOAD_HANDLERS,
    UPLOADSHIELD,
)
from tests.support import corpus
from uploadshield.django import upload_rejected, upload_validated

PHP = b"<?php system($_GET['cmd']); ?>"
JSON = {"Accept": "application/json"}


def upload(name: str, data: bytes, content_type: str = "application/octet-stream"):
    return SimpleUploadedFile(name, data, content_type=content_type)


def apost(client: AsyncClient, path: str, data: dict[str, Any], **kwargs: Any) -> Any:
    """Drive AsyncClient from a sync test (portable across Django 4.2-6.x)."""

    async def request() -> Any:
        return await client.post(path, data, **kwargs)

    return async_to_sync(request)()


def settings_with(**overrides: Any) -> dict[str, Any]:
    return {**UPLOADSHIELD, **overrides}


@pytest.fixture
def client() -> Client:
    return Client()


@pytest.fixture
def signals() -> Iterator[dict[str, list[dict[str, Any]]]]:
    seen: dict[str, list[dict[str, Any]]] = {"validated": [], "rejected": []}

    def on_validated(**kwargs: Any) -> None:
        seen["validated"].append(kwargs)

    def on_rejected(**kwargs: Any) -> None:
        seen["rejected"].append(kwargs)

    upload_validated.connect(on_validated)
    upload_rejected.connect(on_rejected)
    yield seen
    upload_validated.disconnect(on_validated)
    upload_rejected.disconnect(on_rejected)


# --------------------------------------------------------------------------- #
# ValidatingUploadHandler (global safety net)
# --------------------------------------------------------------------------- #


def test_handler_accepts_valid_files_and_normalises_content_type(client: Client) -> None:
    response = client.post(
        "/plain/", {"file": upload("a.png", corpus.png(), "text/plain"), "title": "hello"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["validated"] is True
    assert body["files"][0]["content_type"] == "image/png"  # detected, not client-declared
    assert body["post"] == {"title": ["hello"]}  # other fields untouched (legacy bug)


def test_handler_rejects_disguised_script_with_json(client: Client, signals) -> None:
    response = client.post("/plain/", {"file": upload("cat.png", PHP, "image/png")}, headers=JSON)
    assert response.status_code == 415
    assert response.json() == {
        "error": "upload_rejected",
        "message": "The upload was rejected.",
        "files": [
            {
                "field": "file",
                "name": "cat.png",
                "errors": [
                    {"code": "type_not_allowed", "message": "PHP script files are not allowed."}
                ],
            }
        ],
    }
    assert len(signals["rejected"]) == 1
    assert signals["rejected"][0]["enforced"] is True


def test_rejection_html_is_escaped(client: Client) -> None:
    name = '<img src=x onerror="alert(1)">.png'  # refused for its name, and echoed back
    response = client.post("/plain/", {"file": upload(name, PHP)})
    assert response.status_code == 400
    html = response.content.decode()
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html
    assert "The file name contains invalid characters." in html


@pytest.mark.parametrize(
    ("name", "data", "status", "code"),
    [
        ("big.png", corpus.image("PNG", size=(4000, 4000)), 413, "file_too_large"),
        ("a.png", corpus.image("JPEG"), 415, "extension_mismatch"),
        ("shell.php.png", corpus.png(), 400, "filename_dangerous_extension"),
        ("x.pdf", corpus.pdf_with_javascript(), 400, "pdf_active_content"),
        (
            "x.docx",
            corpus.ooxml("docx", extra={"word/vbaProject.bin": b"x"}),
            400,
            "office_macros",
        ),
        ("x.png", corpus.png() + b"<?php echo 1; ?>", 400, "embedded_code"),
    ],
)
def test_status_codes(client: Client, name: str, data: bytes, status: int, code: str) -> None:
    target = "/tiny/" if code == "file_too_large" else "/plain/"
    response = client.post(target, {"file": upload(name, data)}, headers=JSON)
    assert response.status_code == status
    assert response.json()["files"][0]["errors"][0]["code"] == code


def test_any_bad_file_rejects_the_whole_request(client: Client) -> None:
    files = [upload("ok.png", corpus.png()), upload("bad.png", PHP)]
    response = client.post("/plain/", {"file": files}, headers=JSON)
    assert response.status_code == 415
    assert [f["name"] for f in response.json()["files"]] == ["bad.png"]


def test_requests_without_files_are_not_inspected(client: Client) -> None:
    assert client.get("/plain/").json()["validated"] is False
    response = client.post("/plain/", data=b'{"a": 1}', content_type="application/json")
    assert response.json()["validated"] is False
    response = client.post("/plain/", {"title": "no files"})
    assert response.json()["validated"] is True
    assert response.json()["files"] == []


@pytest.mark.owasp("intro.csrf")
def test_csrf_runs_before_file_inspection(signals) -> None:
    client = Client(enforce_csrf_checks=True)
    response = client.post("/plain/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 403  # CSRF failure, not an upload rejection
    assert signals["validated"] == []


def test_view_policies_by_url_name(client: Client) -> None:
    response = client.post("/legacy/upload/", {"file": upload("a.png", corpus.png())}, headers=JSON)
    assert response.status_code == 415  # 'legacy-*' -> pdf policy
    response = client.post("/legacy/upload/", {"file": upload("a.pdf", corpus.pdf())})
    assert response.status_code == 200
    response = client.post("/unprotected/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 200  # 'unprotected-*' -> None (skip)
    assert response.json()["validated"] is False


def test_report_mode_logs_but_lets_files_through(client: Client, signals, upload_log) -> None:
    with override_settings(UPLOADSHIELD=settings_with(MODE="report")):
        response = client.post("/plain/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 200
    assert response.json()["rejected"] == 1
    assert signals["rejected"][0]["enforced"] is False
    record = next(r for r in upload_log.records if "report mode" in r.getMessage())
    assert record.levelno == logging.WARNING
    details = record.__dict__["upload"]
    assert details["sha256"] == hashlib.sha256(PHP).hexdigest()
    assert details["detected_type"] == "application/x-httpd-php"
    assert details["policy"] == "default"
    assert details["path"] == "/plain/"


def test_global_off_mode_and_no_default_policy(client: Client) -> None:
    with override_settings(UPLOADSHIELD=settings_with(MODE="off")):
        assert client.post("/images/", {"file": upload("cat.png", PHP)}).status_code == 200
    with override_settings(UPLOADSHIELD=settings_with(DEFAULT_POLICY=None)):
        assert client.post("/plain/", {"file": upload("cat.png", PHP)}).status_code == 200
        # explicit decorators still enforce
        assert client.post("/images/", {"file": upload("cat.png", PHP)}).status_code == 415


def test_expose_details_and_message_overrides(client: Client) -> None:
    config = settings_with(EXPOSE_DETAILS=True, MESSAGES={"type_not_allowed": "Nur Bilder!"})
    with override_settings(UPLOADSHIELD=config):
        response = client.post("/images/", {"file": upload("cat.png", PHP)}, headers=JSON)
    error = response.json()["files"][0]["errors"][0]
    assert error["message"] == "Nur Bilder!"
    assert error["details"]["detected_type"] == "application/x-httpd-php"
    assert response.json()["files"][0]["detected_type"] == "application/x-httpd-php"


def test_custom_rejection_handler(client: Client) -> None:
    config = settings_with(REJECTION_HANDLER="tests.django_site.testapp.policies.teapot_handler")
    with override_settings(UPLOADSHIELD=config):
        response = client.post("/plain/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 418
    assert response.content == b"teapot:1"


# --------------------------------------------------------------------------- #
# Decorators
# --------------------------------------------------------------------------- #


def test_decorated_view_uses_its_policy(client: Client) -> None:
    assert client.post("/images/", {"file": upload("a.png", corpus.png())}).status_code == 200
    assert client.post("/images/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 415
    assert client.post("/bare/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200


def test_sanitization_replaces_files_seen_by_the_view(client: Client) -> None:
    original = corpus.jpeg_with_metadata()
    response = client.post("/avatar/", {"file": upload("me.jpeg", original, "image/jpeg")})
    assert response.status_code == 200
    file = response.json()["files"][0]
    assert file["name"].endswith(".jpg")
    assert file["name"] != "me.jpeg"
    assert file["content_type"] == "image/jpeg"
    assert file["sha256"] != hashlib.sha256(original).hexdigest()


def test_sanitization_of_multiple_files_keeps_order(client: Client) -> None:
    files = [
        upload("1.png", corpus.image("PNG", size=(1, 1))),
        upload("2.png", corpus.image("PNG", size=(2, 2))),
    ]
    response = client.post("/avatar/", {"file": files})
    assert response.status_code == 200
    names = [f["name"] for f in response.json()["files"]]
    assert len(names) == 2
    assert all(n.endswith(".png") and len(n) == 36 for n in names)


def test_per_field_policies(client: Client) -> None:
    ok = {
        "doc": upload("a.pdf", corpus.pdf()),
        "photo": upload("a.png", corpus.png()),
        "notes": upload("anything.exe", corpus.pe_executable()),
    }
    assert client.post("/multi/", ok).status_code == 200  # 'notes' is explicitly skipped
    swapped = {"doc": upload("a.png", corpus.png()), "photo": upload("a.pdf", corpus.pdf())}
    response = client.post("/multi/", swapped, headers=JSON)
    assert response.status_code == 415
    assert [f["field"] for f in response.json()["files"]] == ["doc"]  # fails fast


def test_skip_upload_validation(client: Client) -> None:
    response = client.post("/raw/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 200
    assert response.json()["validated"] is False


def test_per_view_report_mode(client: Client, signals) -> None:
    response = client.post("/report/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 200
    assert signals["rejected"][0]["enforced"] is False


def test_redirect_with_messages(client: Client) -> None:
    response = client.post("/redirecting/", {"file": upload("cat.png", PHP)}, follow=True)
    assert response.redirect_chain == [("/done/", 302)]
    assert response.json()["messages"] == ["cat.png: PHP script files are not allowed."]


def test_class_based_view(client: Client) -> None:
    assert client.post("/pdf-view/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200
    assert client.post("/pdf-view/", {"file": upload("a.png", corpus.png())}).status_code == 415
    assert client.get("/pdf-view/").status_code == 405


def test_validation_runs_once_with_handler_and_decorator(client: Client, signals) -> None:
    client.post("/images/", {"file": upload("a.png", corpus.png())})
    assert len(signals["validated"]) == 1


@override_settings(FILE_UPLOAD_HANDLERS=DJANGO_UPLOAD_HANDLERS)
def test_decorators_enforce_without_the_handler(client: Client, signals) -> None:
    assert client.post("/plain/", {"file": upload("cat.png", PHP)}).status_code == 200
    assert client.post("/images/", {"file": upload("cat.png", PHP)}).status_code == 415
    assert client.post("/pdf-view/", {"file": upload("a.png", corpus.png())}).status_code == 415
    response = client.post("/avatar/", {"file": upload("a.png", corpus.png())})
    assert response.json()["files"][0]["name"] != "a.png"  # sanitized by the decorator
    assert len(signals["validated"]) == 3


@pytest.mark.parametrize("handlers", [FILE_UPLOAD_HANDLERS, DJANGO_UPLOAD_HANDLERS])
@pytest.mark.parametrize("path", ["/async-images/", "/async-image-view/"])
def test_async_views_under_asgi(handlers: list[str], path: str) -> None:
    async_client = AsyncClient()
    with override_settings(FILE_UPLOAD_HANDLERS=handlers):
        good = apost(async_client, path, {"file": upload("a.png", corpus.png())})
        bad = apost(async_client, path, {"file": upload("cat.png", PHP)}, headers=JSON)
    assert good.status_code == 200
    assert good.json()["validated"] is True
    assert bad.status_code == 415


def test_sync_views_under_asgi() -> None:
    async_client = AsyncClient()
    response = apost(async_client, "/plain/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 415
    response = apost(async_client, "/avatar/", {"file": upload("a.png", corpus.png())})
    assert response.status_code == 200


# --------------------------------------------------------------------------- #
# Size limits while streaming
# --------------------------------------------------------------------------- #


def test_oversized_files_are_aborted(client: Client) -> None:
    big = io.BytesIO()
    Image.effect_noise((300, 300), 64).save(big, "PNG")
    response = client.post("/tiny/", {"file": upload("big.png", big.getvalue())}, headers=JSON)
    assert response.status_code == 413
    assert response.json()["files"][0]["errors"][0]["code"] == "file_too_large"
    small = client.post("/tiny/", {"file": upload("a.png", corpus.png())})
    assert small.status_code == 200


@pytest.mark.owasp("limits.upload-size")
def test_global_hard_cap_applies_even_to_skipped_views(client: Client) -> None:
    with override_settings(UPLOADSHIELD=settings_with(MAX_UPLOAD_SIZE=1000)):
        response = client.post("/raw/", {"file": upload("a.bin", b"x" * 5000)}, headers=JSON)
        small = client.post("/raw/", {"keep": upload("k.txt", b"small")})
    assert response.status_code == 413
    assert small.status_code == 200


def test_report_mode_does_not_abort(client: Client) -> None:
    big = corpus.image("PNG", size=(200, 200), mode="RGB")
    with override_settings(UPLOADSHIELD=settings_with(MODE="report")):
        response = client.post("/tiny/", {"file": upload("big.png", big + b"\x00" * 5000)})
    assert response.status_code == 200
    assert response.json()["files"][0]["size"] > 2000


def test_stacked_with_django_decorators() -> None:
    client = Client(enforce_csrf_checks=True)  # csrf_exempt must survive our wrapper
    assert client.post("/stacked/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200
    assert client.post("/stacked/", {"file": upload("a.png", corpus.png())}).status_code == 415
    assert "no-cache" in client.get("/stacked/").headers["Cache-Control"]  # outer decorator ran
