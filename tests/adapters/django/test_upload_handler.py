"""ValidatingUploadHandler: streaming checks, inner-handler composition, modes, parsers."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from typing import Any

import django
import pytest
from asgiref.sync import async_to_sync
from django.core.exceptions import ImproperlyConfigured
from django.core.files.uploadedfile import SimpleUploadedFile
from django.middleware import csrf
from django.test import AsyncClient, Client, override_settings

from tests.django_site.settings import DJANGO_UPLOAD_HANDLERS, MIDDLEWARE, UPLOADSHIELD
from tests.django_site.testapp.handlers import STORED
from tests.support import corpus
from uploadshield.django import upload_validated

PHP = b"<?php system($_GET['cmd']); ?>"
JSON = {"Accept": "application/json"}
COUNTING = "tests.django_site.testapp.handlers.CountingTemporaryHandler"
has_drf = pytest.mark.skipif(not importlib.util.find_spec("rest_framework"), reason="needs DRF")


def upload(name: str, data: bytes, content_type: str = "application/octet-stream"):
    return SimpleUploadedFile(name, data, content_type=content_type)


def config(**overrides: Any) -> dict[str, Any]:
    return {**UPLOADSHIELD, **overrides}


@pytest.fixture
def counting() -> Iterator[dict[str, int]]:
    """Store uploads through a handler that counts the bytes it receives."""
    STORED.clear()
    with override_settings(UPLOADSHIELD=config(UPLOAD_HANDLERS=[COUNTING])):
        yield STORED


@pytest.fixture
def client() -> Client:
    return Client()


# --------------------------------------------------------------------------- #
# Streaming: refused files are never stored in full
# --------------------------------------------------------------------------- #


@pytest.mark.owasp("intro.input-first")
def test_dangerous_name_is_refused_before_any_byte_is_stored(client, counting) -> None:
    response = client.post("/plain/", {"file": upload("shell.php.png", corpus.png())}, headers=JSON)
    assert response.status_code == 400
    assert response.json()["files"][0]["errors"][0]["code"] == "filename_dangerous_extension"
    assert "shell.php.png" not in counting  # the storage handler never saw the file


def test_disallowed_type_is_refused_after_the_first_chunk(client, counting) -> None:
    payload = b"MZ" + b"\x00" * (5 * 1024 * 1024)  # 5 MiB "image" that is an executable
    response = client.post("/images/", {"file": upload("cat.png", payload)}, headers=JSON)
    assert response.status_code == 415
    assert counting["cat.png"] == 0  # refused on the first chunk, before storage


@pytest.mark.owasp("limits.upload-size", "threat.huge-files")
def test_oversized_file_is_refused_mid_stream(client, counting) -> None:
    payload = b"a,b\n" * 100_000  # 400 kB of allowed CSV, limit is 1 MB for 'text'
    with override_settings(
        UPLOADSHIELD=config(UPLOAD_HANDLERS=[COUNTING], MAX_UPLOAD_SIZE=100_000)
    ):
        response = client.post("/plain/", {"file": upload("big.csv", payload)}, headers=JSON)
    assert response.status_code == 413
    assert counting["big.csv"] <= 100_000  # nothing past the limit reached storage


def test_containers_are_decided_on_the_complete_file(client, counting) -> None:
    docm = corpus.ooxml("docm")  # a ZIP: DOCX vs DOCM needs the central directory
    response = client.post("/plain/", {"file": upload("report.docx", docm)}, headers=JSON)
    assert response.status_code == 415
    assert counting["report.docx"] == len(docm)


def test_allowed_files_flow_through_the_inner_handlers(client, counting) -> None:
    response = client.post("/plain/", {"file": upload("a.png", corpus.png())})
    assert response.status_code == 200
    assert counting["a.png"] == len(corpus.png())


def test_memory_and_temporary_storage_are_preserved(client) -> None:
    small = client.post("/kinds/", {"file": upload("a.png", corpus.png())}).json()
    assert small == {"file": ["InMemoryUploadedFile"]}
    with override_settings(FILE_UPLOAD_MAX_MEMORY_SIZE=10):
        big = client.post("/kinds/", {"file": upload("a.png", corpus.png())}).json()
    assert big == {"file": ["TemporaryUploadedFile"]}


def test_sanitized_file_is_what_the_view_receives(client) -> None:
    response = client.post("/avatar/", {"file": upload("me.jpg", corpus.jpeg_with_metadata())})
    file = response.json()["files"][0]
    assert file["name"].endswith(".jpg")
    assert file["name"] != "me.jpg"


def test_inner_handlers_that_parse_everything_are_refused(client) -> None:
    short = config(UPLOAD_HANDLERS=["tests.django_site.testapp.handlers.ShortCircuitHandler"])
    with override_settings(UPLOADSHIELD=short), pytest.raises(ImproperlyConfigured):
        client.post("/plain/", {"file": upload("a.png", corpus.png())})


# --------------------------------------------------------------------------- #
# Where parsing happens
# --------------------------------------------------------------------------- #


def test_parse_during_the_csrf_check_still_reaches_handler400() -> None:
    client = Client(enforce_csrf_checks=True)
    secret = csrf._get_new_csrf_string()  # private helpers build a valid cookie/token
    client.cookies["csrftoken"] = secret
    token = csrf._mask_cipher_secret(secret)  # ty: ignore[unresolved-attribute]
    data = {"csrfmiddlewaretoken": token, "file": upload("cat.png", PHP)}
    response = client.post("/images/", data, headers=JSON)
    assert response.status_code == 415
    assert response.json()["files"][0]["errors"][0]["code"] == "type_not_allowed"


def test_parse_before_routing_still_applies_the_view_policy(client) -> None:
    early = ["tests.django_site.testapp.handlers.ParseBeforeRouting", *MIDDLEWARE]
    with override_settings(MIDDLEWARE=early):
        # The handler routes the request itself: the view's 'images' policy applies.
        response = client.post("/images/", {"file": upload("a.pdf", corpus.pdf())}, headers=JSON)
        assert response.status_code == 415
        # Undecorated views get the default policy as usual.
        assert client.post("/plain/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200


@pytest.mark.owasp("permissions.authentication")
@pytest.mark.skipif(django.VERSION < (5, 1), reason="LoginRequiredMiddleware is Django 5.1+")
def test_login_required_before_csrf_prevents_parsing(counting) -> None:
    stack = [
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.auth.middleware.LoginRequiredMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
    ]
    seen: list[Any] = []
    upload_validated.connect(seen.append)
    try:
        with override_settings(MIDDLEWARE=stack, LOGIN_URL="/done/"):
            response = Client().post("/plain/", {"file": upload("a.png", corpus.png())})
    finally:
        upload_validated.disconnect(seen.append)
    assert response.status_code == 302
    assert counting == {}  # anonymous: the body was never parsed
    assert seen == []


def test_asgi(counting) -> None:
    async def post() -> Any:
        return await AsyncClient().post(
            "/plain/", {"file": upload("shell.php.png", PHP)}, headers=JSON
        )

    response = async_to_sync(post)()
    assert response.status_code == 400
    assert counting == {}


# --------------------------------------------------------------------------- #
# Inline (field) mode
# --------------------------------------------------------------------------- #


def test_field_mode_reports_precise_errors_in_plain_django_forms(client) -> None:
    response = client.post("/field-mode/", {"file": upload("cv.pdf", PHP)})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["errors"]["file"][0] == {
        "message": "PHP script files are not allowed.",
        "code": "type_not_allowed",
    }
    assert body["raw_type"] == "RejectedUpload"
    assert body["raw_bytes"] == 0  # the rejected bytes never reach the view


def test_field_mode_for_early_refusals(client, counting) -> None:
    response = client.post("/field-mode/", {"file": upload("cv.php.pdf", corpus.pdf())})
    assert response.json()["errors"]["file"][0]["code"] == "filename_dangerous_extension"
    assert "cv.php.pdf" not in counting


def test_field_mode_passes_good_files(client) -> None:
    response = client.post("/field-mode/", {"file": upload("cv.pdf", corpus.pdf())})
    assert response.json()["valid"] is True


def test_global_on_reject_field(client) -> None:
    with override_settings(UPLOADSHIELD=config(ON_REJECT="field")):
        response = client.post("/plain/", {"file": upload("cat.png", PHP)})
    assert response.status_code == 200
    assert response.json()["files"][0]["size"] == 0


def test_rejected_upload_cannot_be_measured_or_stored(client) -> None:
    from django.core.exceptions import ValidationError

    from uploadshield.django import RejectedUpload
    from uploadshield.engine import preflight
    from uploadshield.presets import IMAGES

    result = preflight(IMAGES, stages={"name"}, name="x.php.png")
    from uploadshield.django.conf import get_config

    placeholder = RejectedUpload(result, field_name="f", config=get_config())
    with pytest.raises(ValidationError):
        _ = placeholder.size
    assert placeholder.read() == b""


# --------------------------------------------------------------------------- #
# Django REST framework: every DRF parser goes through upload handlers
# --------------------------------------------------------------------------- #


@has_drf
@pytest.mark.parametrize("method", ["post", "put"])
def test_drf_multipart_post_and_put(client, method: str) -> None:
    send = getattr(client, method)
    good = (
        send("/api/documents/", {"file": upload("a.pdf", corpus.pdf())})
        if method == "post"
        else _put_multipart(client, "/api/documents/", "a.pdf", corpus.pdf())
    )
    assert good.status_code == 200
    assert good.json() == {"files": {"file": ["a.pdf"]}, "validated": True}
    bad = (
        send("/api/documents/", {"file": upload("cat.pdf", PHP)})
        if method == "post"
        else _put_multipart(client, "/api/documents/", "cat.pdf", PHP)
    )
    assert bad.status_code == 400  # DRF's own ParseError response
    assert "Upload rejected" in bad.json()["detail"]


def _put_multipart(client: Client, path: str, name: str, data: bytes) -> Any:
    from django.test.client import BOUNDARY, MULTIPART_CONTENT, encode_multipart

    body = encode_multipart(BOUNDARY, {"file": upload(name, data)})
    return client.put(path, body, content_type=MULTIPART_CONTENT)


@has_drf
def test_drf_raw_file_upload_parser(client) -> None:
    good = client.put(
        "/api/raw/report.pdf",
        corpus.pdf(),
        content_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=report.pdf"},
    )
    assert good.status_code == 200
    assert good.json() == {"files": {"file": ["report.pdf"]}, "validated": True}
    bad = client.put(
        "/api/raw/cat.pdf",
        PHP,
        content_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=cat.pdf", **JSON},
    )
    assert bad.status_code == 415  # not caught by DRF: answered by handler400


@has_drf
@override_settings(FILE_UPLOAD_HANDLERS=DJANGO_UPLOAD_HANDLERS)
def test_drf_put_and_raw_bodies_are_validated_by_the_decorator_alone(client) -> None:
    # Django never parses PUT or raw bodies; DRF does, later, through upload handlers.
    good = _put_multipart(client, "/api/documents/", "a.pdf", corpus.pdf())
    assert good.json() == {"files": {"file": ["a.pdf"]}, "validated": True}
    bad = _put_multipart(client, "/api/documents/", "cat.pdf", PHP)
    assert bad.status_code == 400
    assert "Upload rejected" in bad.json()["detail"]
    raw = client.put(
        "/api/raw/cat.pdf",
        PHP,
        content_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=cat.pdf", **JSON},
    )
    assert raw.status_code == 415


@has_drf
def test_drf_serializer_reports_inline_in_field_mode(client) -> None:
    response = client.post("/api/serializer/", {"file": upload("cat.pdf", PHP)})
    assert response.status_code == 200
    assert response.json()["errors"] == {"file": ["PHP script files are not allowed."]}


def test_handler400_leaves_other_bad_requests_to_django(client) -> None:
    response = client.get("/suspicious/")
    assert response.status_code == 400
    assert b"Bad Request" in response.content


def test_rejections_are_logged_once_without_tracebacks(client, caplog) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    client.post("/plain/", {"file": upload("cat.png", PHP)})
    django_records = [r for r in caplog.records if r.name.startswith("django.")]
    ours = [r for r in caplog.records if r.name == "uploadshield"]
    assert django_records == []
    assert len(ours) == 1
    assert ours[0].exc_info is None
    caplog.clear()
    client.get("/suspicious/")  # other bad requests keep Django's normal logging
    assert any(r.name.startswith("django.") for r in caplog.records)


# --------------------------------------------------------------------------- #
# Resources and logs of refused requests
# --------------------------------------------------------------------------- #


def test_aborted_requests_leave_no_temporary_files(client, tmp_path) -> None:
    big = corpus.image("JPEG", size=(1200, 900), quality=95)  # > 1 KiB: a temporary file
    files = {
        "a": upload("a.jpg", big),  # re-encoded: the original is replaced
        "b": upload("b.jpg", big),
        "c": upload("c.jpg", b"MZ" + bytes(20000)),  # refused after its first chunk
    }
    with override_settings(FILE_UPLOAD_MAX_MEMORY_SIZE=1024, FILE_UPLOAD_TEMP_DIR=str(tmp_path)):
        assert client.post("/avatar/", files, headers=JSON).status_code == 415
        assert list(tmp_path.iterdir()) == []  # closed (and deleted) without waiting for gc
        good = {"a": upload("a.jpg", big)}
        assert client.post("/avatar/", good, headers=JSON).status_code == 200
        assert list(tmp_path.iterdir()) == []


@pytest.mark.owasp("ufu.prevent.logging")
def test_field_names_cannot_forge_log_lines(client, caplog) -> None:
    import logging

    caplog.set_level(logging.DEBUG, logger="uploadshield")
    # RFC 2231 lets a client put any character into a field name: Django decodes it.
    forged = "f%0D%0A2026-11-09%2012:00:00%20INFO%20django.security%20login%20ok"
    body = (
        (
            "--XyZ\r\n"
            f"Content-Disposition: form-data; name*=UTF-8''{forged}; filename=\"cat.png\"\r\n"
            "Content-Type: image/png\r\n\r\n"
        ).encode()
        + PHP
        + b"\r\n--XyZ--\r\n"
    )
    multipart = "multipart/form-data; boundary=XyZ"
    response = client.post("/plain/", body, content_type=multipart, headers=JSON)
    assert response.status_code == 415
    messages = [r.getMessage() for r in caplog.records if r.name == "uploadshield"]
    assert messages
    assert not any("\n" in m or "\r" in m for m in messages)
