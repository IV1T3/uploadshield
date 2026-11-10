"""Which policy applies: decorators routing cannot see, early parses, DRF field aliases.

The upload handler validates while Django (or DRF) parses the body, so it has to find
the view's policy itself.  Every layout below once fell back to the default policy -
or to none - and must apply the view's own.
"""

from __future__ import annotations

import importlib.util
from typing import Any

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, override_settings
from django.test.client import BOUNDARY, MULTIPART_CONTENT, encode_multipart

from tests.django_site.settings import DJANGO_UPLOAD_HANDLERS, MIDDLEWARE, UPLOADSHIELD
from tests.support import corpus
from uploadshield.django.conf import get_config
from uploadshield.django.service import ViewSpec

JSON = {"Accept": "application/json"}
#: Neither the "pdf" nor the "default" policy accepts an HTML page named .pdf.
HTML = b"<!doctype html><html><body><script>alert(document.domain)</script></body></html>"
EARLY_PARSE = ["tests.django_site.testapp.handlers.ParseBeforeRouting", *MIDDLEWARE]
has_drf = pytest.mark.skipif(not importlib.util.find_spec("rest_framework"), reason="needs DRF")
without_handler = override_settings(FILE_UPLOAD_HANDLERS=DJANGO_UPLOAD_HANDLERS)


def upload(name: str, data: bytes, content_type: str = "application/pdf") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, data, content_type=content_type)


def refused(response: Any) -> bool:
    """415 from uploadshield, or DRF's 400 when the refusal happened inside DRF's parser."""
    if response.status_code == 400:
        return "Upload rejected" in response.json()["detail"]
    return response.status_code == 415


def put_multipart(client: Client, path: str, fields: dict[str, Any]) -> Any:
    body = encode_multipart(BOUNDARY, fields)
    return client.put(path, body, content_type=MULTIPART_CONTENT, headers=JSON)


@pytest.fixture
def client() -> Client:
    return Client()


# --------------------------------------------------------------------------- #
# Decorators the URL resolver cannot see
# --------------------------------------------------------------------------- #


@has_drf
@pytest.mark.parametrize("handler", ["installed", "decorator only"])
def test_drf_function_view(client: Client, handler: str) -> None:
    with override_settings(**({} if handler == "installed" else without_handler.options)):
        png = client.post("/api/function/", {"file": upload("cat.png", corpus.png())}, headers=JSON)
        assert refused(png)  # the view's "pdf" policy, not the default one
        assert refused(client.post("/api/function/", {"file": upload("a.pdf", HTML)}))
        assert refused(put_multipart(client, "/api/function/", {"file": upload("a.pdf", HTML)}))
        good = client.post("/api/function/", {"file": upload("a.pdf", corpus.pdf())})
        assert good.json() == {"files": {"file": ["a.pdf"]}, "validated": True}


@has_drf
def test_drf_function_view_without_a_default_policy(client: Client) -> None:
    with override_settings(UPLOADSHIELD={**UPLOADSHIELD, "DEFAULT_POLICY": None}):
        assert refused(client.post("/api/function/", {"file": upload("a.pdf", HTML)}))


@pytest.mark.parametrize("handler", ["installed", "decorator only"])
def test_method_decorator_on_a_view(client: Client, handler: str) -> None:
    with override_settings(**({} if handler == "installed" else without_handler.options)):
        png = client.post("/method-view/", {"file": upload("cat.png", corpus.png())}, headers=JSON)
        assert png.status_code == 415
        assert png.json()["files"][0]["errors"][0]["code"] == "type_not_allowed"
        assert (
            client.post("/method-view/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200
        )


@has_drf
@pytest.mark.parametrize("handler", ["installed", "decorator only"])
def test_method_decorator_on_a_drf_view(client: Client, handler: str) -> None:
    with override_settings(**({} if handler == "installed" else without_handler.options)):
        assert refused(client.post("/api/method/", {"file": upload("cat.png", corpus.png())}))
        assert refused(client.post("/api/method/", {"file": upload("a.pdf", HTML)}))
        assert (
            client.post("/api/method/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200
        )


# --------------------------------------------------------------------------- #
# Bodies parsed before URL routing
# --------------------------------------------------------------------------- #


def test_early_parse_still_applies_view_policies(client: Client) -> None:
    with override_settings(MIDDLEWARE=EARLY_PARSE):
        # VIEW_POLICIES maps "legacy-*" to "pdf": a PNG is refused there...
        png = client.post(
            "/legacy/upload/", {"file": upload("cat.png", corpus.png())}, headers=JSON
        )
        assert png.status_code == 415
        # ...and "unprotected-*" to None, which stays a deliberate opt-out.
        assert (
            client.post("/unprotected/", {"file": upload("cat.png", corpus.png())}).status_code
            == 200
        )
        assert client.post("/plain/", {"file": upload("a.pdf", corpus.pdf())}).status_code == 200


def test_early_parse_for_an_unknown_url_uses_the_default_policy(client: Client) -> None:
    with override_settings(MIDDLEWARE=EARLY_PARSE):
        response = client.post("/no/such/page/", {"file": upload("cat.pdf", HTML)}, headers=JSON)
        assert response.status_code == 415


# --------------------------------------------------------------------------- #
# Field names: raw bodies and DRF's list aliases
# --------------------------------------------------------------------------- #


@has_drf
def test_raw_bodies_get_the_policy_of_the_file_field(client: Client) -> None:
    def put(name: str, data: bytes, content_type: str) -> Any:
        return client.put(
            f"/api/raw-field/{name}",
            data,
            content_type=content_type,
            headers={"Content-Disposition": f"attachment; filename={name}", **JSON},
        )

    assert put("cat.png", corpus.png(), "image/png").status_code == 415
    assert put("evil.pdf", HTML, "application/pdf").status_code == 415
    assert put("a.pdf", corpus.pdf(), "application/pdf").json() == {
        "files": {"file": ["a.pdf"]},
        "validated": True,
    }


@has_drf
@pytest.mark.parametrize("field", ["attachments", "attachments[0]"])
def test_list_field_aliases_get_the_policy_of_their_field(client: Client, field: str) -> None:
    bad = client.post("/api/attachments/", {field: upload("evil.pdf", HTML)}, headers=JSON)
    assert refused(bad)
    good = client.post("/api/attachments/", {field: upload("a.pdf", corpus.pdf())})
    assert good.json() == {"stored": ["a.pdf"]}


@pytest.mark.parametrize(
    ("field", "policy"),
    [
        ("photos", "images"),
        ("photos[0]", "images"),
        ("photos.1", "images"),
        ("photos[0][thumb]", "images"),
        ("photosx", "pdf"),
        ("other", "pdf"),
        ("notes", None),
        # An alias inherits a field's policy, never its opt-out: "notes[0]" is checked.
        ("notes[0]", "pdf"),
    ],
)
def test_policy_for_field_aliases(field: str, policy: str | None) -> None:
    spec = ViewSpec(policy="pdf", fields={"photos": "images", "notes": None})
    resolved = spec.policy_for(field, get_config())
    assert (resolved.name if resolved is not None else None) == policy


def test_method_decorator_policy_applies_when_csrf_parses_the_body_first() -> None:
    # CsrfViewMiddleware reads request.POST before the view method runs; the handler
    # must still use the method's policy (ZIP allowed), not the default (ZIP refused).
    client = Client(enforce_csrf_checks=True)
    token = "a" * 32
    client.cookies["csrftoken"] = token
    archive = upload("bundle.zip", corpus.build_zip({"a.txt": b"hello"}), "application/zip")
    response = client.post(
        "/csrf-zip/", {"file": archive, "csrfmiddlewaretoken": token}, headers=JSON
    )
    assert response.status_code == 200
    assert response.json()["files"][0]["name"] == "bundle.zip"
    refused = client.post(
        "/csrf-zip/",
        {"file": upload("a.pdf", corpus.pdf()), "csrfmiddlewaretoken": token},
        headers=JSON,
    )
    assert refused.status_code == 415


def test_method_decorator_on_reject_reaches_handler400(client: Client) -> None:
    response = client.post("/method-on-reject/", {"file": upload("cat.png", corpus.png())})
    assert response.status_code == 418
    assert response.content == b"teapot"
