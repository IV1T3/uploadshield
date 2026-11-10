"""OWASP File Upload Cheat Sheet - Content-Type Validation."""

from __future__ import annotations

import pytest

from tests.support import corpus
from tests.support.engine import codes
from tests.support.harness import App, file
from uploadshield import Policy, presets

owasp = pytest.mark.owasp


@owasp("content-type.untrusted")
@pytest.mark.parametrize(
    ("data", "name", "claimed"),
    [
        (corpus.PHP_SHELL, "cat.png", "image/png"),
        (corpus.HTML, "cv.pdf", "application/pdf"),
        (corpus.pe_executable(), "photo.jpg", "image/jpeg"),
    ],
)
def test_a_claimed_type_never_gets_hostile_content_in(
    app: App, data: bytes, name: str, claimed: str
) -> None:
    assert app.post("/legacy", file(name, data, claimed)).status == 415


@owasp("content-type.untrusted")
@pytest.mark.parametrize("claimed", ["text/html", "image/svg+xml", "application/x-php", "x/y"])
def test_views_receive_the_detected_type_not_the_claim(app: App, claimed: str) -> None:
    (delivered,) = app.post("/legacy", file("photo.png", corpus.png(), claimed)).files
    assert delivered["content_type"] == "image/png"


@owasp("content-type.quick-check")
def test_declared_types_can_be_checked_as_a_quick_filter() -> None:
    strict = presets.IMAGES.replace(match_declared_type=True)
    png = corpus.png()
    assert codes(png, "a.png", strict, declared_type="image/png") == ()
    assert codes(png, "a.png", strict, declared_type="image/gif") == ("declared_type_mismatch",)
    # Generic labels carry no claim, and child types satisfy their parent.
    assert codes(png, "a.png", strict, declared_type="application/octet-stream") == ()
    csv = Policy(allowed_types={"text/csv"}, match_declared_type=True)
    assert codes(b"a,b\n", "a.csv", csv, declared_type="text/plain") == ()
    # Off by default: browsers label CSV as application/vnd.ms-excel on Windows.
    assert (
        codes(b"a,b\n", "a.csv", presets.DOCUMENTS, declared_type="application/vnd.ms-excel") == ()
    )


@owasp("content-type.quick-check")
def test_the_quick_check_works_in_every_adapter() -> None:
    pytest.importorskip("flask")
    from flask import Flask

    from uploadshield.flask import validate_uploads

    app = Flask(__name__)

    @app.post("/strict")
    @validate_uploads(presets.IMAGES.replace(match_declared_type=True))
    def strict() -> str:
        return "ok"

    client = app.test_client()
    import io

    lying = {"file": (io.BytesIO(corpus.png()), "a.png", "image/gif")}
    response = client.post("/strict", data=lying, headers={"Accept": "application/json"})
    body = response.get_json()
    assert response.status_code == 415
    assert body is not None
    assert body["files"][0]["errors"][0]["code"] == "declared_type_mismatch"
