"""The Flask extension, decorators, errors, signals and integration styles."""

from __future__ import annotations

import io
import logging
from typing import Any

import pytest

pytest.importorskip("flask")

from flask import Flask, jsonify, request

from tests.adapters.flask.app import (
    PHP,
    _exif,
    describe,
    make_app,
    noise,
    raw_multipart,
    send,
    send_raw,
)
from tests.support import corpus
from uploadshield.flask import (
    UploadRejected,
    UploadShield,
    get_upload_results,
    skip_upload_validation,
    upload_rejected,
    upload_validated,
    validate_uploads,
)


def test_valid_file_gets_detected_content_type(client: Any) -> None:
    response = client.post(
        "/documents", data={"file": (io.BytesIO(corpus.pdf()), "a.pdf", "text/plain")}
    )
    assert response.status_code == 200
    file = response.json["files"][0]
    assert file["content_type"] == "application/pdf"
    assert response.json["validated"] is True


@pytest.mark.parametrize(
    ("path", "name", "data", "status", "code"),
    [
        ("/plain", "cat.png", PHP, 415, "type_not_allowed"),
        ("/plain", "shell.php.png", corpus.png(), 400, "filename_dangerous_extension"),
        ("/plain", "../../etc/x.png", corpus.png(), 400, "filename_invalid"),
        ("/documents", "invoice.pdf", corpus.pdf_with_javascript(), 400, "pdf_active_content"),
        (
            "/documents",
            "r.docx",
            corpus.ooxml("docx", extra={"word/vbaProject.bin": b"x"}),
            400,
            "office_macros",
        ),
        ("/tiny", "big.png", corpus.image("PNG", size=(300, 300)), 413, "file_too_large"),
    ],
)
def test_attacks_are_refused(
    client: Any, path: str, name: str, data: bytes, status: int, code: str
) -> None:
    response = send(client, path, name, data)
    assert response.status_code == status
    assert response.json["error"] == "upload_rejected"
    assert response.json["files"][0]["errors"][0]["code"] == code


def test_html_for_browsers_is_escaped(client: Any) -> None:
    # (Werkzeug cuts filenames at an embedded quote, so the payload avoids quotes.)
    response = send(
        client, "/plain", "<img src=x onerror=alert(1)>.png", PHP, headers={"Accept": "text/html"}
    )
    assert response.status_code == 400  # refused for its name, which the page echoes
    assert response.mimetype == "text/html"
    assert b"<img src=x" not in response.data
    assert b"&lt;img src=x" in response.data


def test_sanitized_avatar(client: Any) -> None:
    response = send(client, "/avatar", "me.jpg", corpus.jpeg_with_metadata())
    file = response.json["files"][0]
    assert file["name"].endswith(".jpg")
    assert file["name"] != "me.jpg"
    assert (file["exif"], file["cam"]) == (0, False)


def test_per_field_policies_and_skip(client: Any) -> None:
    data = {
        "doc": (io.BytesIO(corpus.pdf()), "a.pdf"),
        "photo": (io.BytesIO(corpus.png()), "a.png"),
        "notes": (io.BytesIO(corpus.pe_executable()), "tool.exe"),
    }
    assert client.post("/multi", data=data).status_code == 200
    assert send(client, "/raw", "cat.png", PHP).status_code == 200


def test_endpoint_globs_and_non_multipart(client: Any) -> None:
    assert send(client, "/legacy-upload", "a.png", corpus.png()).status_code == 415
    assert send(client, "/legacy-upload", "a.pdf", corpus.pdf()).status_code == 200
    assert client.post("/json", json={"a": 1}).json == {"a": 1}
    assert client.post("/plain", data={"title": "no files"}).json["files"] == []


def test_on_reject_and_async_views(client: Any) -> None:
    response = send(client, "/redirecting", "cat.png", PHP)
    assert response.status_code == 302
    assert response.headers["Location"] == "/done"
    assert send(client, "/async", "a.png", corpus.png()).status_code == 200
    assert send(client, "/async", "cat.png", PHP).status_code == 415


def test_decorators_work_without_the_extension() -> None:
    client = make_app(extension=False).test_client()
    assert send(client, "/plain", "cat.png", PHP).status_code == 200  # nothing installed
    assert send(client, "/documents", "cat.pdf", PHP).status_code == 415


def test_protect_all_can_be_disabled() -> None:
    client = make_app({"PROTECT_ALL": False}).test_client()
    assert send(client, "/plain", "cat.png", PHP).status_code == 200
    assert send(client, "/documents", "cat.pdf", PHP).status_code == 415


def test_report_and_off_modes_and_signals() -> None:
    app = make_app({"MODE": "report"})
    seen: list[tuple[str, Any]] = []

    def on_validated(sender: Any, **kwargs: Any) -> None:
        seen.append(("validated", kwargs["results"]))

    def on_rejected(sender: Any, **kwargs: Any) -> None:
        seen.append(("rejected", kwargs["enforced"]))

    upload_validated.connect(on_validated, app)
    upload_rejected.connect(on_rejected, app)
    try:
        assert send(app.test_client(), "/plain", "cat.png", PHP).status_code == 200
    finally:
        upload_validated.disconnect(on_validated, app)
        upload_rejected.disconnect(on_rejected, app)
    assert [name for name, _ in seen] == ["validated", "rejected"]
    assert seen[1][1] is False
    off = make_app({"MODE": "off"}).test_client()
    assert send(off, "/documents", "cat.pdf", PHP).status_code == 200


def test_custom_error_handler_and_messages() -> None:
    app = make_app({"MESSAGES": {"type_not_allowed": "Nur Bilder!"}, "EXPOSE_DETAILS": True})

    @app.errorhandler(UploadRejected)
    def handle(error: UploadRejected):
        return jsonify({"custom": error.payload["files"][0]["errors"][0]}), error.code

    response = send(app.test_client(), "/plain", "cat.png", PHP)
    assert response.status_code == 415
    error = response.json["custom"]
    assert error["message"] == "Nur Bilder!"
    assert error["details"]["detected_type"] == "application/x-httpd-php"


@pytest.mark.parametrize(
    ("config", "exception", "message"),
    [
        ({"MODEE": "x"}, ValueError, "Unknown UPLOADSHIELD keys"),
        ({"MODE": "strict"}, ValueError, "must be one of"),
        ({"POLICIES": {"x": "nope"}}, TypeError, "must be a Policy"),
        ({"DEFAULT_POLICY": "nope"}, ValueError, "Unknown upload policy"),
    ],
)
def test_invalid_configuration(
    config: dict[str, Any], exception: type[Exception], message: str
) -> None:
    with pytest.raises(exception, match=message):
        make_app(config)


def test_rejections_are_logged(client: Any, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="uploadshield")
    send(client, "/plain", "cat.png", PHP)
    details = next(r for r in caplog.records if r.name == "uploadshield").__dict__["upload"]
    assert (details["path"], details["policy"]) == ("/plain", "default")
    assert len(details["sha256"]) == 64


@pytest.mark.parametrize("path", ["/plain", "/documents", "/async"])
def test_nameless_file_parts_with_content_are_refused(client: Any, path: str) -> None:
    # Werkzeug puts filename="" parts into request.files; skipping them was a bypass.
    response = send_raw(client, path, raw_multipart("", PHP))
    assert response.status_code == 400
    assert response.json["files"][0]["errors"][0]["code"] == "filename_invalid"


def test_empty_file_inputs_are_left_alone(client: Any) -> None:
    response = send_raw(client, "/documents", raw_multipart("", b""))
    assert response.status_code == 200
    assert response.json["files"] == [
        {
            "field": "file",
            "name": "",
            "content_type": "application/octet-stream",
            "size": 0,
            "exif": None,
            "cam": False,
        }
    ]


@pytest.mark.parametrize("method", ["get", "put", "patch", "delete"])
def test_multipart_bodies_are_validated_for_every_method(method: str) -> None:
    app = make_app()

    @app.route("/any", methods=["GET", "PUT", "PATCH", "DELETE"])
    def any_method():
        return describe()

    client = app.test_client()
    bad = send_raw(client, "/any", raw_multipart("cat.png", PHP), method)
    assert bad.status_code == 415
    good = send_raw(client, "/any", raw_multipart("a.png", corpus.png()), method)
    assert good.status_code == 200
    assert good.json["files"][0]["content_type"] == "image/png"


@pytest.mark.parametrize(("path", "fmt"), [("/plain", "PNG"), ("/avatar", "JPEG")])
def test_files_spooled_to_disk_are_delivered_and_closed(client: Any, path: str, fmt: str) -> None:
    # Werkzeug spools these to temporary files; one left open would fail this suite,
    # which turns ResourceWarnings into errors.  (Raw bodies: the test client's own
    # encoder leaks a temporary file for large dict payloads.)
    data = noise(fmt)
    response = send_raw(client, path, raw_multipart(f"big.{fmt.lower()}", data))
    assert response.status_code == 200
    delivered = response.json["files"][0]
    if path == "/plain":
        assert delivered["size"] == len(data)
    else:  # re-encoded from the spooled original
        assert delivered["size"] != len(data)
        assert delivered["exif"] == 0


def test_sanitized_files_save_sanitized_bytes(tmp_path: Any) -> None:
    app = Flask(__name__)
    UploadShield(app)
    stored: list[Any] = []

    @app.post("/avatar")
    @validate_uploads("sanitized_images")
    def avatar():
        upload = request.files["file"]
        target = tmp_path / str(upload.filename)
        upload.save(target)  # the idiomatic Werkzeug call
        stored.append(target)
        return {"name": upload.filename}

    response = send(app.test_client(), "/avatar", "me.jpg", corpus.jpeg_with_metadata())
    assert response.status_code == 200
    (target,) = stored
    data = target.read_bytes()
    assert target.name == response.json["name"] != "me.jpg"
    assert b"EvilCam" not in data
    assert _exif(data) == 0


def test_get_upload_results_describes_every_file(client: Any) -> None:
    app = make_app()
    seen: list[Any] = []

    @app.post("/inspect")
    @validate_uploads(fields={"doc": "pdf", "photo": "images"})
    def inspect_view():
        seen.extend(get_upload_results() or [])
        return "ok"

    data = {
        "doc": (io.BytesIO(corpus.pdf()), "a.pdf"),
        "photo": (io.BytesIO(corpus.png()), "a.png"),
    }
    assert app.test_client().post("/inspect", data=data).status_code == 200
    assert [(o.field, o.policy_name, o.ok, o.result.file_type.mime) for o in seen] == [
        ("doc", "pdf", True, "application/pdf"),
        ("photo", "images", True, "image/png"),
    ]
    assert client.post("/plain", data={"title": "x"}).json["validated"] is False  # urlencoded


def test_method_view_with_decorators() -> None:
    from flask.views import MethodView

    class Upload(MethodView):
        decorators = [validate_uploads("pdf")]

        def post(self):
            return describe()

    app = make_app()
    app.add_url_rule("/upload", view_func=Upload.as_view("upload"))
    client = app.test_client()
    assert send(client, "/upload", "a.pdf", corpus.pdf()).status_code == 200
    assert send(client, "/upload", "a.png", corpus.png()).status_code == 415


def test_blueprints_and_endpoint_globs() -> None:
    from flask import Blueprint

    admin = Blueprint("admin", __name__, url_prefix="/admin")

    @admin.post("/import")
    def import_view():
        return describe()

    @admin.post("/raw")
    @skip_upload_validation
    def raw_view():
        return describe()

    app = make_app({"ENDPOINT_POLICIES": {"admin.*": "pdf"}})
    app.register_blueprint(admin)
    client = app.test_client()
    assert send(client, "/admin/import", "a.png", corpus.png()).status_code == 415
    assert send(client, "/admin/import", "a.pdf", corpus.pdf()).status_code == 200
    assert send(client, "/admin/raw", "cat.png", PHP).status_code == 200  # decorator wins


def test_app_factory_and_per_app_configuration() -> None:
    shield = UploadShield()  # module level, as with other Flask extensions

    def create_app(mode: str) -> Flask:
        app = Flask(__name__)
        app.config["UPLOADSHIELD"] = {"MODE": mode}
        shield.init_app(app)

        @app.post("/upload")
        def upload():
            return describe()

        return app

    enforcing, reporting = create_app("enforce"), create_app("report")
    assert send(enforcing.test_client(), "/upload", "cat.png", PHP).status_code == 415
    assert send(reporting.test_client(), "/upload", "cat.png", PHP).status_code == 200


@pytest.mark.owasp("limits.upload-size")
def test_max_content_length_is_werkzeug_s_413() -> None:
    app = make_app()
    app.config["MAX_CONTENT_LENGTH"] = 1000
    response = send(app.test_client(), "/plain", "a.png", corpus.image("PNG", size=(300, 300)))
    assert response.status_code == 413  # RequestEntityTooLarge, before any parsing


def test_report_mode_delivers_the_original_upload() -> None:
    client = make_app({"MODE": "report"}).test_client()
    response = client.post("/avatar", data={"file": (io.BytesIO(PHP), "cat.png", "image/png")})
    body = response.get_json()
    assert response.status_code == 200
    assert body is not None
    file = body["files"][0]
    assert (file["name"], file["content_type"], file["size"]) == ("cat.png", "image/png", len(PHP))


@pytest.mark.parametrize("path", ["/plain", "/documents", "/legacy-upload"])
def test_requests_sharing_one_app_context_are_each_validated(path: str) -> None:
    # Tests, CLI commands and workers often push one app context for many requests;
    # ``g`` lives as long as that context, so results must not be kept there.
    app = make_app()
    client = app.test_client()
    with app.app_context():
        assert send(client, path, "a.pdf", corpus.pdf()).status_code == 200
        assert send(client, path, "cat.pdf", PHP).status_code == 415
        assert send(client, path, "b.pdf", corpus.pdf()).status_code == 200


def test_exposed_details_of_any_kind_are_serialised() -> None:
    # A custom check may put sets or bytes into its details: still a refusal, not a 500.
    from collections.abc import Iterator
    from dataclasses import dataclass

    from uploadshield import InspectedFile, Violation, presets
    from uploadshield.checks import Check

    @dataclass(frozen=True)
    class Picky(Check):
        name = "picky"

        def run(self, file: InspectedFile) -> Iterator[Violation]:
            yield self.violation("picky", "No.", tags={"b", "a"}, head=b"\x00\xff")

    policy = presets.PDF.extend(checks=[Picky()], name="picky")
    app = make_app(
        {"EXPOSE_DETAILS": True, "POLICIES": {"picky": policy}, "DEFAULT_POLICY": "picky"}
    )
    response = send(app.test_client(), "/plain", "a.pdf", corpus.pdf())
    assert response.status_code == 400
    (error,) = response.get_json()["files"][0]["errors"]
    assert error["details"] == {"tags": ["a", "b"], "head": "00ff"}
