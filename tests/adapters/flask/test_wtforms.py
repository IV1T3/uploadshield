"""uploadshield.flask.wtforms.ShieldedFile in Flask-WTF and WTForms forms."""

from __future__ import annotations

import io

import pytest

pytest.importorskip("flask")

from flask import Flask, jsonify

from tests.adapters.flask.app import PHP, raw_multipart, send_raw
from tests.support import corpus
from uploadshield.flask import (
    UploadShield,
)

# --------------------------------------------------------------------------- #
# Flask-WTF / WTForms
# --------------------------------------------------------------------------- #


def test_wtforms_validator_inline_errors_and_sanitized_data() -> None:
    pytest.importorskip("flask_wtf")
    from flask_wtf import FlaskForm
    from flask_wtf.file import FileField, FileRequired

    from uploadshield.flask.wtforms import ShieldedFile

    class AvatarForm(FlaskForm):
        picture = FileField(validators=[FileRequired(), ShieldedFile("sanitized_images")])

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="test", WTF_CSRF_ENABLED=False, UPLOADSHIELD={"PROTECT_ALL": False}
    )
    UploadShield(app)

    @app.post("/form")
    def form_view():
        form = AvatarForm()
        if not form.validate_on_submit():
            return jsonify({"errors": form.errors}), 400
        data = form.picture.data.read()
        return jsonify({"name": form.picture.data.filename, "cam": b"EvilCam" in data})

    client = app.test_client()
    bad = client.post("/form", data={"picture": (io.BytesIO(PHP), "me.png")})
    assert bad.status_code == 400
    assert bad.get_json() == {"errors": {"picture": ["PHP script files are not allowed."]}}
    good = client.post(
        "/form", data={"picture": (io.BytesIO(corpus.jpeg_with_metadata()), "me.jpg")}
    )
    assert good.status_code == 200
    body = good.get_json()
    assert body is not None
    assert body["name"] != "me.jpg"
    assert body["cam"] is False


def test_wtforms_multiple_files_and_empty_fields() -> None:
    pytest.importorskip("flask_wtf")
    from flask_wtf import FlaskForm
    from flask_wtf.file import MultipleFileField

    from uploadshield.flask.wtforms import ShieldedFile

    class GalleryForm(FlaskForm):
        photos = MultipleFileField(validators=[ShieldedFile("images")])

    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", WTF_CSRF_ENABLED=False)

    @app.post("/gallery")
    def gallery():
        form = GalleryForm()
        if not form.validate_on_submit():
            return jsonify({"errors": form.errors}), 400
        return jsonify({"types": [f.content_type for f in form.photos.data or [] if f]})

    client = app.test_client()
    empty = client.post("/gallery", data={"other": "x"})
    assert empty.status_code == 200  # optional field without files: nothing to check
    good = client.post(
        "/gallery",
        data={
            "photos": [
                (io.BytesIO(corpus.png()), "a.png"),
                (io.BytesIO(corpus.image("GIF")), "b.gif"),
            ]
        },
    )
    assert good.get_json() == {"types": ["image/png", "image/gif"]}
    bad = client.post(
        "/gallery",
        data={"photos": [(io.BytesIO(corpus.png()), "a.png"), (io.BytesIO(PHP), "c.png")]},
    )
    assert bad.status_code == 400


def test_wtforms_refuses_nameless_parts_with_content() -> None:
    pytest.importorskip("flask_wtf")
    import wtforms
    from flask_wtf import FlaskForm
    from flask_wtf.file import FileField

    from uploadshield.flask.wtforms import ShieldedFile

    class OptionalForm(FlaskForm):
        # Flask-WTF's FileField discards nameless parts itself; WTForms' keeps them.
        attachment = wtforms.FileField(validators=[ShieldedFile("pdf")])  # optional
        document = FileField(validators=[ShieldedFile("pdf")])

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="test", WTF_CSRF_ENABLED=False, UPLOADSHIELD={"PROTECT_ALL": False}
    )
    UploadShield(app)

    @app.post("/form")
    def form_view():
        form = OptionalForm()
        return jsonify({"valid": form.validate_on_submit(), "errors": form.errors})

    client = app.test_client()
    sneaky = send_raw(client, "/form", raw_multipart("", PHP, field="attachment")).json
    assert sneaky == {"valid": False, "errors": {"attachment": ["The file has no name."]}}
    empty = send_raw(client, "/form", raw_multipart("", b"", field="attachment")).json
    assert empty == {"valid": True, "errors": {}}
    dropped = send_raw(client, "/form", raw_multipart("", PHP, field="document")).json
    assert dropped == {"valid": True, "errors": {}}  # form.document.data is None
