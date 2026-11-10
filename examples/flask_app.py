"""A minimal Flask upload app protected by uploadshield.

Run:  uv run python examples/flask_app.py   (serves http://127.0.0.1:8811)
"""

from __future__ import annotations

import hashlib

from flask import Flask, Response, jsonify, request

from uploadshield.flask import UploadShield, validate_uploads

app = Flask(__name__)
# Werkzeug parses the whole body before validation runs: cap it.
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
app.config["UPLOADSHIELD"] = {"MODE": "enforce"}
UploadShield(app)  # validates every multipart request (DEFAULT_POLICY) before its view


def summary() -> Response:
    files = []
    for field, storage in request.files.items(multi=True):
        data = storage.read()
        files.append(
            {
                "field": field,
                "name": storage.filename,
                "content_type": storage.content_type,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return jsonify({"files": files})


@app.post("/documents")
@validate_uploads("documents")
def documents() -> Response:
    return summary()


@app.post("/avatar")
@validate_uploads("sanitized_images")  # re-encoded, metadata stripped, random name
def avatar() -> Response:
    return summary()


@app.post("/gallery")
@validate_uploads("images")
def gallery() -> Response:  # several files in the field "files"
    return summary()


@app.post("/legacy")
def legacy() -> Response:  # no decorator: protected by the extension's request hook
    return summary()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8811)
