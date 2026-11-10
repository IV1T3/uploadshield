"""Flask integration.

::

    from flask import Flask
    from uploadshield.flask import UploadShield, validate_uploads

    app = Flask(__name__)
    app.config["UPLOADSHIELD"] = {"MODE": "report"}
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # Werkzeug's whole-request cap
    UploadShield(app)  # validates every multipart request before its view runs

    @app.post("/avatar")
    @validate_uploads("sanitized_images")
    def avatar(): ...

Werkzeug parses the body before validation (it has no stable per-file streaming hook),
so keep ``MAX_CONTENT_LENGTH`` set.  Refusals are Werkzeug HTTP errors
(:class:`UploadRejected`, 400/413/415) rendered as JSON for API clients and HTML
otherwise.  For inline form errors use :class:`uploadshield.flask.wtforms.ShieldedFile`.
"""

from .core import (
    FileOutcome,
    UploadRejected,
    UploadShield,
    get_upload_results,
    upload_rejected,
    upload_validated,
)
from .decorators import skip_upload_validation, validate_uploads

__all__ = [
    "FileOutcome",
    "UploadRejected",
    "UploadShield",
    "get_upload_results",
    "skip_upload_validation",
    "upload_rejected",
    "upload_validated",
    "validate_uploads",
]
