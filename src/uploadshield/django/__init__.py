"""Django integration, built on Django's own extension points.

* ``FILE_UPLOAD_HANDLERS``: :class:`~uploadshield.django.handlers.ValidatingUploadHandler`
  validates every uploaded file while the body is parsed (views, forms, admin, DRF).
* :func:`validate_uploads` / :func:`skip_upload_validation`: per-view policies.
* :class:`FileValidator` / :class:`ValidatedFileField`: per-field validation with
  inline errors in forms, model ``full_clean`` and DRF serializers.
* ``STORAGES``: :class:`~uploadshield.django.storage.ValidatingStorage`
  validates everything that is persisted, inside or outside requests.
* ``handler400``: :func:`uploadshield.django.views.bad_request` renders
  rejections as 413/415/400 JSON or HTML.
"""

from .decorators import skip_upload_validation, validate_uploads
from .exceptions import UploadRejected
from .forms import ValidatedFileField
from .responses import redirect_with_messages
from .service import FileOutcome, RejectedUpload, UploadValidation, get_upload_validation
from .signals import file_rejected, upload_rejected, upload_validated
from .validators import FileValidator

__all__ = [
    "FileOutcome",
    "FileValidator",
    "RejectedUpload",
    "UploadRejected",
    "UploadValidation",
    "ValidatedFileField",
    "file_rejected",
    "get_upload_validation",
    "redirect_with_messages",
    "skip_upload_validation",
    "upload_rejected",
    "upload_validated",
    "validate_uploads",
]
