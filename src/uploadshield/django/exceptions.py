"""The exception raised when an upload is refused."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import SuspiciousOperation
from django.http.multipartparser import MultiPartParserError

if TYPE_CHECKING:
    from .service import UploadValidation

__all__ = ["UploadRejected"]


class UploadRejected(MultiPartParserError, SuspiciousOperation):  # noqa: N818 - Django naming
    """An uploaded file violated its policy.

    Raised by ``ValidatingUploadHandler`` while Django parses the request body, and by
    ``ValidatingStorage`` on ``save()``.  The base classes are chosen for Django's own
    handling:

    * ``MultiPartParserError``: Django answers with ``handler400`` (also when
      ``DEBUG=True``) and marks the body as unparseable, so code that catches the
      exception and reads ``request.FILES`` again gets nothing. DRF turns it into its
      standard 400 ``ParseError``.
    * ``SuspiciousOperation``: like Django's ``TooManyFilesSent``, a refused upload is
      a security event.

    Point ``handler400`` at ``uploadshield.django.views.bad_request`` for
    413/415 status codes and JSON/HTML bodies.
    """

    def __init__(self, validation: UploadValidation) -> None:
        self.validation = validation
        summary = "; ".join(
            f"{o.result.name!r} ({', '.join(o.result.codes)})" for o in validation.rejected
        )
        super().__init__(f"Upload rejected: {summary or 'no details'}")
