"""Signals for auditing, metrics and alerting.

``upload_validated``: every validated request; kwargs ``request``, ``validation``.
``upload_rejected``: requests with at least one bad file; kwargs ``request``,
``validation`` and ``enforced`` (``False`` in report mode).
``file_rejected``: a form/model/serializer field rejected a file (``FileValidator``,
``ValidatedFileField``); kwargs ``result`` and ``policy``.  No request is available.
"""

from django.dispatch import Signal

__all__ = ["file_rejected", "upload_rejected", "upload_validated"]

upload_validated = Signal()
upload_rejected = Signal()
file_rejected = Signal()
