"""Validate every uploaded file while Django parses the request body.

Enable it as the only upload handler::

    FILE_UPLOAD_HANDLERS = ["uploadshield.django.handlers.ValidatingUploadHandler"]

Every parser stores files through upload handlers: Django's ``request.POST``/
``request.FILES`` (views, forms, the admin) and DRF's ``MultiPartParser`` and
``FileUploadParser`` (POST, PUT, PATCH).  This one setting therefore covers them all,
and it only does work when something actually parses a body.  For each file:

1. ``new_file``: the name is checked before a single byte is stored.
2. ``receive_data_chunk``: size limits are enforced as data arrives, and as soon as
   the first 8 KiB are in, the sniffed type is checked against the allow-list. A
   refused file is never stored in full.
3. ``file_complete``: the complete policy runs (format-specific checks, sanitizers)
   and the application receives the sanitized file.

A refused upload raises :class:`~uploadshield.django.exceptions.UploadRejected`
(Django answers 400 via ``handler400``), unless the view reports errors inline
(``on_reject="field"``) or the mode is ``report``.  Incoming data is stored by the
handlers in ``UPLOADSHIELD["UPLOAD_HANDLERS"]`` (Django's defaults).
"""

from __future__ import annotations

import dataclasses
from typing import IO, TYPE_CHECKING, Any

from django.core.exceptions import ImproperlyConfigured
from django.core.files.uploadhandler import FileUploadHandler, StopFutureHandlers, load_handler

from uploadshield.core.result import ValidationResult
from uploadshield.core.types import format_size
from uploadshield.core.upload import HEAD_SIZE
from uploadshield.core.violations import Code, Violation
from uploadshield.engine import preflight

from .conf import get_config
from .exceptions import UploadRejected
from .service import (
    FileOutcome,
    RejectedUpload,
    UploadValidation,
    ViewSpec,
    accept,
    finish,
    spec_for_request,
    validate_file,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from django.core.files.uploadedfile import UploadedFile
    from django.http import HttpRequest

    from uploadshield.policy import Policy

__all__ = ["ValidatingUploadHandler"]


def _resolve(request: HttpRequest) -> Any:
    from django.urls import Resolver404, resolve

    try:
        return resolve(request.path_info, getattr(request, "urlconf", None))
    except Resolver404:
        return None


class ValidatingUploadHandler(FileUploadHandler):
    """Django instantiates it from ``FILE_UPLOAD_HANDLERS`` with the request only.

    ``inner`` (the handlers that store the data) and ``spec`` (the policy) are for
    :func:`~uploadshield.django.validate_uploads`, which installs one per request when
    the handler is not configured globally.
    """

    def __init__(
        self,
        request: HttpRequest | None = None,
        *,
        inner: Sequence[FileUploadHandler] | None = None,
        spec: ViewSpec | None = None,
    ) -> None:
        super().__init__(request)
        self.config = get_config()
        if inner is None:
            inner = [load_handler(path, request) for path in self.config.upload_handlers]
        self.inner = list(inner)
        if sizes := [h.chunk_size for h in self.inner if h.chunk_size]:
            self.chunk_size = min(sizes)
        self._spec: ViewSpec | None = spec
        self.outcomes: list[FileOutcome] = []
        self._per_field: dict[str, int] = {}
        self._start_file(None)

    # -- configuration for this request ------------------------------------------------

    @property
    def spec(self) -> ViewSpec:
        if self._spec is None:
            if self.request is None:
                self._spec = ViewSpec(policy=self.config.default_policy)
            else:
                # Parsed before URL routing (e.g. from MIDDLEWARE): route it ourselves, so
                # the view's decorator and VIEW_POLICIES still decide.
                match = getattr(self.request, "resolver_match", None) or _resolve(self.request)
                view = match.func if match is not None else None
                self._spec = spec_for_request(self.request, view, self.config, match=match)
        return self._spec

    def use_spec(self, spec: ViewSpec) -> None:
        """Validate with ``spec``: set by ``@validate_uploads`` before the body is parsed,
        also where routing cannot see the decorator (DRF ``@api_view``, ``method_decorator``)."""
        self._spec = spec

    @property
    def mode(self) -> str:
        return self.spec.effective_mode(self.config)

    @property
    def inline(self) -> bool:
        return self.mode == "enforce" and self.spec.inline_errors(self.config)

    # -- Django's upload handler protocol ----------------------------------------------

    def handle_raw_input(
        self,
        input_data: IO[bytes],
        META: dict[str, str],  # noqa: N803 - Django's parameter name
        content_length: int,
        boundary: str,
        encoding: str | None = None,
    ) -> None:
        for handler in self.inner:
            if handler.handle_raw_input(input_data, META, content_length, boundary, encoding):
                raise ImproperlyConfigured(
                    f"{type(handler).__name__} parses the whole request itself, so its "
                    "files cannot be validated; remove it from UPLOAD_HANDLERS"
                )

    def new_file(  # noqa: PLR0917 - Django's signature
        self,
        field_name: str,  # None for DRF's FileUploadParser (raw single-file bodies)
        file_name: str,
        content_type: str,
        content_length: int | None,
        charset: str | None = None,
        content_type_extra: dict[str, bytes] | None = None,
    ) -> None:
        super().new_file(
            field_name, file_name, content_type, content_length, charset, content_type_extra
        )
        # Raw single-file bodies (DRF's FileUploadParser) arrive as request.FILES["file"].
        field = field_name or "file"
        policy = self.spec.policy_for(field, self.config) if self.mode != "off" else None
        self._start_file(policy)
        if policy is not None and self.mode == "enforce":
            self._check(preflight(policy, stages={"name"}, **self._facts()))
            if self.early is not None:
                return  # refused by name: nothing is ever stored
        self.inner_started = True
        for handler in self.inner:
            try:
                handler.new_file(
                    field_name,
                    file_name,
                    content_type,
                    content_length,
                    charset,
                    content_type_extra,
                )
            except StopFutureHandlers:
                break

    def receive_data_chunk(self, raw_data: bytes, start: int) -> None:
        self.received += len(raw_data)
        self._enforce_limits()
        if self.early is not None:
            return  # refused; drop the rest of this file
        if self.policy is not None and self.mode == "enforce" and not self.prechecked:
            self.head += raw_data[: HEAD_SIZE - len(self.head)]
            if len(self.head) >= HEAD_SIZE:
                self.prechecked = True
                self._check(preflight(policy=self.policy, stages={"type"}, **self._facts()))
                if self.early is not None:
                    return
        chunk: bytes | None = raw_data
        for i, handler in enumerate(self.inner):
            length = len(chunk)
            chunk = handler.receive_data_chunk(chunk, self.counters[i])
            self.counters[i] += length
            if chunk is None:
                break
        return

    def file_complete(self, file_size: int) -> UploadedFile | None:
        file_obj = self._inner_complete()
        field = self.field_name or "file"
        if self.early is not None:
            if file_obj is not None:
                file_obj.close()  # partial data of a refused file
            return RejectedUpload(self.early, field_name=self.field_name, config=self.config)
        if file_obj is None or self.policy is None:
            return file_obj
        result = validate_file(file_obj, self.policy, field=field)
        if result is None:  # pragma: no cover - handlers always return new uploads
            return file_obj
        outcome = FileOutcome(field, self._index(field), result, self.policy.name, file_obj)
        self.outcomes.append(outcome)
        if not result.ok and self.mode == "enforce" and not self.inline:
            self._abort(file_obj)
        delivered = accept(outcome, self.policy, self.config, inline=self.inline)
        if delivered is not file_obj:
            # Django only closes what ends up in request.FILES, and not at all when the
            # parse fails later: hash the replaced original for the logs, close it now.
            self.outcomes[-1] = dataclasses.replace(outcome, digest=outcome.sha256())
            file_obj.close()
        if self.field_name is None:
            self._finish()  # raw single-file body (DRF FileUploadParser): no upload_complete
        return delivered

    def upload_complete(self) -> None:
        for handler in self.inner:
            handler.upload_complete()
        self._finish()

    def upload_interrupted(self) -> None:
        for handler in self.inner:
            handler.upload_interrupted()

    # -- internals ---------------------------------------------------------------------

    def _start_file(self, policy: Policy | None) -> None:
        self.policy = policy
        self.received = 0
        self.head = bytearray()
        self.prechecked = False
        self.early: ValidationResult | None = None
        self.inner_started = False
        self.counters = [0] * len(self.inner)

    def _facts(self) -> dict[str, Any]:
        return {
            "name": self.file_name or "",
            "head": bytes(self.head),
            "size": self.received,
            "declared_type": self.content_type,
            "field": self.field_name,
        }

    def _index(self, field: str) -> int:
        index = self._per_field.get(field, 0)
        self._per_field[field] = index + 1
        return index

    def _enforce_limits(self) -> None:
        hard_cap = self.config.max_upload_size
        if hard_cap is not None and self.received > hard_cap:
            self._refuse(self._too_large(hard_cap), force_abort=True)
        policy = self.policy
        if (
            policy is not None
            and self.mode == "enforce"
            and policy.max_size is not None
            and self.received > policy.max_size
            and self.early is None
        ):
            self._check(preflight(policy, stages={"size"}, **self._facts()))

    def _too_large(self, limit: int) -> ValidationResult:
        violation = Violation(
            code=Code.FILE_TOO_LARGE,
            message=f"The file is too large (maximum {format_size(limit)}).",
            check="size",
            details={"size": self.received, "limit": limit, "aborted_upload": True},
        )
        return ValidationResult(
            name=self.file_name or "",
            field=self.field_name,
            size=self.received,
            file_type=None,
            declared_type=self.content_type,
            violations=(violation,),
            checks_run=("size",),
        )

    def _check(self, result: ValidationResult) -> None:
        if not result.ok:
            self._refuse(result)

    def _refuse(self, result: ValidationResult, *, force_abort: bool = False) -> None:
        field = self.field_name or "file"
        name = self.policy.name if self.policy is not None else "upload_limit"
        self.outcomes.append(FileOutcome(field, self._index(field), result, name))
        if self.inline and not force_abort:
            self.early = result
            return
        self._abort()

    def _inner_complete(self) -> UploadedFile | None:
        if not self.inner_started:
            return None
        for i, handler in enumerate(self.inner):
            if (file_obj := handler.file_complete(self.counters[i])) is not None:
                return file_obj
        return None

    def _abort(self, rejected: UploadedFile | None = None) -> None:
        validation = UploadValidation(tuple(self.outcomes), "enforce")
        if self.request is not None:
            finish(self.request, validation, self.spec)  # logs, with the file's hash
        if rejected is not None:
            rejected.close()  # never reaches request.FILES, so Django would not close it
        self.upload_interrupted()  # lets the storage handlers delete temporary files
        raise UploadRejected(validation)

    def _finish(self) -> None:
        if self.request is not None and self.mode != "off":
            finish(self.request, UploadValidation(tuple(self.outcomes), self.mode), self.spec)
