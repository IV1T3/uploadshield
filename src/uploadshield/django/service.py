"""Validation logic shared by the upload handler, decorators, fields and storage."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import logging
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import IO, TYPE_CHECKING, Any, Final, cast

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile, UploadedFile
from django.db.models.fields.files import FieldFile

from uploadshield import web
from uploadshield.core.upload import Upload
from uploadshield.engine import validate
from uploadshield.presets import DEFAULT

from .conf import MODES, Config, PolicyRef, get_config
from .signals import file_rejected, upload_rejected, upload_validated

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from django.core.files import File
    from django.http import HttpRequest, HttpResponse

    from uploadshield.core.result import ValidationResult
    from uploadshield.core.violations import Violation
    from uploadshield.policy import Policy

__all__ = [
    "SKIP",
    "FileOutcome",
    "RejectedUpload",
    "UploadValidation",
    "ViewSpec",
    "accept",
    "already_reported",
    "build_replacement",
    "close_replaced",
    "field_rejection",
    "finish",
    "get_upload_validation",
    "get_view_spec",
    "message_for",
    "rejection_response",
    "spec_for_request",
    "validate_file",
    "validate_request",
]

logger = logging.getLogger("uploadshield")

VIEW_ATTR: Final = "_uploadshield_spec"
DONE_ATTR: Final = "_uploadshield_done"
#: The spec the request was validated against (the handler may run before routing).
SPEC_ATTR: Final = "_uploadshield_validated_spec"
#: Public: views can read ``request.upload_validation`` after validation.
RESULT_ATTR: Final = "upload_validation"
_CACHE_ATTR: Final = "_uploadshield_results"
_REPORTED_ATTR: Final = "_uploadshield_reported"


def already_reported(file: Any) -> bool:
    """Whether a rejection of ``file`` was already logged and signalled upstream."""
    return bool(getattr(file, "__dict__", {}).get(_REPORTED_ATTR))


class _UseDefault:
    """Sentinel: use ``DEFAULT_POLICY`` (or the built-in default)."""

    def __repr__(self) -> str:
        return "USE_DEFAULT"


USE_DEFAULT: Final = _UseDefault()


@dataclass(frozen=True)
class ViewSpec:
    """How uploads to one view are validated (set by decorators or settings).

    ``on_reject`` is ``None`` (use ``ON_REJECT``), ``"reject"``, ``"field"``, or a
    callable ``(request, validation) -> HttpResponse`` that renders the rejection.
    """

    policy: PolicyRef | _UseDefault | None = USE_DEFAULT
    fields: Mapping[str, PolicyRef | None] = field(default_factory=dict)
    mode: str | None = None
    on_reject: Callable[[HttpRequest, UploadValidation], HttpResponse] | str | None = None

    def __post_init__(self) -> None:
        if self.mode is not None and self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {self.mode!r}")
        if not (self.on_reject in (None, "reject", "field") or callable(self.on_reject)):
            raise ValueError("on_reject must be 'reject', 'field' or a callable")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))

    def policy_for(self, field_name: str, config: Config) -> Policy | None:
        if field_name in self.fields:
            ref = self.fields[field_name]
        else:
            # DRF reads "photos[0]" and "photos.0" into "photos": such aliases get that
            # field's policy - but they can never skip validation that way.
            base = self.fields.get(_base_field(field_name))
            ref = base if base is not None else self.policy
        if ref is None:
            return None
        if isinstance(ref, _UseDefault):
            return config.default_policy or DEFAULT
        return config.resolve(ref)

    def effective_mode(self, config: Config) -> str:
        return self.mode or config.mode

    def inline_errors(self, config: Config) -> bool:
        """Whether rejected files become placeholders for forms to report."""
        if self.on_reject is None:
            return config.on_reject == "field"
        return self.on_reject == "field"


_FIELD_INDEX = re.compile(r"[\[.]")


def _base_field(name: str) -> str:
    return _FIELD_INDEX.split(name, maxsplit=1)[0]


#: Marks a view as exempt from upload validation.
SKIP: Final = ViewSpec(policy=None, mode="off")


@dataclass(frozen=True)
class FileOutcome:
    field: str
    index: int
    result: ValidationResult
    policy_name: str
    original: UploadedFile | None = None
    #: Set when the original was hashed and closed early (it was replaced).
    digest: str | None = None

    @property
    def ok(self) -> bool:
        return self.result.ok

    def sha256(self) -> str | None:
        if self.digest is not None:
            return self.digest
        if self.original is None or isinstance(self.original, RejectedUpload):
            return None
        digest = hashlib.sha256()
        for chunk in self.original.chunks():
            digest.update(chunk)
        self.original.seek(0)
        return digest.hexdigest()


@dataclass(frozen=True)
class UploadValidation:
    """Everything that happened to the files of one request."""

    outcomes: tuple[FileOutcome, ...]
    mode: str

    @property
    def ok(self) -> bool:
        return all(o.ok for o in self.outcomes)

    @property
    def rejected(self) -> tuple[FileOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.ok)

    @property
    def enforced(self) -> bool:
        return self.mode == "enforce"

    def for_field(self, name: str) -> tuple[FileOutcome, ...]:
        return tuple(o for o in self.outcomes if o.field == name)


# --------------------------------------------------------------------------- #
# Single files
# --------------------------------------------------------------------------- #


class RejectedUpload(InMemoryUploadedFile):
    """Stands in for a rejected file when a view reports errors inline.

    It has no content, so the rejected bytes never reach application code.  Reading
    ``size`` raises the :class:`~django.core.exceptions.ValidationError`: Django's and
    DRF's file fields read it while cleaning, so *every* file field (plain, model,
    admin, serializer) reports the precise reason next to the field.
    """

    def __init__(self, result: ValidationResult, *, field_name: str | None, config: Config) -> None:
        self.result = result
        self._error = ValidationError(
            [ValidationError(message_for(v, config), code=str(v.code)) for v in result.violations]
        )
        super().__init__(
            io.BytesIO(b""), field_name, result.name, "application/octet-stream", 0, None
        )

    @property
    def size(self) -> int | None:
        raise self._error

    @size.setter
    def size(self, value: int | None) -> None:
        """Ignored: ``UploadedFile.__init__`` assigns it."""


def _uploaded_file(value: Any, *, stored: bool = False) -> File | None:
    """The new upload behind ``value``; ``None`` for files already in storage.

    With ``stored`` a file already in storage counts too: storage validates whatever it
    is given to save, also a stored file copied under a new name.
    """
    if isinstance(value, FieldFile):
        if getattr(value, "_committed", True):
            return value.file if stored and value else None
        return value.file
    return value if hasattr(value, "read") else None


def validate_file(
    value: Any,
    policy: Policy,
    *,
    field: str | None = None,
    sanitize: bool = True,
    name: str | None = None,
    stored: bool = False,
) -> ValidationResult | None:
    """Validate a Django file object, memoising the result on the object.

    ``name`` overrides the file's own name, e.g. with the name it will be stored under.
    ``stored`` also validates files already in storage (see :func:`_uploaded_file`).
    """
    uploaded = _uploaded_file(value, stored=stored)
    if uploaded is None:
        return None
    if isinstance(uploaded, RejectedUpload):
        return uploaded.result  # the bytes are gone; the original verdict stands
    name = (uploaded.name or "") if name is None else name
    # Results are keyed by the name they were judged under: a file renamed after
    # validation (f.name = "doc.html") is judged again.
    cache: dict[tuple[Any, ...], ValidationResult] = uploaded.__dict__.setdefault(_CACHE_ATTR, {})
    for key in ((policy, True, name), (policy, sanitize, name)):
        if key in cache:
            return cache[key]
    inner = getattr(uploaded, "file", None)
    # Django's File proxies read/seek/tell/seekable to the underlying file object.
    stream = cast("IO[bytes]", inner if inner is not None else uploaded)
    result = validate(
        Upload(
            stream=stream,
            name=name,
            size=uploaded.size,
            declared_type=getattr(uploaded, "content_type", None),
            field=field,
        ),
        policy,
        sanitize=sanitize,
    )
    cache[(policy, sanitize, name)] = result
    return result


def build_replacement(
    original: UploadedFile, result: ValidationResult, policy: Policy
) -> UploadedFile:
    """The file to hand to the application after a passing validation.

    Applies the sanitized name/content and the detected content type, and records the
    outcome on the returned object so later layers (fields, storage) neither validate
    nor sanitize it again.
    """
    sanitized = result.sanitized
    if sanitized is None or sanitized.data is None:
        if sanitized is not None:
            original.name = sanitized.name
        if result.file_type is not None and get_config().normalize_content_type:
            original.content_type = result.file_type.mime
        replacement = original
    else:
        replacement = InMemoryUploadedFile(
            file=io.BytesIO(sanitized.data),
            field_name=getattr(original, "field_name", None),
            name=sanitized.name,
            content_type=sanitized.content_type,
            size=len(sanitized.data),
            charset=None,
            content_type_extra=getattr(original, "content_type_extra", None),
        )
    done = dataclasses.replace(result, sanitized=None, name=replacement.name or result.name)
    judged = replacement.name or ""
    replacement.__dict__[_CACHE_ATTR] = {
        (policy, True, judged): done,
        (policy, False, judged): done,
    }
    return replacement


def field_rejection(result: ValidationResult, policy: Policy, config: Config) -> ValidationError:
    """Log and signal a field-level rejection; return the error for the form/model."""
    logger.warning(
        "Upload rejected by field validator: name=%r type=%s codes=%s",
        result.name,
        result.file_type.mime if result.file_type else None,
        ",".join(result.codes),
        extra={
            "upload": result.as_dict(include_details=True, include_cwe=True)
            | {"policy": policy.name}
        },
    )
    file_rejected.send(sender=None, result=result, policy=policy)
    return ValidationError(
        [ValidationError(message_for(v, config), code=str(v.code)) for v in result.violations]
    )


def message_for(violation: Violation, config: Config | None = None) -> str:
    """The user-facing message, honouring ``MESSAGES`` overrides (may be lazy)."""
    return web.message_for(violation, (config or get_config()).messages)


# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #


def get_upload_validation(request: HttpRequest) -> UploadValidation | None:
    """The :class:`UploadValidation` of ``request``, if its files were validated."""
    return getattr(request, RESULT_ATTR, None)


def get_view_spec(view: Any, method: str | None = None) -> ViewSpec | None:
    """The spec attached by ``@validate_uploads``/``@skip_upload_validation``, if any.

    Looks at the view, its class, and - for ``method`` - the class's handler method,
    where ``method_decorator(validate_uploads(...), name="post")`` leaves it.
    """
    spec = getattr(view, VIEW_ATTR, None)
    view_class = getattr(view, "view_class", None) or getattr(view, "cls", None)
    if spec is None:
        spec = getattr(view_class, VIEW_ATTR, None)
    if spec is None and view_class is not None and method:
        spec = getattr(getattr(view_class, method.lower(), None), VIEW_ATTR, None)
    return spec if isinstance(spec, ViewSpec) else None


def spec_for_request(
    request: HttpRequest, view: Any, config: Config, *, match: Any = None
) -> ViewSpec:
    """Decorator spec, else the first matching ``VIEW_POLICIES`` entry, else default."""
    if (spec := get_view_spec(view, getattr(request, "method", None))) is not None:
        return spec
    match = match if match is not None else getattr(request, "resolver_match", None)
    matched, policy = config.policy_for_view_name(getattr(match, "view_name", None))
    if matched:
        return SKIP if policy is None else ViewSpec(policy=policy)
    return ViewSpec(policy=config.default_policy)


def finish(request: HttpRequest, validation: UploadValidation, spec: ViewSpec) -> None:
    """Record the outcome on the request and report it (logs and signals)."""
    setattr(request, RESULT_ATTR, validation)
    setattr(request, SPEC_ATTR, spec)
    setattr(request, DONE_ATTR, True)
    _report(request, validation)


def accept(outcome: FileOutcome, policy: Policy, config: Config, *, inline: bool) -> UploadedFile:
    """The file object the application receives for one validated upload.

    Passing files are sanitized; rejected ones become a :class:`RejectedUpload` when
    ``inline`` is set, and are returned untouched otherwise (report mode).  Replaced
    originals stay open until :func:`close_replaced` (reporting still hashes them).
    """
    original, result = outcome.original, outcome.result
    if original is None:
        raise ValueError("outcome has no file")
    if result.ok:
        return build_replacement(original, result, policy)
    if inline:
        return RejectedUpload(result, field_name=outcome.field, config=config)
    return original


def close_replaced(pairs: list[tuple[UploadedFile, UploadedFile]]) -> None:
    """Close originals that were swapped for a sanitized file or a placeholder."""
    for original, delivered in pairs:
        if delivered is not original:
            original.close()


def validate_request(request: HttpRequest, spec: ViewSpec) -> UploadValidation:
    """Validate every file in ``request.FILES`` after the body has been parsed.

    This is the fallback for projects that use ``@validate_uploads`` without
    ``ValidatingUploadHandler``.  With the handler installed the files were already
    validated while they streamed in, and this returns that result - unless the body
    was read before URL routing, when the handler could only apply the default policy:
    then the view's own spec is applied to the files now.
    """
    if getattr(request, DONE_ATTR, False) and getattr(request, SPEC_ATTR, None) == spec:
        return getattr(request, RESULT_ATTR)
    config = get_config()
    mode = spec.effective_mode(config)
    inline = mode == "enforce" and spec.inline_errors(config)
    outcomes: list[FileOutcome] = []
    replaced: list[tuple[UploadedFile, UploadedFile]] = []
    if mode != "off":
        files = request.FILES
        for field_name in list(files):
            policy = spec.policy_for(field_name, config)
            if policy is None:
                continue
            delivered = []
            for index, uploaded in enumerate(files.getlist(field_name)):
                result = validate_file(uploaded, policy, field=field_name)
                if result is None:
                    delivered.append(uploaded)
                    continue
                outcome = FileOutcome(field_name, index, result, policy.name, uploaded)
                outcomes.append(outcome)
                delivered.append(accept(outcome, policy, config, inline=inline))
                replaced.append((uploaded, delivered[-1]))
            files.setlist(field_name, delivered)
    validation = UploadValidation(tuple(outcomes), mode)
    finish(request, validation, spec)
    close_replaced(replaced)
    return validation


def rejection_response(
    request: HttpRequest, validation: UploadValidation, spec: ViewSpec
) -> HttpResponse | None:
    """The response to send instead of calling the view, or ``None`` to proceed."""
    config = get_config()
    if validation.ok or not validation.enforced or spec.inline_errors(config):
        return None
    on_reject = spec.on_reject
    if on_reject is not None and not isinstance(on_reject, str):
        return on_reject(request, validation)
    return config.rejection_handler(request, validation)


def _report(request: HttpRequest, validation: UploadValidation) -> None:
    for outcome in validation.rejected:
        if outcome.original is not None:
            outcome.original.__dict__[_REPORTED_ATTR] = True  # later layers stay quiet
        web.log_rejection(
            outcome.result,
            field=outcome.field,
            policy_name=outcome.policy_name,
            mode=validation.mode,
            path=request.path,
            sha256=outcome.sha256(),
        )
    for outcome in validation.outcomes:
        if outcome.ok:
            logger.debug("Upload accepted: field=%r name=%r", outcome.field, outcome.result.name)
    upload_validated.send(sender=None, request=request, validation=validation)
    if not validation.ok:
        upload_rejected.send(
            sender=None, request=request, validation=validation, enforced=validation.enforced
        )
