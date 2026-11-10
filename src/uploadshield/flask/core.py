"""Flask integration: configuration, request validation and the error type."""

from __future__ import annotations

import dataclasses
import fnmatch
import io
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, cast

from blinker import Namespace
from flask import Flask, Response, current_app, has_request_context, request
from werkzeug.datastructures import FileStorage, ImmutableMultiDict
from werkzeug.exceptions import HTTPException

from uploadshield import web
from uploadshield.core.upload import Upload
from uploadshield.engine import validate
from uploadshield.policy import Policy
from uploadshield.presets import BUILTIN_POLICIES, DEFAULT

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from uploadshield.core.result import ValidationResult

__all__ = [
    "SKIP",
    "FileOutcome",
    "UploadRejected",
    "UploadShield",
    "ViewSpec",
    "get_upload_results",
    "upload_rejected",
    "upload_validated",
    "validate_request",
    "validate_storage",
]

EXTENSION: Final = "uploadshield"
VIEW_ATTR: Final = "_uploadshield_spec"
_CACHE_ATTR: Final = "_uploadshield_results"
# Per-request state lives in the WSGI environ: ``g`` belongs to the app context, which
# a pushed context (tests, batch jobs) shares between requests.
_ENV_SPEC: Final = "uploadshield.spec"
_ENV_RESULTS: Final = "uploadshield.results"
MODES = ("enforce", "report", "off")

_signals = Namespace()
#: Sent for every validated request; kwargs ``results`` (list of :class:`FileOutcome`).
upload_validated = _signals.signal("uploadshield.upload-validated")
#: Sent when files are refused; kwargs ``results`` and ``enforced``.
upload_rejected = _signals.signal("uploadshield.upload-rejected")

_DEFAULTS: dict[str, Any] = {
    "MODE": "enforce",
    "DEFAULT_POLICY": "default",
    "POLICIES": {},
    "ENDPOINT_POLICIES": {},
    "EXPOSE_DETAILS": False,
    "MESSAGES": {},
    "PROTECT_ALL": True,
}


class _UseDefault:
    def __repr__(self) -> str:
        return "USE_DEFAULT"


USE_DEFAULT: Final = _UseDefault()


@dataclass(frozen=True)
class State:
    mode: str = "enforce"
    default_policy: Policy | None = DEFAULT
    policies: Mapping[str, Policy] = field(
        default_factory=lambda: MappingProxyType(BUILTIN_POLICIES)
    )
    endpoint_policies: tuple[tuple[str, Policy | None], ...] = ()
    expose_details: bool = False
    messages: Mapping[str, Any] = field(default_factory=dict)
    protect_all: bool = True

    def resolve(self, ref: Any) -> Policy:
        try:
            return web.resolve_policy(ref, self.policies)
        except web.PolicyLookupError as exc:
            raise ValueError(str(exc)) from exc


def _load_state(raw: Mapping[str, Any]) -> State:
    unknown = set(raw) - set(_DEFAULTS)
    if unknown:
        raise ValueError(
            f"Unknown UPLOADSHIELD keys: {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(_DEFAULTS)}."
        )
    values = {**_DEFAULTS, **raw}
    if values["MODE"] not in MODES:
        raise ValueError(f"UPLOADSHIELD['MODE'] must be one of {MODES}, got {values['MODE']!r}")
    policies = dict(BUILTIN_POLICIES)
    for name, policy in dict(values["POLICIES"]).items():
        if not isinstance(policy, Policy):
            raise TypeError(f"UPLOADSHIELD['POLICIES'][{name!r}] must be a Policy")
        policies[name] = policy
    base = State(policies=MappingProxyType(policies))
    default = values["DEFAULT_POLICY"]
    return dataclasses.replace(
        base,
        mode=values["MODE"],
        default_policy=None if default is None else base.resolve(default),
        endpoint_policies=tuple(
            (pattern, None if ref is None else base.resolve(ref))
            for pattern, ref in dict(values["ENDPOINT_POLICIES"]).items()
        ),
        expose_details=bool(values["EXPOSE_DETAILS"]),
        messages=MappingProxyType(dict(values["MESSAGES"])),
        protect_all=bool(values["PROTECT_ALL"]),
    )


def _state() -> State:
    """The app's configuration, or the defaults when ``init_app`` was not called."""
    return cast("State", current_app.extensions.get(EXTENSION) or _FALLBACK)


_FALLBACK = State()


@dataclass(frozen=True)
class ViewSpec:
    """How uploads to one endpoint are validated (from decorators or config)."""

    policy: Any = USE_DEFAULT
    fields: Mapping[str, Any] = field(default_factory=dict)
    mode: str | None = None
    on_reject: Callable[[list[FileOutcome]], Any] | None = None

    def __post_init__(self) -> None:
        if self.mode is not None and self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {self.mode!r}")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))

    def policy_for(self, field_name: str, state: State) -> Policy | None:
        ref = self.fields.get(field_name, self.policy)
        if ref is None:
            return None
        if isinstance(ref, _UseDefault):
            return state.default_policy or DEFAULT
        return state.resolve(ref)


SKIP: Final = ViewSpec(policy=None, mode="off")


@dataclass(frozen=True)
class FileOutcome:
    field: str
    result: ValidationResult
    policy_name: str
    storage: FileStorage

    @property
    def ok(self) -> bool:
        return self.result.ok


class UploadRejected(HTTPException):
    """Refused upload: a Werkzeug HTTP error (400/413/415) with a JSON or HTML body.

    Flask renders it like any ``abort()``; register an error handler for it to
    customise the response application-wide.
    """

    def __init__(
        self,
        outcomes: list[FileOutcome],
        *,
        expose_details: bool = False,
        messages: Mapping[str, Any] | None = None,
        response: Response | None = None,
    ) -> None:
        self.outcomes = outcomes
        results = [o.result for o in outcomes]
        self.payload = web.rejection_payload(
            results,
            include_details=expose_details,
            messages=messages,
            fields=[o.field for o in outcomes],
        )
        super().__init__(description=self.payload["message"], response=response)
        self.code = web.status_code_for(results)

    def get_response(self, environ: Any = None, scope: Any = None) -> Response:  # type: ignore[override]
        if self.response is not None:
            return cast("Response", self.response)
        status = self.code or 400
        html = has_request_context() and not web.wants_json(
            request.headers.get("Accept"), request.headers.get("X-Requested-With")
        )
        if html:
            return Response(web.html_rejection(self.payload), status=status, mimetype="text/html")
        body = json.dumps(web.json_safe(self.payload))  # details may hold sets or bytes
        return Response(body, status=status, mimetype="application/json")


def validate_storage(storage: FileStorage, policy: Policy, *, field: str) -> ValidationResult:
    """Validate a Werkzeug ``FileStorage``, memoising the result on it."""
    cache: dict[Policy, ValidationResult] = storage.__dict__.setdefault(_CACHE_ATTR, {})
    if policy not in cache:
        cache[policy] = validate(
            Upload(
                stream=storage.stream,
                name=storage.filename or "",
                declared_type=storage.mimetype or None,
                field=field,
            ),
            policy,
        )
    return cache[policy]


def deliver(storage: FileStorage, result: ValidationResult, policy: Policy) -> FileStorage:
    """The file the view receives: sanitized, with the detected content type."""
    if not result.ok or result.file_type is None:
        return storage
    sanitized = result.sanitized
    stream: Any = storage.stream
    name = storage.filename
    content_type = result.file_type.mime
    if sanitized is not None:
        name, content_type = sanitized.name, sanitized.content_type
        if sanitized.data is not None:
            stream = io.BytesIO(sanitized.data)
    replacement = FileStorage(stream, filename=name, name=storage.name, content_type=content_type)
    done = dataclasses.replace(result, sanitized=None, name=name or result.name)
    replacement.__dict__[_CACHE_ATTR] = {policy: done}
    return replacement


def get_upload_results() -> list[FileOutcome] | None:
    """The outcomes for the current request, once its files were validated."""
    return request.environ.get(_ENV_RESULTS)


def validate_request(spec: ViewSpec) -> list[FileOutcome]:
    """Validate ``request.files`` against ``spec``; refuse or swap in sanitized files."""
    if request.environ.get(_ENV_SPEC) == spec:
        return request.environ.get(_ENV_RESULTS) or []
    state = _state()
    mode = spec.mode or state.mode
    if mode == "off":
        return []
    outcomes: list[FileOutcome] = []
    delivered: list[tuple[str, FileStorage]] = []
    replaced: list[FileStorage] = []
    for field_name, storage in request.files.items(multi=True):
        policy = spec.policy_for(field_name, state)
        if policy is None or web.is_unused_file_input(storage.filename, storage.stream):
            delivered.append((field_name, storage))
            continue
        result = validate_storage(storage, policy, field=field_name)
        outcomes.append(FileOutcome(field_name, result, policy.name, storage))
        replacement = deliver(storage, result, policy)
        delivered.append((field_name, replacement))
        if replacement.stream is not storage.stream:
            replaced.append(storage)

    rejected = [o for o in outcomes if not o.ok]
    for o in rejected:
        web.log_rejection(
            o.result,
            field=o.field,
            policy_name=o.policy_name,
            mode=mode,
            path=request.path,
            sha256=web.sha256_of(o.storage.stream),
        )
    request.environ[_ENV_SPEC] = spec
    request.environ[_ENV_RESULTS] = outcomes
    app = current_app._get_current_object()  # ty: ignore[unresolved-attribute] - proxy API
    upload_validated.send(app, results=outcomes)
    if rejected:
        upload_rejected.send(app, results=rejected, enforced=mode == "enforce")
        if mode == "enforce":
            response = None
            if spec.on_reject is not None:
                response = current_app.make_response(spec.on_reject(rejected))
            raise UploadRejected(
                rejected,
                expose_details=state.expose_details,
                messages=state.messages,
                response=response,
            )
    request.__dict__["files"] = ImmutableMultiDict(delivered)  # Werkzeug caches it here
    # Werkzeug closes what is in request.files when the request ends; originals replaced
    # by sanitized copies are no longer there, so close them now.
    for original in replaced:
        original.close()
    return outcomes


def get_view_spec(view: Any) -> ViewSpec | None:
    spec = getattr(view, VIEW_ATTR, None)
    if spec is None:
        spec = getattr(getattr(view, "view_class", None), VIEW_ATTR, None)
    return spec if isinstance(spec, ViewSpec) else None


def _wants_validation() -> bool:
    # Werkzeug parses multipart bodies for every method (GET and DELETE included).
    return request.mimetype == "multipart/form-data"


class UploadShield:
    """The Flask extension: ``UploadShield(app)`` or ``shield.init_app(app)``.

    Reads ``app.config["UPLOADSHIELD"]`` (``MODE``, ``DEFAULT_POLICY``, ``POLICIES``,
    ``ENDPOINT_POLICIES``, ``EXPOSE_DETAILS``, ``MESSAGES``, ``PROTECT_ALL``).  With
    ``PROTECT_ALL`` (the default) every multipart request is validated before its view
    runs, using the view's ``@validate_uploads`` spec, else the first matching
    ``ENDPOINT_POLICIES`` glob (on ``request.endpoint``), else ``DEFAULT_POLICY``.
    """

    def __init__(self, app: Flask | None = None) -> None:
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        state = _load_state(app.config.get("UPLOADSHIELD", {}))
        app.extensions[EXTENSION] = state
        if state.protect_all:
            app.before_request(_protect)


def _protect() -> None:
    if not _wants_validation():
        return
    state = _state()
    view = current_app.view_functions.get(request.endpoint) if request.endpoint else None
    spec = get_view_spec(view)
    if spec is None:
        spec = ViewSpec(policy=state.default_policy)
        for pattern, policy in state.endpoint_policies:
            if request.endpoint and fnmatch.fnmatchcase(request.endpoint, pattern):
                spec = SKIP if policy is None else ViewSpec(policy=policy)
                break
    if spec.mode != "off":
        validate_request(spec)


def check_request(spec: ViewSpec) -> None:
    """Used by the decorator: validate unless the request needs no validation."""
    if spec.mode != "off" and _wants_validation():
        validate_request(spec)
