"""The :class:`UploadShield` dependency factory for FastAPI."""

from __future__ import annotations

import inspect
import io
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, cast

from fastapi import File, HTTPException, Request, UploadFile, params
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.requests import HTTPConnection  # noqa: TC002 - FastAPI injects by annotation

from uploadshield import web
from uploadshield.core.upload import Upload
from uploadshield.engine import validate
from uploadshield.presets import BUILTIN_POLICIES

if TYPE_CHECKING:
    from typing import IO

    from uploadshield.core.result import ValidationResult
    from uploadshield.policy import Policy

__all__ = ["UploadShield"]

MODES = ("enforce", "report", "off")
#: Set on the dependencies :meth:`UploadShield.file`/``files`` build:
#: ``(form field, whether it takes every file of the field)``.
FIELD_ATTR = "__uploadshield_field__"
#: ``(request, [(field, result), ...])``, called for refused files (sync or async).
RejectedCallback = Callable[[Request, list[tuple[str, "ValidationResult"]]], Awaitable[None] | None]


class UploadShield:
    """Builds FastAPI dependencies that validate uploads against policies.

    ``policies`` are added to the built-in presets (``"images"``, ``"pdf"``, ...);
    any dependency accepts a :class:`~uploadshield.Policy`, a registered name, or a
    dotted import path.  ``mode`` is ``"enforce"`` (refuse with 400/413/415),
    ``"report"`` (log and call ``on_rejected`` only) or ``"off"``.
    """

    def __init__(
        self,
        *,
        policies: Mapping[str, Policy] | None = None,
        default_policy: Any = "default",
        mode: str = "enforce",
        expose_details: bool = False,
        messages: Mapping[str, str] | None = None,
        on_rejected: RejectedCallback | None = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.policies: dict[str, Policy] = {**BUILTIN_POLICIES, **(policies or {})}
        self.default_policy = self.resolve(default_policy)
        self.mode = mode
        self.expose_details = expose_details
        self.messages = dict(messages or {})
        self.on_rejected = on_rejected

    def resolve(self, ref: Any) -> Policy:
        try:
            return web.resolve_policy(ref, self.policies)
        except web.PolicyLookupError as exc:
            raise ValueError(str(exc)) from exc

    # -- dependency factories ---------------------------------------------------------

    def file(
        self, policy: Any = None, *, alias: str = "file"
    ) -> Callable[..., Awaitable[UploadFile]]:
        """A dependency for one file field; returns the validated file, sanitized in place.

        The ``UploadFile`` itself is updated (bytes, name, content type), so a route
        that also receives the field directly, or declares the dependency in
        ``dependencies=[...]``, sees the sanitized file as well.
        """
        resolved = self.default_policy if policy is None else self.resolve(policy)

        async def dependency(request: Request, upload: UploadFile) -> UploadFile:
            results = await self._check(request, [(alias, upload)], resolved, sanitize=True)
            return upload if results is None else _deliver(upload, results[0])

        return _with_signature(dependency, File(alias=alias), UploadFile, field=(alias, False))

    def files(
        self, policy: Any = None, *, alias: str = "files"
    ) -> Callable[..., Awaitable[list[UploadFile]]]:
        """A dependency for a multi-file field; returns the files, sanitized in place."""
        resolved = self.default_policy if policy is None else self.resolve(policy)

        async def dependency(request: Request, upload: list[UploadFile]) -> list[UploadFile]:
            items = [(alias, u) for u in upload]
            results = await self._check(request, items, resolved, sanitize=True)
            if results is None:
                return upload
            return [_deliver(u, r) for u, r in zip(upload, results, strict=True)]

        return _with_signature(dependency, File(alias=alias), list[UploadFile], field=(alias, True))

    def all_files(self, policy: Any = None) -> Callable[..., AsyncIterator[None]]:
        """A safety-net dependency for ``FastAPI(dependencies=...)`` or a router.

        It validates every file of a multipart request to the routes it is attached to
        against ``policy`` (default: ``default_policy``) and refuses the request if one
        fails.  Fields that the endpoint validates itself with :meth:`file`/:meth:`files`
        are left to that policy, as a view's own policy wins over the default in Django
        and Flask.  Passing files get the detected ``content_type`` (in place: Starlette's
        form data is immutable); use :meth:`file` for sanitization.  A part without a
        filename sent to a field the route declares as ``File()`` is checked too (and
        refused for its missing name): FastAPI would hand its content to a ``bytes``
        parameter.  WebSocket routes are left alone, and so are apps mounted inside.

        A form the safety net parses itself (the endpoint declares no form parameters)
        is closed once the response is done, as FastAPI does with forms it parses.
        """
        resolved = self.default_policy if policy is None else self.resolve(policy)

        async def dependency(connection: HTTPConnection) -> AsyncIterator[None]:
            if self.mode == "off" or not (
                isinstance(connection, Request) and _is_multipart(connection)
            ):
                yield
                return
            request = connection
            # Starlette caches the parsed form here; set when FastAPI parsed it already.
            owned = getattr(request, "_form", None) is None
            form = await request.form()  # cached: the endpoint sees the same files
            try:
                items = _unchecked_files(request, form)
                results = await self._check(request, items, resolved, sanitize=False)
                for (_, upload), result in zip(items, results or [], strict=False):
                    if result.ok and result.file_type is not None:
                        _set_content_type(upload, result.file_type.mime)
                yield
            finally:
                if owned:
                    await request.close()  # its temporary files

        return dependency

    # -- internals --------------------------------------------------------------------

    async def _check(
        self,
        request: Request,
        items: list[tuple[str, Any]],
        policy: Policy,
        *,
        sanitize: bool,
    ) -> list[ValidationResult] | None:
        """Validate ``items``; refuse (enforce) or report.  ``None`` when mode is off."""
        if self.mode == "off":
            return None
        results = [
            await run_in_threadpool(_validate, upload, policy, field, sanitize=sanitize)
            for field, upload in items
        ]
        rejected = [
            (field, result)
            for (field, _), result in zip(items, results, strict=True)
            if not result.ok
        ]
        for (field, upload), result in zip(items, results, strict=True):
            if not result.ok:
                digest = await run_in_threadpool(web.sha256_of, upload.file)
                web.log_rejection(
                    result,
                    field=field,
                    policy_name=policy.name,
                    mode=self.mode,
                    path=request.url.path,
                    sha256=digest,
                )
        if rejected:
            if self.on_rejected is not None:
                outcome = self.on_rejected(request, rejected)
                if inspect.isawaitable(outcome):
                    await outcome
            if self.mode == "enforce":
                raise HTTPException(
                    status_code=web.status_code_for(r for _, r in rejected),
                    detail=web.rejection_payload(
                        (r for _, r in rejected),
                        include_details=self.expose_details,
                        messages=self.messages,
                        fields=[f for f, _ in rejected],
                    ),
                )
        return results


def _validate(upload: Any, policy: Policy, field: str, *, sanitize: bool) -> ValidationResult:
    stream = cast("IO[bytes]", upload.file)
    return validate(
        Upload(
            stream=stream,
            name=upload.filename or "",
            size=upload.size,
            declared_type=upload.content_type,
            field=field,
        ),
        policy,
        sanitize=sanitize,
    )


def _deliver(upload: Any, result: ValidationResult) -> UploadFile:
    """Sanitize ``upload`` in place: bytes, name and the detected content type.

    Updating the object (rather than returning a new one) means every reference to it -
    the dependency's return value, the route's own parameter, ``request.form()`` - sees
    the sanitized file.
    """
    if not result.ok or result.file_type is None:
        return upload  # report mode: untouched
    sanitized = result.sanitized
    content_type = result.file_type.mime
    if sanitized is not None:
        upload.filename = sanitized.name
        content_type = sanitized.content_type
        if sanitized.data is not None:
            original = upload.file
            upload.file = io.BytesIO(sanitized.data)
            upload.size = len(sanitized.data)
            original.close()  # the form now closes the replacement instead
    _set_content_type(upload, content_type)
    return upload


def _is_multipart(request: Request) -> bool:
    """Decide "multipart" the way Starlette's parser does: case- and space-insensitive."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0]
    return media_type.strip().lower() == "multipart/form-data"


def _unchecked_files(request: Request, form: Any) -> list[tuple[str, Any]]:
    """The parts the safety net must check: every file no endpoint dependency takes.

    A field taken by :meth:`UploadShield.file` only exempts the part FastAPI hands it
    (the last one); further parts under the same name are checked here.  Parts without
    a filename that a ``File()`` parameter would receive as bytes are checked as files.
    """
    own, file_fields = _route_fields(request)
    items: list[tuple[str, Any]] = []
    for key, value in form.multi_items():
        if isinstance(value, StarletteUploadFile):
            many = own.get(key)
            if many is True or (many is False and value is form.get(key)):
                continue
            if not web.is_unused_file_input(value.filename, value.file):
                items.append((key, value))
        elif isinstance(value, str) and value and key in file_fields:
            data = value.encode("utf-8", "surrogateescape")
            items.append((key, StarletteUploadFile(io.BytesIO(data), size=len(data))))
    return items


def _set_content_type(upload: StarletteUploadFile, mime: str) -> None:
    """Replace the client-declared type in place (the safety net cannot swap files)."""
    raw = [(k, v) for k, v in upload.headers.raw if k.lower() != b"content-type"]
    upload.headers = Headers(raw=[*raw, (b"content-type", mime.encode("latin-1"))])


def _route_fields(request: Request) -> tuple[dict[str, bool], set[str]]:
    """``(fields file()/files() dependencies take -> takes all parts, File() fields)``."""
    root = getattr(request.scope.get("route"), "dependant", None)
    own: dict[str, bool] = {}
    file_fields: set[str] = set()
    pending = [root] if root is not None else []
    while pending:
        dependant = pending.pop()
        if (field := getattr(dependant.call, FIELD_ATTR, None)) is not None:
            alias, many = field
            own[alias] = own.get(alias, False) or many
        for body_field in getattr(dependant, "body_params", ()):
            if isinstance(getattr(body_field, "field_info", None), params.File):
                file_fields.add(body_field.alias)
        pending.extend(dependant.dependencies)
    return own, file_fields


def _with_signature(
    dependency: Any, default: Any, annotation: Any, *, field: tuple[str, bool]
) -> Any:
    """Give the dependency an ``upload`` parameter bound to the form field ``alias``."""
    kw = inspect.Parameter.KEYWORD_ONLY
    dependency.__signature__ = inspect.Signature(
        [
            inspect.Parameter("request", kw, annotation=Request),
            inspect.Parameter("upload", kw, default=default, annotation=annotation),
        ]
    )
    setattr(dependency, FIELD_ATTR, field)
    return dependency
