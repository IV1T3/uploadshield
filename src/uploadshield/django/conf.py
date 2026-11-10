"""The ``UPLOADSHIELD`` setting: parsing, validation and policy lookup."""

from __future__ import annotations

import fnmatch
import functools
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.dispatch import receiver
from django.utils.module_loading import import_string

from uploadshield.policy import Policy
from uploadshield.presets import BUILTIN_POLICIES
from uploadshield.web import PolicyLookupError, resolve_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

    from .service import UploadValidation

__all__ = ["MODES", "ON_REJECT", "SETTING", "Config", "PolicyRef", "get_config", "load_config"]

SETTING = "UPLOADSHIELD"
#: ``enforce`` rejects, ``report`` only logs/signals what would be rejected, ``off``
#: disables request-level validation (field validators keep working).
MODES = ("enforce", "report", "off")
#: ``reject`` aborts the request (400/413/415); ``field`` replaces the file with an empty
#: placeholder so forms report the error next to the field.
ON_REJECT = ("reject", "field")
_OWN_HANDLER = "uploadshield.django.handlers.ValidatingUploadHandler"

PolicyRef = str | Policy
RejectionHandler = Callable[["HttpRequest", "UploadValidation"], "HttpResponse"]

_DEFAULTS: dict[str, Any] = {
    "MODE": "enforce",
    "DEFAULT_POLICY": "default",
    "POLICIES": {},
    "VIEW_POLICIES": {},
    "REJECTION_HANDLER": "uploadshield.django.responses.reject",
    "EXPOSE_DETAILS": False,
    "NORMALIZE_CONTENT_TYPE": True,
    "MAX_UPLOAD_SIZE": None,
    "ON_REJECT": "reject",
    # Where ValidatingUploadHandler stores incoming data (Django's defaults).
    "UPLOAD_HANDLERS": [
        "django.core.files.uploadhandler.MemoryFileUploadHandler",
        "django.core.files.uploadhandler.TemporaryFileUploadHandler",
    ],
    "MESSAGES": {},
}


@dataclass(frozen=True)
class Config:
    mode: str
    default_policy: Policy | None
    policies: Mapping[str, Policy]
    view_policies: tuple[tuple[str, Policy | None], ...]
    rejection_handler: RejectionHandler
    expose_details: bool
    normalize_content_type: bool
    max_upload_size: int | None
    messages: Mapping[str, str]
    on_reject: str
    upload_handlers: tuple[str, ...]

    def resolve(self, ref: PolicyRef) -> Policy:
        """Resolve a policy object, a registered name, or a dotted import path."""
        return _resolve(ref, self.policies)

    def policy_for_view_name(self, view_name: str | None) -> tuple[bool, Policy | None]:
        """``(matched, policy)`` for the first ``VIEW_POLICIES`` glob matching the name."""
        if view_name:
            for pattern, policy in self.view_policies:
                if fnmatch.fnmatchcase(view_name, pattern):
                    return True, policy
        return False, None


def _resolve(ref: PolicyRef, policies: Mapping[str, Policy]) -> Policy:
    try:
        return resolve_policy(ref, policies)
    except PolicyLookupError as exc:
        raise ImproperlyConfigured(str(exc)) from exc


def load_config() -> Config:
    """Build a :class:`Config` from settings, raising ``ImproperlyConfigured`` on errors."""
    raw = getattr(settings, SETTING, {})
    if not isinstance(raw, Mapping):
        raise ImproperlyConfigured(f"{SETTING} must be a dict")
    unknown = set(raw) - set(_DEFAULTS)
    if unknown:
        raise ImproperlyConfigured(
            f"Unknown {SETTING} keys: {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(_DEFAULTS)}."
        )
    values = {**_DEFAULTS, **raw}

    mode = values["MODE"]
    if mode not in MODES:
        raise ImproperlyConfigured(f"{SETTING}['MODE'] must be one of {MODES}, got {mode!r}")

    policies: dict[str, Policy] = dict(BUILTIN_POLICIES)
    for name, policy in dict(values["POLICIES"]).items():
        if not isinstance(policy, Policy):
            raise ImproperlyConfigured(
                f"{SETTING}['POLICIES'][{name!r}] must be a Policy, got {type(policy).__name__}"
            )
        policies[name] = policy

    default_ref = values["DEFAULT_POLICY"]
    default_policy = None if default_ref is None else _resolve(default_ref, policies)
    view_policies = tuple(
        (pattern, None if ref is None else _resolve(ref, policies))
        for pattern, ref in dict(values["VIEW_POLICIES"]).items()
    )

    handler = values["REJECTION_HANDLER"]
    if isinstance(handler, str):
        try:
            handler = import_string(handler)
        except ImportError as exc:
            raise ImproperlyConfigured(f"Cannot import REJECTION_HANDLER: {exc}") from exc
    if not callable(handler):
        raise ImproperlyConfigured(f"{SETTING}['REJECTION_HANDLER'] must be callable")

    max_upload = values["MAX_UPLOAD_SIZE"]
    if max_upload is not None and (not isinstance(max_upload, int) or max_upload <= 0):
        raise ImproperlyConfigured(f"{SETTING}['MAX_UPLOAD_SIZE'] must be a positive int")

    return Config(
        mode=mode,
        default_policy=default_policy,
        policies=MappingProxyType(policies),
        view_policies=view_policies,
        rejection_handler=handler,
        expose_details=bool(values["EXPOSE_DETAILS"]),
        normalize_content_type=bool(values["NORMALIZE_CONTENT_TYPE"]),
        max_upload_size=max_upload,
        messages=MappingProxyType({str(k): v for k, v in dict(values["MESSAGES"]).items()}),
        on_reject=_check_on_reject(values["ON_REJECT"]),
        upload_handlers=_check_upload_handlers(values["UPLOAD_HANDLERS"]),
    )


def _check_on_reject(value: Any) -> str:
    if value not in ON_REJECT:
        raise ImproperlyConfigured(f"{SETTING}['ON_REJECT'] must be one of {ON_REJECT}")
    return value


def _check_upload_handlers(paths: Any) -> tuple[str, ...]:
    from django.core.files.uploadhandler import FileUploadHandler

    if isinstance(paths, str) or not paths:
        raise ImproperlyConfigured(f"{SETTING}['UPLOAD_HANDLERS'] must be a non-empty list")
    for path in paths:
        if path == _OWN_HANDLER:
            raise ImproperlyConfigured(
                f"{SETTING}['UPLOAD_HANDLERS'] lists the handlers ValidatingUploadHandler "
                "delegates to; it must not contain ValidatingUploadHandler itself"
            )
        try:
            handler = import_string(path)
        except ImportError as exc:
            raise ImproperlyConfigured(f"Cannot import upload handler {path!r}: {exc}") from exc
        if not (isinstance(handler, type) and issubclass(handler, FileUploadHandler)):
            raise ImproperlyConfigured(f"{path!r} is not a FileUploadHandler subclass")
    return tuple(paths)


@functools.cache
def get_config() -> Config:
    """The cached configuration (rebuilt when the setting changes, e.g. in tests)."""
    return load_config()


@receiver(setting_changed)
def _reset_config(*, setting: str, **_: Any) -> None:
    if setting == SETTING:
        get_config.cache_clear()
