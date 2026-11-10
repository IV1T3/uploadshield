"""Validate files where they are persisted: the last line of defense.

Every file that reaches storage passes ``Storage.save()``, whether it came from a
form, the admin, a legacy view writing ``request.FILES`` directly, a Celery task or a
management command.  Configure it in ``STORAGES``, wrapping any backend::

    STORAGES = {
        "default": {
            "BACKEND": "uploadshield.django.storage.ValidatingStorage",
            "OPTIONS": {
                "backend": "django.core.files.storage.FileSystemStorage",  # or S3, ...
                "options": {},
                "policy": "default",
                "path_policies": {"avatars/": "sanitized_images", "thumbnails/": None},
            },
        },
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }

Files already validated by the upload handler or a field validator against the same
policy are not checked again: the result travels with the file object.
"""

from __future__ import annotations

import posixpath
from types import MappingProxyType
from typing import IO, TYPE_CHECKING, Any

from django.core.files import File
from django.core.files.base import ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from django.utils.module_loading import import_string

from .conf import PolicyRef, get_config
from .exceptions import UploadRejected
from .service import (
    FileOutcome,
    RejectedUpload,
    UploadValidation,
    already_reported,
    validate_file,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from uploadshield.policy import Policy

__all__ = ["ValidatingStorage", "ValidatingStorageMixin"]


class ValidatingStorageMixin(Storage):
    """Add upload validation to a storage class (``class S3(ValidatingStorageMixin, S3Storage)``).

    ``upload_policy`` applies to every save; ``path_policies`` maps name prefixes to
    other policies (``None`` disables validation, e.g. for generated thumbnails).
    The longest matching prefix wins.
    """

    upload_policy: PolicyRef | None = "default"
    path_policies: Mapping[str, PolicyRef | None] = MappingProxyType({})

    def policy_for_name(self, name: str) -> Policy | None:
        normalized = name.replace("\\", "/").lstrip("/")
        ref: PolicyRef | None = self.upload_policy
        best = -1
        for prefix, candidate in self.path_policies.items():
            if normalized.startswith(prefix) and len(prefix) > best:
                ref, best = candidate, len(prefix)
        return None if ref is None else get_config().resolve(ref)

    def save(self, name: str | None, content: IO[Any], max_length: int | None = None) -> str:
        if name is None:
            name = content.name
        # Django's Storage.save() does the same wrapping for plain file objects.
        file = content if isinstance(content, File) else File(content, name)
        name, file = self.validate_upload(str(name), file)
        return self._store(name, file, max_length)

    def validate_upload(self, name: str, content: File) -> tuple[str, File]:
        """Validate ``content``; return the (possibly sanitized) name and content.

        Follows the global ``MODE`` like the upload handler: ``report`` logs and signals
        but stores anyway, ``off`` stores without checking.
        """
        mode = get_config().mode
        policy = self.policy_for_name(name)
        if policy is None or mode == "off":
            return name, content
        if isinstance(content, RejectedUpload):
            self._reject(content.result, policy, enforce=True)  # placeholders hold no data
        # Judge the name the file is stored and served under (upload_to may rename it).
        stored_name = posixpath.basename(name.replace("\\", "/"))
        result = validate_file(content, policy, field=None, name=stored_name, stored=True)
        if result is None:  # nothing to read (an empty FieldFile)
            return name, content
        if not result.ok:
            self._reject(result, policy, enforce=mode == "enforce", quiet=already_reported(content))
            return name, content
        sanitized = result.sanitized
        if sanitized is None:
            return name, content
        name = posixpath.join(posixpath.dirname(name), sanitized.name)
        if sanitized.data is not None:
            content = ContentFile(sanitized.data, name=sanitized.name)
        return name, content

    def open(self, name: str, mode: str = "rb") -> File:
        """Open for reading; writing would bypass validation and is refused.

        Backends that support write modes (S3, ...) would store whatever is written
        without passing :meth:`save`.  Paths without a policy (``path_policies`` maps
        them to ``None``) can still be opened for writing.
        """
        if any(flag in mode for flag in "wax+") and self.policy_for_name(name) is not None:
            raise PermissionError(
                f"{type(self).__name__} validates files in save(); opening {name!r} with "
                f"mode {mode!r} would bypass it.  Use save(), or a path_policies entry of "
                "None for files your code generates."
            )
        return super().open(name, mode)

    def _reject(self, result: Any, policy: Policy, *, enforce: bool, quiet: bool = False) -> None:
        from .service import field_rejection

        if not quiet:
            field_rejection(result, policy, get_config())  # logs and sends file_rejected
        if enforce:
            outcome = FileOutcome("", 0, result, policy.name)
            raise UploadRejected(UploadValidation((outcome,), "enforce"))

    def _store(self, name: str, content: File, max_length: int | None) -> str:
        return super().save(name, content, max_length=max_length)


@deconstructible(path="uploadshield.django.storage.ValidatingStorage")
class ValidatingStorage(ValidatingStorageMixin):
    """Wrap any storage backend (configured by dotted path) with upload validation."""

    def __init__(
        self,
        backend: str = "django.core.files.storage.FileSystemStorage",
        options: dict[str, Any] | None = None,
        policy: PolicyRef | None = "default",
        path_policies: Mapping[str, PolicyRef | None] | None = None,
    ) -> None:
        self.backend = backend
        self.wrapped: Storage = import_string(backend)(**(options or {}))
        self.upload_policy = policy
        self.path_policies = MappingProxyType(dict(path_policies or {}))

    def _store(self, name: str, content: File, max_length: int | None) -> str:
        return self.wrapped.save(name, content, max_length=max_length)

    # Storage API: delegate everything to the wrapped backend.
    def _open(self, name: str, mode: str = "rb") -> File:
        return self.wrapped.open(name, mode)

    def _save(self, name: str, content: File) -> str:  # pragma: no cover - save() delegates
        return self.wrapped.save(name, content)

    def delete(self, name: str) -> None:
        self.wrapped.delete(name)

    def exists(self, name: str) -> bool:
        return self.wrapped.exists(name)

    def listdir(self, path: str) -> tuple[list[str], list[str]]:
        return self.wrapped.listdir(path)

    def size(self, name: str) -> int:
        return self.wrapped.size(name)

    def url(self, name: str | None) -> str:
        return self.wrapped.url(name)

    def path(self, name: str) -> str:
        return self.wrapped.path(name)

    def get_valid_name(self, name: str) -> str:
        return self.wrapped.get_valid_name(name)

    def get_available_name(self, name: str, max_length: int | None = None) -> str:
        return self.wrapped.get_available_name(name, max_length=max_length)

    def generate_filename(self, filename: Any) -> str:
        return self.wrapped.generate_filename(filename)

    def get_accessed_time(self, name: str) -> Any:
        return self.wrapped.get_accessed_time(name)

    def get_created_time(self, name: str) -> Any:
        return self.wrapped.get_created_time(name)

    def get_modified_time(self, name: str) -> Any:
        return self.wrapped.get_modified_time(name)

    def __getattr__(self, attr: str) -> Any:
        # Backend-specific attributes (bucket_name, location, ...).
        if attr == "wrapped":  # not yet initialised (e.g. during unpickling)
            raise AttributeError(attr)
        return getattr(self.wrapped, attr)
