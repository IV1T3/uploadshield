"""A WTForms / Flask-WTF validator for inline form errors."""

from __future__ import annotations

from typing import Any, ClassVar

from werkzeug.datastructures import FileStorage

from uploadshield import web

from .core import _state, deliver, validate_storage

__all__ = ["ShieldedFile"]


class ShieldedFile:
    """Validate (and sanitize) a ``FileField``/``MultipleFileField``::

        class AvatarForm(FlaskForm):
            picture = FileField(validators=[FileRequired(), ShieldedFile("sanitized_images")])

    Refusals become ordinary form errors; on success ``field.data`` holds the
    sanitized file.  Empty fields are left to ``FileRequired``.
    """

    field_flags: ClassVar[dict[str, Any]] = {"accept": None}

    def __init__(self, policy: Any = "default") -> None:
        self.policy = policy

    def __call__(self, form: Any, field: Any) -> None:
        from wtforms.validators import StopValidation

        files = field.data if isinstance(field.data, list) else [field.data]
        if not any(_is_upload(f) for f in files):
            return
        state = _state()
        policy = state.resolve(self.policy)
        delivered = []
        for storage in files:
            if not _is_upload(storage):
                delivered.append(storage)
                continue
            result = validate_storage(storage, policy, field=field.name)
            if not result.ok:
                web.log_rejection(result, field=field.name, policy_name=policy.name, mode="enforce")
                raise StopValidation(
                    " ".join(web.message_for(v, state.messages) for v in result.violations)
                )
            delivered.append(deliver(storage, result, policy))
        field.data = delivered if isinstance(field.data, list) else delivered[0]


def _is_upload(value: Any) -> bool:
    """A submitted file; inputs left empty are ``FileRequired``'s business."""
    return isinstance(value, FileStorage) and not web.is_unused_file_input(
        value.filename, value.stream
    )
