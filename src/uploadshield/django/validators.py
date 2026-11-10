"""Field validators for models, forms and DRF serializers."""

from __future__ import annotations

from typing import Any

from django.utils.deconstruct import deconstructible

from .conf import PolicyRef, get_config
from .service import field_rejection, validate_file

__all__ = ["FileValidator"]


@deconstructible(path="uploadshield.django.FileValidator")
class FileValidator:
    """Validate a file field against a policy::

        avatar = models.ImageField(validators=[FileValidator("images")])
        cv = forms.FileField(validators=[FileValidator(PDF.replace(max_size=5 * MB))])

    Validators always enforce, independent of the global ``MODE``: adding one is an
    explicit decision for that field.  They cannot replace the file; use
    :class:`~uploadshield.django.forms.ValidatedFileField` or a decorator for
    sanitization.  Files already in storage (re-saving a model) are not re-checked.

    Prefer policy *names* in model fields: they keep migrations short and let you
    change the policy in settings without a new migration.
    """

    def __init__(self, policy: PolicyRef = "default") -> None:
        self.policy = policy

    def __call__(self, value: Any) -> None:
        config = get_config()
        policy = config.resolve(self.policy)
        result = validate_file(value, policy, sanitize=False)
        if result is not None and not result.ok:
            raise field_rejection(result, policy, config)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FileValidator) and self.policy == other.policy

    def __hash__(self) -> int:
        return hash(self.policy)

    def __repr__(self) -> str:
        return f"FileValidator({self.policy!r})"
