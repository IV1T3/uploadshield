"""A form field that validates *and* sanitizes uploads."""

from __future__ import annotations

from typing import Any

from django import forms
from django.core.files.uploadedfile import UploadedFile

from .conf import PolicyRef, get_config
from .service import build_replacement, field_rejection, validate_file

__all__ = ["ValidatedFileField"]


class ValidatedFileField(forms.FileField):
    """``forms.FileField`` that runs a policy and returns the sanitized file.

    Errors appear next to the field like any other form error, which is the best
    experience for HTML forms.  ``cleaned_data`` holds the sanitized upload (e.g. a
    re-encoded image under a random name) with ``content_type`` set from the
    detected type, never from the client.
    """

    def __init__(self, *args: Any, policy: PolicyRef = "default", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.policy = policy

    def clean(self, data: Any, initial: Any = None) -> Any:
        value = super().clean(data, initial)
        if not isinstance(value, UploadedFile):
            return value  # empty, cleared, or the initial (already stored) file
        config = get_config()
        policy = config.resolve(self.policy)
        result = validate_file(value, policy)
        if result is None:
            return value
        if not result.ok:
            raise field_rejection(result, policy, config)
        return build_replacement(value, result, policy)
