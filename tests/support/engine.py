"""Shorthands for running the engine in tests."""

from __future__ import annotations

from uploadshield import Policy, Upload, presets, validate


def codes(data: bytes, name: str, policy: Policy = presets.DEFAULT, **kw) -> tuple[str, ...]:
    return validate(Upload.from_bytes(data, name, **kw), policy).codes
