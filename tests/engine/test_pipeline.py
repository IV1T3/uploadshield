"""The engine: pipeline order, failing closed, policies, results."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from tests.support import corpus
from uploadshield import (
    MB,
    Code,
    InspectedFile,
    Policy,
    Upload,
    ValidationResult,
    Violation,
    presets,
    validate,
)
from uploadshield.checks import Check, ClamAV, FilenameCheck, PdfActiveContent


@dataclass(frozen=True)
class Explodes(Check):
    name = "explodes"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        raise RuntimeError("parser bug")


@dataclass(frozen=True)
class AlwaysFails(Check):
    name = "always_fails"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        yield self.violation("custom_code", "Nope.", reason="test")


def run(data: bytes, name: str, policy: Policy) -> ValidationResult:
    return validate(Upload.from_bytes(data, name), policy)


def test_crashing_checks_fail_closed(caplog: pytest.LogCaptureFixture) -> None:
    policy = presets.IMAGES.extend(checks=[Explodes()])
    with caplog.at_level(logging.ERROR, logger="uploadshield"):
        result = run(corpus.png(), "a.png", policy)
    assert result.codes == ("check_failed",)
    assert result.violations[0].details["error"] == "RuntimeError: parser bug"
    assert result.violations[0].details["reason"] == "crashed"
    assert "crashed" in caplog.text


def test_budget_failures_say_why() -> None:
    tiny = presets.PDF.replace(content_checks=(PdfActiveContent(max_bytes=10),))
    result = run(corpus.pdf(), "a.pdf", tiny)
    assert result.codes == ("check_failed",)
    assert result.violations[0].details["reason"] == "too_large"


def test_fail_fast_stops_before_expensive_checks() -> None:
    policy = presets.IMAGES.extend(checks=[AlwaysFails()])
    result = run(b"\x00not an image", "a.png", policy)
    assert result.codes == ("type_unknown",)
    assert "always_fails" not in result.checks_run
    collect_all = policy.replace(fail_fast=False)
    result = run(corpus.png(), "shell.php.jpg", collect_all)
    assert result.codes == ("filename_dangerous_extension", "extension_mismatch", "custom_code")


def test_pipeline_order_is_cheap_to_expensive() -> None:
    names = [c.name for c in presets.DEFAULT.extend(checks=[ClamAV()]).pipeline]
    assert names[:4] == ["size", "filename", "type", "extension"]
    assert names[-1] == "clamav"
    assert names.index("embedded") < names.index("image")


def test_policy_validation_and_derivation() -> None:
    with pytest.raises(ValueError, match="Unknown file type 'image/jpg2'"):
        Policy(allowed_types={"image/jpg2"})
    with pytest.raises(ValueError, match="Unknown media category"):
        Policy(allowed_types={"nonsense/*"})
    with pytest.raises(ValueError, match="max_size"):
        Policy(allowed_types={"image/png"}, max_size=-1)
    with pytest.raises(TypeError, match="not a Check"):
        Policy(allowed_types={"image/png"}, checks=("nope",))  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError, match="not a Sanitizer"):
        Policy(allowed_types={"image/png"}, sanitizers=(object(),))  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError, match="not a Sniffer"):
        Policy(allowed_types={"image/png"}, sniffer=object())  # ty: ignore[invalid-argument-type]

    single = Policy(allowed_types="image/jpg")  # alias + single string
    assert single.types == frozenset({"image/jpeg"})
    extended = presets.PDF.extend(allowed_types=["image/png"], name="pdf_or_png")
    assert extended.types == frozenset({"application/pdf", "image/png"})
    assert extended.name == "pdf_or_png"
    assert presets.PDF.allows_mime("application/pdf")
    assert not presets.PDF.allows_mime("image/png")
    assert not presets.PDF.allows_mime("unknown/thing")


def test_policies_are_hashable_values() -> None:
    assert presets.IMAGES.replace() == presets.IMAGES
    assert hash(presets.IMAGES) == hash(presets.IMAGES.replace())
    assert presets.IMAGES.replace(max_size=1 * MB) != presets.IMAGES
    assert len({presets.IMAGES, presets.IMAGES.replace(), presets.PDF}) == 2


def test_deconstruct_emits_only_non_defaults() -> None:
    path, args, kwargs = presets.IMAGES.deconstruct()
    assert path == "uploadshield.Policy"
    assert args == ()
    assert kwargs == {"allowed_types": presets.IMAGE_TYPES, "name": "images"}
    custom = Policy(
        allowed_types={"application/pdf"},
        content_checks=(PdfActiveContent(allow_encrypted=True),),
        filename=FilenameCheck(max_length=64),
    )
    kwargs = custom.deconstruct()[2]
    assert kwargs["content_checks"][0].deconstruct() == (
        "uploadshield.checks.PdfActiveContent",
        (),
        {"allow_encrypted": True},
    )
    assert kwargs["filename"].deconstruct()[2] == {"max_length": 64}


def test_result_serialisation() -> None:
    result = run(corpus.png(), "a.jpg", presets.IMAGES)
    public = result.as_dict()
    assert public == {
        "field": None,
        "name": "a.jpg",
        "ok": False,
        "errors": [
            {
                "code": "extension_mismatch",
                "message": "The file extension '.jpg' does not match its content (PNG image).",
            }
        ],
    }
    private = result.as_dict(include_details=True)
    assert private["detected_type"] == "image/png"
    assert private["errors"][0]["details"]["expected"] == [".png"]


def test_violation_value_semantics() -> None:
    a = Violation(Code.FILE_EMPTY, "x", details={"a": 1})
    b = Violation(Code.FILE_EMPTY, "x", details={"a": 2})
    assert a == b  # details are diagnostics, not identity
    assert hash(a) == hash(b)
    with pytest.raises(TypeError):
        a.details["a"] = 3  # ty: ignore[invalid-assignment]
