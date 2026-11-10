"""The validation engine: run a policy against one upload."""

from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING

from .core.result import SanitizedFile, ValidationResult
from .core.upload import ContentTooLargeError, InspectedFile, Upload
from .core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Collection

    from .core.check import Check, Stage
    from .core.types import FileType
    from .policy import Policy

__all__ = ["SanitizationError", "preflight", "validate"]

logger = logging.getLogger("uploadshield")


class SanitizationError(Exception):
    """A sanitizer produced output that does not match the validated file."""


def validate(upload: Upload, policy: Policy, *, sanitize: bool = True) -> ValidationResult:
    """Validate ``upload`` against ``policy`` and, if it passes, sanitize it.

    Never raises for bad input: crashing checks and sanitizers are reported as
    violations (fail closed), so a parser bug cannot become a bypass.
    """
    file = InspectedFile(upload, policy.sniffer)
    try:
        return _validate(file, policy, sanitize=sanitize)
    finally:
        file.close()


def _validate(file: InspectedFile, policy: Policy, *, sanitize: bool) -> ValidationResult:
    violations: list[Violation] = []
    checks_run: list[str] = []

    for check in policy.pipeline:
        found = _run_check(check, file)
        if found is None:
            continue
        checks_run.append(check.name)
        violations.extend(found)
        if found and policy.fail_fast:
            break

    sanitized: SanitizedFile | None = None
    if not violations and sanitize and policy.sanitizers:
        try:
            sanitized = _sanitize(file, policy)
        except Exception as exc:
            logger.exception("Sanitizing %r failed", file.name)
            violations.append(
                Violation(
                    code=Code.SANITIZATION_FAILED,
                    message="The file could not be processed.",
                    check="sanitizer",
                    details={"error": f"{type(exc).__name__}: {exc}"},
                )
            )

    if (
        sanitized is not None
        and sanitized.name != file.name
        and (found := _recheck_name(sanitized.name, file, policy))
    ):
        violations.extend(found)
        sanitized = None
    if (
        sanitized is not None
        and sanitized.data is not None
        and (found := _recheck(sanitized.data, sanitized.name, file, policy))
    ):
        violations.extend(found)
        sanitized = None

    return ValidationResult(
        name=file.name,
        field=file.field,
        size=file.size,
        file_type=_safe_file_type(file),
        declared_type=file.declared_type,
        violations=tuple(violations),
        checks_run=tuple(checks_run),
        sanitized=sanitized,
    )


def preflight(
    policy: Policy,
    *,
    stages: Collection[Stage],
    name: str,
    head: bytes = b"",
    size: int = 0,
    declared_type: str | None = None,
    field: str | None = None,
) -> ValidationResult:
    """Run the checks of ``stages`` against an upload that is still arriving.

    ``head`` holds the first bytes and ``size`` the bytes received so far.  Type checks
    are skipped for container formats (ZIP, OLE2): telling a DOCX from a macro-enabled
    DOCM needs the complete file, so they are decided by :func:`validate` later.
    """
    file = InspectedFile(Upload(io.BytesIO(head), name, size, declared_type, field), policy.sniffer)
    wanted = set(stages)
    if "type" in wanted:
        detected = _safe_file_type(file)
        if detected is not None and detected.container is not None:
            wanted.discard("type")
    violations: list[Violation] = []
    checks_run: list[str] = []
    for check in policy.pipeline:
        if check.stage not in wanted:
            continue
        found = _run_check(check, file)
        if found is None:
            continue
        checks_run.append(check.name)
        violations.extend(found)
        if found and policy.fail_fast:
            break
    return ValidationResult(
        name=file.name,
        field=field,
        size=size,
        file_type=_safe_file_type(file) if "type" in wanted else None,
        declared_type=declared_type,
        violations=tuple(violations),
        checks_run=tuple(checks_run),
    )


def _run_check(check: Check, file: InspectedFile) -> list[Violation] | None:
    """Run one check; ``None`` means "not applicable"."""
    try:
        if not check.applies(file):
            return None
        return list(check.run(file))
    except ContentTooLargeError as exc:
        logger.warning("Check %r could not inspect %r: %s", check.name, file.name, exc)
        error = str(exc)
        reason = "too_large"
        message = "The file is too large to be verified."
    except Exception as exc:
        logger.exception("Check %r crashed on %r", check.name, file.name)
        error = f"{type(exc).__name__}: {exc}"
        reason = "crashed"
        message = "The file could not be verified."
    details = {"error": error, "reason": reason}
    return [Violation(code=Code.CHECK_FAILED, message=message, check=check.name, details=details)]


def _recheck_name(name: str, file: InspectedFile, policy: Policy) -> list[Violation]:
    """Names produced by sanitizers must pass the same filename rules as uploaded ones."""
    probe = InspectedFile(Upload(io.BytesIO(b""), name, 0, None, file.field), policy.sniffer)
    return [
        Violation(v.code, v.message, v.check, {**v.details, "in_sanitized_output": True})
        for v in _run_check(policy.filename, probe) or []
    ]


def _recheck(data: bytes, name: str, file: InspectedFile, policy: Policy) -> list[Violation]:
    """Run the content checks on what the sanitizers produced.

    Re-encoding must not *create* what the checks refuse: payloads can be crafted to
    appear only after an image library compresses the pixels again.
    """
    output = InspectedFile(
        Upload(io.BytesIO(data), name, len(data), file.declared_type, file.field), policy.sniffer
    )
    found: list[Violation] = []
    for check in policy.content_checks:
        for violation in _run_check(check, output) or []:
            details = {**violation.details, "in_sanitized_output": True}
            found.append(Violation(violation.code, violation.message, violation.check, details))
    return found


def _sanitize(file: InspectedFile, policy: Policy) -> SanitizedFile | None:
    current = file
    data: bytes | None = None
    applied: list[str] = []
    for sanitizer in policy.sanitizers:
        if not sanitizer.applies(current):
            continue
        replacement = sanitizer.sanitize(current)
        applied.append(sanitizer.name)
        if replacement.data is None and replacement.name is None:
            continue
        if replacement.data is not None:
            data = replacement.data
        stream = io.BytesIO(data) if data is not None else current.stream
        current = InspectedFile(
            Upload(
                stream=stream,
                name=replacement.name or current.name,
                size=len(data) if data is not None else current.size,
                declared_type=current.declared_type,
                field=current.field,
            ),
            policy.sniffer,
        )
    if not applied:
        return None

    original, result = file.file_type, current.file_type
    if result is None or (original is not None and result.mime != original.mime):
        raise SanitizationError(
            f"sanitized output is {result.mime if result else 'unidentifiable'}, "
            f"expected {original.mime if original else 'unknown'}"
        )
    return SanitizedFile(
        name=current.name, content_type=result.mime, data=data, applied=tuple(applied)
    )


def _safe_file_type(file: InspectedFile) -> FileType | None:
    try:
        return file.file_type
    except Exception:
        return None
