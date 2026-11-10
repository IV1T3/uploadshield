"""Framework-neutral pieces shared by the Django, Flask and FastAPI adapters.

Nothing here imports a web framework: status codes, error payloads, content
negotiation, policy lookup and the structured rejection log line are the same for
every integration.
"""

from __future__ import annotations

import enum
import hashlib
import html
import importlib
import logging
from collections.abc import Mapping
from typing import IO, TYPE_CHECKING, Any

from .core.violations import Code
from .policy import Policy

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .core.result import ValidationResult
    from .core.violations import Violation

__all__ = [
    "REJECTED_MESSAGE",
    "TYPE_CODES",
    "PolicyLookupError",
    "html_rejection",
    "is_unused_file_input",
    "json_safe",
    "log_rejection",
    "message_for",
    "rejection_payload",
    "resolve_policy",
    "sha256_of",
    "status_code_for",
    "wants_json",
]

logger = logging.getLogger("uploadshield")


def json_safe(value: Any) -> Any:
    """``value`` as JSON-compatible data: violation details may hold sets, tuples, bytes.

    Sets become sorted lists, bytes hex strings, enums their value, and anything else
    unknown its ``str()``, so an error payload can always be serialised.
    """
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((json_safe(v) for v in value), key=repr)
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


REJECTED_MESSAGE = "The upload was rejected."

#: Violations that are about *what* the file is; they map to 415.
TYPE_CODES = frozenset({
    Code.TYPE_NOT_ALLOWED,
    Code.TYPE_UNKNOWN,
    Code.EXTENSION_MISMATCH,
    Code.CONTENT_MISMATCH,
    Code.DECLARED_TYPE_MISMATCH,
})  # fmt: skip


class PolicyLookupError(LookupError):
    """A policy reference could not be resolved."""


def resolve_policy(ref: Any, policies: Mapping[str, Policy]) -> Policy:
    """Resolve a :class:`Policy`, a registered name, or a dotted import path."""
    if isinstance(ref, Policy):
        return ref
    if not isinstance(ref, str):
        raise PolicyLookupError(f"Upload policy must be a Policy or a string, got {ref!r}")
    if ref in policies:
        return policies[ref]
    if "." in ref:
        module_name, _, attribute = ref.rpartition(".")
        try:
            obj = getattr(importlib.import_module(module_name), attribute)
        except (ImportError, AttributeError) as exc:
            raise PolicyLookupError(f"Cannot import upload policy {ref!r}: {exc}") from exc
        if not isinstance(obj, Policy):
            raise PolicyLookupError(f"{ref!r} is not a uploadshield.Policy")
        return obj
    known = ", ".join(sorted(policies))
    raise PolicyLookupError(f"Unknown upload policy {ref!r}. Known policies: {known}.")


def status_code_for(results: Iterable[ValidationResult]) -> int:
    """413 if every problem is size, 415 if every problem is the type, else 400."""
    codes = {v.code for result in results for v in result.violations}
    if codes and codes <= {Code.FILE_TOO_LARGE}:
        return 413
    if codes and codes <= TYPE_CODES:
        return 415
    return 400


def message_for(violation: Violation, messages: Mapping[str, Any]) -> str:
    """The user-facing message, honouring per-code overrides (which may be lazy)."""
    return str(messages.get(str(violation.code), violation.message))


def rejection_payload(
    results: Iterable[ValidationResult],
    *,
    include_details: bool = False,
    messages: Mapping[str, Any] | None = None,
    message: Any = REJECTED_MESSAGE,
    fields: Iterable[str | None] | None = None,
) -> dict[str, Any]:
    """A JSON-serialisable description of rejected files.

    ``fields`` optionally overrides each result's form field name (adapters know it
    better than the engine).
    """
    overrides = messages or {}
    results = list(results)
    names = list(fields) if fields is not None else [r.field for r in results]
    files = []
    for result, field in zip(results, names, strict=True):
        entry = result.as_dict(include_details=include_details)
        entry.pop("ok", None)
        entry["field"] = field
        for error, violation in zip(entry["errors"], result.violations, strict=True):
            error["message"] = message_for(violation, overrides)
        files.append(entry)
    return {"error": "upload_rejected", "message": str(message), "files": files}


def wants_json(accept: str | None, requested_with: str | None = None) -> bool:
    """Whether a client prefers JSON over HTML (API clients, XHR)."""
    accept = accept or ""
    return ("json" in accept and "text/html" not in accept) or requested_with == "XMLHttpRequest"


def html_rejection(payload: Mapping[str, Any]) -> str:
    """A minimal, escaped HTML page for browsers."""
    items = "".join(
        f"<li>{html.escape(str(f['name']))}: "
        f"{html.escape(' '.join(str(e['message']) for e in f['errors']))}</li>"
        for f in payload["files"]
    )
    return f"<h1>{html.escape(str(payload['message']))}</h1><ul>{items}</ul>"


def is_unused_file_input(name: str | None, stream: IO[bytes]) -> bool:
    """Whether a file part is an ``<input type="file">`` the user left empty.

    Browsers send such inputs with an empty filename and no content; they are not
    uploads.  A part without a name but *with* content is an upload and must be
    validated (and refused for its missing name), or it would bypass every check.
    """
    if name:
        return False
    position = stream.tell()
    try:
        return not stream.read(1)
    finally:
        stream.seek(position)


def sha256_of(stream: IO[bytes]) -> str:
    """Hash a seekable stream, restoring its position."""
    position = stream.tell()
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        digest.update(chunk)
    stream.seek(position)
    return digest.hexdigest()


def log_rejection(
    result: ValidationResult,
    *,
    field: str | None,
    policy_name: str,
    mode: str,
    path: str | None = None,
    sha256: str | None = None,
) -> None:
    """Emit the structured warning every adapter logs for a refused file."""
    details = result.as_dict(include_details=True, include_cwe=True)
    details |= {
        "field": field,
        "policy": policy_name,
        "path": path,
        "sha256": sha256,
        "violations": [
            v.as_dict(include_details=True, include_cwe=True) for v in result.violations
        ],
        "mode": mode,
    }
    logger.warning(
        # Field and file names are attacker-controlled: %r escapes CR/LF and other
        # control characters, so they cannot forge log lines.
        "Upload %s: field=%r name=%r type=%s codes=%s",
        "rejected" if mode == "enforce" else "would be rejected (report mode)",
        field,
        result.name,
        details["detected_type"],
        ",".join(result.codes),
        extra={"upload": details},
    )
