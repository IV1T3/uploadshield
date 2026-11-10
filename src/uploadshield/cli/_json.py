"""The ``--json`` document: one object with every file, a summary and the exit status."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from uploadshield.web import json_safe

from ._verdicts import Verdict

if TYPE_CHECKING:
    from ._verdicts import Outcome, Summary

__all__ = ["SCHEMA", "document", "dumps", "json_safe"]

#: Bumped when a field changes meaning or disappears; new fields do not bump it.
SCHEMA = 1


def file_entry(outcome: Outcome) -> dict[str, Any]:
    entry: dict[str, Any] = {"path": outcome.display, "verdict": outcome.verdict.value}
    if outcome.skipped is not None:
        return {"path": outcome.display, "verdict": None, "skipped": outcome.skipped}
    if outcome.error is not None:
        entry["error"] = outcome.error
    if outcome.result is not None:
        entry["sha256"] = outcome.sha256
        result = outcome.result
        entry |= result.as_dict(include_details=True)
        entry.pop("field", None)  # always None outside a web request
        for error, verdict in zip(entry["errors"], outcome.verdicts, strict=True):
            error["verdict"] = verdict.value
        if (sanitized := result.sanitized) is not None:
            entry["sanitized_as"] = {
                "name": sanitized.name,
                "content_type": sanitized.content_type,
                "size": len(sanitized.data) if sanitized.data is not None else result.size,
                "content_changed": sanitized.data is not None,
            }
    if outcome.saved is not None:
        entry["saved"] = outcome.saved
    if outcome.save_error is not None:
        entry["save_error"] = outcome.save_error
    return entry


def document(
    *,
    command: str,
    policy: str | None,
    outcomes: list[Outcome],
    summary: Summary,
    warnings: list[str],
    interrupted: bool,
    exit_code: int,
) -> dict[str, Any]:
    from uploadshield import __version__

    return {
        "schema": SCHEMA,
        "version": __version__,
        "command": command,
        "policy": policy,
        "files": [file_entry(o) for o in outcomes],
        "summary": {
            "files": summary.files,
            **{verdict.value: summary.counts[verdict] for verdict in Verdict},
            "skipped": sum(summary.skipped.values()),
            "seconds": round(summary.seconds, 3),
        },
        "warnings": warnings,
        "interrupted": interrupted,
        "exit_code": exit_code,
    }


def dumps(data: dict[str, Any]) -> str:
    # ASCII escapes keep undecodable names (lone surrogates) valid and printable.
    return json.dumps(json_safe(data), indent=2, ensure_ascii=True)
