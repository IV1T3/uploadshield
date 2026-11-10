"""The policy behind ``uploadshield scan``, and the optional scanners."""

from __future__ import annotations

import dataclasses
import importlib.util
from typing import TYPE_CHECKING

from uploadshield.checks import (
    DEFAULT_CONTENT_CHECKS,
    UNINSPECTED_ARCHIVES,
    ClamAV,
    EmbeddedContent,
    FilenameCheck,
    MagikaCheck,
    YaraRules,
)
from uploadshield.checks.scanners import clamd_ping
from uploadshield.core.types import all_types
from uploadshield.policy import Policy

if TYPE_CHECKING:
    from uploadshield.core.check import Check

__all__ = ["SetupError", "scan_policy", "scanner_checks"]

#: Formats a scan refuses outright: dangerous to accept whatever they contain.
ACTIVE_TYPES = frozenset({"text/html"})


class SetupError(Exception):
    """The command cannot run as asked (exit status 2)."""


def scan_policy(extra_checks: tuple[Check, ...] = ()) -> Policy:
    """Accept every format uploadshield can inspect, and judge each one by its content.

    Built when the command runs, so formats an application registered count too.
    Executables and HTML are refused (they are dangerous as uploads whatever they
    contain); archives it cannot open are reported as not verified.  Names are judged
    for what makes them dangerous - not for being hidden or lacking an extension - and
    there is no size limit: files too large for a check are reported, not skipped.
    """
    allowed = {
        t.mime
        for t in all_types()
        if not t.executable and t.mime not in ACTIVE_TYPES | UNINSPECTED_ARCHIVES
    }
    content_checks = tuple(
        dataclasses.replace(check, max_scan_bytes=1 << 62)
        if isinstance(check, EmbeddedContent)
        else check
        for check in DEFAULT_CONTENT_CHECKS
    )
    return Policy(
        name="scan",
        allowed_types=allowed,
        max_size=None,
        allow_empty=True,
        filename=FilenameCheck(allow_hidden=True, require_extension=False),
        content_checks=content_checks,
        checks=extra_checks,
        fail_fast=False,
    )


def scanner_checks(
    *, clamav: str | None, yara: list[str] | None, magika: bool
) -> tuple[Check, ...]:
    """The optional scanners, verified before the first file is read."""
    checks: list[Check] = []
    if clamav:
        if not clamd_ping(clamav):
            raise SetupError(f"clamd does not answer at {clamav} (is it running?)")
        checks.append(ClamAV(address=clamav))
    if yara:
        _require("yara", "yara")
        rules = YaraRules(rules=tuple(yara))
        try:
            rules.compile()
        except Exception as exc:
            raise SetupError(f"YARA rules do not compile: {exc}") from exc
        checks.append(rules)
    if magika:
        _require("magika", "magika")
        checks.append(MagikaCheck())
    return tuple(checks)


def _require(module: str, extra: str) -> None:
    if importlib.util.find_spec(module) is None:
        raise SetupError(
            f"--{extra} needs the {extra} extra: "
            f'uvx --from "uploadshield[{extra}]" uploadshield ..., '
            f"or uv add 'uploadshield[{extra}]' in your project"
        )
