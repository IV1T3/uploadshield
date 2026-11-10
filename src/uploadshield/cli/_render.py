"""Human-readable output for ``scan`` and ``validate``, and the ``--json`` reporter."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, TextIO

from uploadshield.core.types import format_size
from uploadshield.core.violations import Code

from ._json import document, dumps
from ._style import Style, safe
from ._verdicts import Verdict

if TYPE_CHECKING:
    from uploadshield.core.check import Check, Sanitizer
    from uploadshield.core.result import ValidationResult
    from uploadshield.policy import Policy

    from ._verdicts import Outcome, Summary

__all__ = ["HumanReporter", "JsonReporter", "Reporter", "missing_dependency"]

_COLORS = {
    Verdict.CLEAN: "green",
    Verdict.REFUSED: "yellow",
    Verdict.NOT_VERIFIED: "magenta",
    Verdict.DANGEROUS: "red",
}
#: Details worth a glance in a scan (``validate`` shows all of them).
_HIGHLIGHTS = (
    "keywords",
    "members",
    "found",
    "marker",
    "signature",
    "rules",
    "magika_label",
    "read_as",
)
#: Optional dependencies without which a component silently does nothing.
_NEEDS: dict[str, tuple[str, str]] = {
    "ImageIntegrity": ("PIL", "images"),
    "ReencodeImage": ("PIL", "images"),
    "MagikaCheck": ("magika", "magika"),
    "YaraRules": ("yara", "yara"),
}


def missing_dependency(component: Check | Sanitizer) -> str | None:
    """The extra a check or sanitizer needs but cannot find (it is then inactive)."""
    needed = _NEEDS.get(type(component).__name__)
    if needed is None or importlib.util.find_spec(needed[0]) is not None:
        return None
    return needed[1]


class Reporter(Protocol):
    def file(self, outcome: Outcome) -> None: ...
    def warn(self, text: str) -> None: ...
    def finish(self, summary: Summary, *, interrupted: bool, exit_code: int) -> None: ...


class JsonReporter:
    """Collects everything and prints one document at the end."""

    def __init__(self, out: TextIO, *, command: str, policy: str | None) -> None:
        self.out = out
        self.command = command
        self.policy = policy
        self.outcomes: list[Outcome] = []
        self.warnings: list[str] = []

    def file(self, outcome: Outcome) -> None:
        self.outcomes.append(outcome)

    def warn(self, text: str) -> None:
        self.warnings.append(text)

    def finish(self, summary: Summary, *, interrupted: bool, exit_code: int) -> None:
        data = document(
            command=self.command,
            policy=self.policy,
            outcomes=self.outcomes,
            summary=summary,
            warnings=self.warnings,
            interrupted=interrupted,
            exit_code=exit_code,
        )
        print(dumps(data), file=self.out)


class HumanReporter:
    """Prints each file as it is inspected: a line per file (scan) or a trace (validate)."""

    def __init__(
        self,
        out: TextIO,
        err: TextIO,
        style: Style,
        *,
        policy: Policy,
        detailed: bool,
        quiet: bool,
    ) -> None:
        self.out, self.err, self.s = out, err, style
        self.policy = policy
        self.detailed = detailed
        self.quiet = quiet
        self._root: str | None = None

    # -- per file ---------------------------------------------------------------------

    def file(self, outcome: Outcome) -> None:
        if outcome.skipped is not None:
            if not self.quiet:
                self._heading(outcome)
                line = f"  - {safe(outcome.label)}  skipped: {outcome.skipped}"
                self._print(self.s.dim(line))
            return
        if self.quiet and outcome.verdict is Verdict.CLEAN and outcome.save_error is None:
            return
        self._heading(outcome)
        if self.detailed:
            self._trace(outcome)
        else:
            self._line(outcome)

    def _heading(self, outcome: Outcome) -> None:
        """Files found in a directory are listed under it, relative to it."""
        if outcome.root != self._root:
            self._root = outcome.root
            if outcome.root is not None:
                self._print(self.s.bold(safe(outcome.root.rstrip("/\\") + "/")))

    def _glyph(self, verdict: Verdict) -> str:
        glyph = {
            Verdict.CLEAN: self.s.ok,
            Verdict.REFUSED: "!",
            Verdict.NOT_VERIFIED: "?",
            Verdict.DANGEROUS: self.s.bad,
        }[verdict]
        return self.s.paint(glyph, _COLORS[verdict], "bold")

    def _describe(self, result: ValidationResult) -> str:
        kind = result.file_type.label if result.file_type is not None else "unknown format"
        return f"{kind} {self.s.dot} {format_size(result.size)}"

    def _line(self, outcome: Outcome) -> None:
        name = self.s.bold(safe(outcome.label))
        if outcome.result is None:
            reason = outcome.error or "could not be read"
            self._print(f"  {self._glyph(outcome.verdict)} {name}  not verified: {reason}")
            return
        result = outcome.result
        self._print(
            f"  {self._glyph(outcome.verdict)} {name}  {self.s.dim(self._describe(result))}"
        )
        for violation, verdict in zip(result.violations, outcome.verdicts, strict=True):
            # A line per file shows what makes it this verdict; --json lists everything.
            if verdict is not outcome.verdict:
                continue
            message = violation.message
            if violation.code == Code.TYPE_NOT_ALLOWED and verdict is Verdict.NOT_VERIFIED:
                message = (
                    "Its contents cannot be inspected: unpack it and scan the files, "
                    "or add --clamav."
                )
            extra = _highlights(violation.details, self.s.ellipsis)
            code = self.s.paint(str(violation.code), _COLORS[verdict])
            self._print(f"      {code}  {safe(message)}{self.s.dim(extra)}")

    def _trace(self, outcome: Outcome) -> None:
        s = self.s
        name = s.bold(safe(outcome.label))
        policy = f'"{self.policy.name or "custom"}"'
        if outcome.result is None:
            self._print(f"{self._glyph(outcome.verdict)} {name}  not verified: {outcome.error}")
            self._print("")
            return
        result = outcome.result
        self._print(f"{self._glyph(outcome.verdict)} {name}  {self._head(outcome, policy)}")
        if result.name != Path(outcome.label).name:
            self._row("as", safe(result.name))
        detected = (
            f"{result.file_type.label} ({result.file_type.mime}), {format_size(result.size)}"
            if result.file_type is not None
            else f"unknown format, {format_size(result.size)}"
        )
        self._row("detected", detected)
        if result.declared_type:
            declared = safe(result.declared_type)
            if not self.policy.match_declared_type:
                declared += s.dim("  (not compared: the policy has match_declared_type=False)")
            self._row("declared", declared)
        self._checks(result)
        self._violations(outcome)
        if result.sanitized is not None:
            sanitized = result.sanitized
            size = len(sanitized.data) if sanitized.data is not None else result.size
            changed = "renamed only" if sanitized.data is None else "rewritten"
            self._row(
                "sanitized",
                f"{', '.join(sanitized.applied)} {s.arrow} {safe(sanitized.name)} "
                f"({sanitized.content_type}, {format_size(size)}, {changed})",
            )
        if outcome.saved is not None:
            self._row("saved", safe(outcome.saved))
        if outcome.save_error is not None:
            self._row("not saved", s.paint(outcome.save_error, "red"))
        if not result.ok:
            codes = " ".join(dict.fromkeys(str(v.code) for v in result.violations))
            self._row("explain", s.dim(f"uploadshield explain {codes}"))
        self._print("")

    def _head(self, outcome: Outcome, policy: str) -> str:
        s = self.s
        if outcome.verdict is Verdict.CLEAN:
            return s.paint(f"accepted by {policy}", "green", "bold")
        head = s.paint(f"refused by {policy}", _COLORS[outcome.verdict], "bold")
        if outcome.verdict in (Verdict.DANGEROUS, Verdict.NOT_VERIFIED):
            head += s.paint(f" ({outcome.verdict.label})", _COLORS[outcome.verdict])
        return head

    def _violations(self, outcome: Outcome) -> None:
        s = self.s
        violations = outcome.result.violations if outcome.result is not None else ()
        for violation, verdict in zip(violations, outcome.verdicts, strict=True):
            code = s.paint(f"{self._glyph(verdict)} {violation.code}", _COLORS[verdict])
            self._print(f"  {code}  {safe(violation.message)}")
            for key, value in violation.details.items():
                if value not in (None, "", [], ()):
                    self._print(s.dim(f"      {key}: {_format(value, s.ellipsis, limit=300)}"))

    def _checks(self, result: ValidationResult) -> None:
        s = self.s
        failed = {v.check for v in result.violations}
        ran: list[str] = []
        idle: list[str] = []
        not_run: list[str] = []
        inactive: list[str] = []
        stopped = False
        for check in self.policy.pipeline:
            if check.name in result.checks_run:
                if check.name in failed:
                    ran.append(s.paint(f"{s.bad} {check.name}", "red"))
                    stopped = self.policy.fail_fast
                else:
                    ran.append(s.paint(f"{s.ok} {check.name}", "green"))
            elif stopped:
                not_run.append(check.name)
            elif (extra := missing_dependency(check)) is not None:
                inactive.append(f"{check.name} (needs uploadshield[{extra}])")
            else:
                idle.append(check.name)
        self._row("checks", "  ".join(ran) or "none")
        if idle:
            self._row("", s.dim(f"not applicable: {', '.join(idle)}"))
        if not_run:
            self._row("", s.dim(f"not run after the first failure: {', '.join(not_run)}"))
            self._row("", s.dim("  (--all-checks runs every check)"))
        if inactive:
            self._row("", s.paint(f"inactive: {', '.join(inactive)}", "yellow"))

    # -- summary ----------------------------------------------------------------------

    def warn(self, text: str) -> None:
        print(self.s.paint(f"warning: {text}", "yellow"), file=self.err)

    def finish(self, summary: Summary, *, interrupted: bool, exit_code: int) -> None:
        s = self.s
        parts = [
            s.paint(f"{summary.counts[v]} {v.label}", _COLORS[v])
            for v in (Verdict.CLEAN, Verdict.DANGEROUS, Verdict.REFUSED, Verdict.NOT_VERIFIED)
            if summary.counts[v] or v is Verdict.CLEAN
        ]
        files = f"{summary.files} file{'' if summary.files == 1 else 's'}"
        line = f"{files} in {summary.seconds:.1f} s: {', '.join(parts)}"
        if skipped := sum(summary.skipped.values()):
            reasons = ", ".join(f"{n} {why}" for why, n in sorted(summary.skipped.items()))
            line += s.dim(f"; {skipped} skipped ({reasons})")
        if not self.detailed or summary.files > 1 or interrupted:
            self._print(("" if self.detailed else "\n") + s.bold(line + "."))
        if interrupted:
            self._print(
                s.paint("Interrupted: the files above are all that was inspected.", "yellow")
            )
        elif exit_code == 1 and not self.detailed:
            self._print(s.dim("What a code means: uploadshield explain <code>"))

    # -- helpers ----------------------------------------------------------------------

    def _row(self, label: str, value: str) -> None:
        self._print(f"  {self.s.dim(f'{label:<10}')} {value}")

    def _print(self, text: str) -> None:
        print(text, file=self.out)


def _highlights(details: Any, ellipsis: str) -> str:
    shown = [
        _format(details[key], ellipsis, limit=80)
        for key in _HIGHLIGHTS
        if details.get(key) not in (None, "", [], ())
    ]
    if details.get("in_sanitized_output"):
        shown.append("in the sanitized output")
    return f"  {'; '.join(shown)}" if shown else ""


def _format(value: Any, ellipsis: str, *, limit: int) -> str:
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        text = ", ".join(str(v) for v in items)
    else:
        text = str(value)
    text = safe(text)
    return text if len(text) <= limit else text[: limit - 1] + ellipsis
