"""A machine-learning second opinion from Google Magika (``uv add "uploadshield[magika]"``).

Magika classifies 200+ formats, including the text and source-code formats that have
no magic number (it tells CSV from Python, PowerShell or batch).  It is used here as a
**veto only**: it can refuse a file the deterministic checks accepted, never accept one
they refused.  The reasons:

* it is a probabilistic classifier with no claims about adversarial robustness;
* it only looks at the first and last KiB of a file, so whoever writes those bytes
  steers its verdict;
* a model upgrade changes its answers.

A bad verdict can therefore cost availability (a false positive) but never safety.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from uploadshield.core.check import Check
from uploadshield.core.violations import Code, Violation

if TYPE_CHECKING:
    from collections.abc import Iterator

    from uploadshield.core.upload import InspectedFile

__all__ = ["DEFAULT_MAGIKA_FORBIDDEN", "MAGIKA_EQUIVALENTS", "MagikaCheck"]

#: Magika labels for content that executes or renders when opened or served.
DEFAULT_MAGIKA_FORBIDDEN = frozenset({
    # executables, installers, bytecode, shortcuts
    "pebin", "elf", "macho", "coff", "msi", "lnk", "dex", "apk", "jar", "javabytecode",
    "pythonbytecode", "wasm", "chm", "swf", "crx", "xpi", "internetshortcut", "winregistry",
    # scripts
    "shell", "batch", "powershell", "vba", "autohotkey", "autoit", "javascript",
    "typescript", "coffeescript", "python", "perl", "ruby", "php", "asp", "lua", "tcl",
    # active markup and server configuration
    "html", "svg", "mht", "htaccess",
})  # fmt: skip

#: Labels that correspond to a registered type: if a policy explicitly allows that
#: type (e.g. ``text/html``), Magika agreeing with it is not a reason to refuse.
MAGIKA_EQUIVALENTS: dict[str, str] = {
    "html": "text/html",
    "svg": "image/svg+xml",
    "php": "application/x-httpd-php",
    "shell": "application/x-sh",
    "pebin": "application/vnd.microsoft.portable-executable",
    "elf": "application/x-elf",
    "macho": "application/x-mach-binary",
    "jar": "application/java-archive",
    "apk": "application/vnd.android.package-archive",
    "wasm": "application/wasm",
    "javabytecode": "application/java-vm",
}

_models: dict[str, Any] = {}
_models_lock = threading.Lock()


def _model(prediction_mode: str) -> Any:
    """One ``Magika`` instance per process and mode, created on first use."""
    if (model := _models.get(prediction_mode)) is None:
        with _models_lock:
            if (model := _models.get(prediction_mode)) is None:
                from magika import Magika, PredictionMode

                model = Magika(prediction_mode=PredictionMode(prediction_mode))
                _models[prediction_mode] = model
    return model


@dataclass(frozen=True, slots=True)
class MagikaCheck(Check):
    """Refuse files that Magika confidently recognises as code, executables or markup.

    Typical catch: a ``.csv`` or ``.txt`` that is really a PowerShell, batch or Python
    script; deterministic sniffing can only prove it is text.  Only labels in
    ``forbidden`` with a score of at least ``min_score`` refuse a file, and never when
    the label matches the type the policy already accepted (see
    :data:`MAGIKA_EQUIVALENTS`).  ``prediction_mode`` is ``"high_confidence"``,
    ``"medium_confidence"`` or ``"best_guess"``.
    """

    _deconstruct_module = "uploadshield.checks"
    name = "magika"
    requires = ("magika",)

    forbidden: frozenset[str] = DEFAULT_MAGIKA_FORBIDDEN
    min_score: float = 0.9
    prediction_mode: str = "high_confidence"

    def __post_init__(self) -> None:
        if self.prediction_mode not in ("high_confidence", "medium_confidence", "best_guess"):
            raise ValueError(f"Unknown Magika prediction mode {self.prediction_mode!r}")
        if not 0.0 <= self.min_score <= 1.0:
            raise ValueError("min_score must be between 0 and 1")
        object.__setattr__(self, "forbidden", frozenset(self.forbidden))

    def applies(self, file: InspectedFile) -> bool:
        return file.file_type is not None

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        model = _model(self.prediction_mode)
        with file.open() as fh:
            result = model.identify_stream(fh)
        if not result.ok:
            raise RuntimeError(f"Magika could not analyse the file: {result.status}")
        output = result.output
        label = str(output.label)
        accepted = file.file_type.mime if file.file_type else None
        if (
            label in self.forbidden
            and result.score >= self.min_score
            and MAGIKA_EQUIVALENTS.get(label) != accepted
        ):
            yield self.violation(
                Code.CONTENT_MISMATCH,
                f"The file's content looks like {output.description}, which is not allowed here.",
                magika_label=label,
                score=round(float(result.score), 3),
                group=str(output.group),
                mime_type=str(output.mime_type),
                model=str(model.get_model_name()),
                detected_type=accepted,
            )
