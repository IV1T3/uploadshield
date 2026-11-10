"""Run the ``uploadshield`` command in-process, and a directory of typical files."""

from __future__ import annotations

import gzip
import io
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.support import corpus
from uploadshield.cli import main


@dataclass(frozen=True)
class Run:
    status: int
    out: str
    err: str

    def json(self) -> Any:
        return json.loads(self.out)

    def verdicts(self) -> dict[str, str | None]:
        return {Path(f["path"]).name: f["verdict"] for f in self.json()["files"]}


Cli = Callable[..., Run]


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> Cli:
    for name in ("NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(name, raising=False)

    def run(*argv: object, stdin: bytes | None = None) -> Run:
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin)))
        status = main([str(a) for a in argv])
        captured = capsys.readouterr()
        return Run(status, captured.out, captured.err)

    return run


#: One file per verdict a scan can reach.
SAMPLES: dict[str, tuple[bytes, str]] = {
    "ok.png": (corpus.png(), "clean"),
    "ok.pdf": (corpus.pdf(), "clean"),
    "notes.txt": (b"Meeting notes\n", "clean"),
    "empty.txt": (b"", "clean"),
    "js.pdf": (corpus.pdf_with_javascript(), "dangerous"),
    "macro.docx": (
        corpus.ooxml("docx", extra={"word/vbaProject.bin": b"\xd0\xcf\x11\xe0"}),
        "dangerous",
    ),
    "shell.php": (corpus.PHP_SHELL, "dangerous"),
    "cat.png": (corpus.PHP_SHELL, "dangerous"),
    "xss.svg": (corpus.svg('<rect onload="alert(1)"/>'), "dangerous"),
    "photo.png": (corpus.image("JPEG"), "refused"),  # harmless, but misnamed
    "backup.gz": (gzip.compress(b"anything"), "not_verified"),
}


@pytest.fixture
def samples(tmp_path: Path) -> Path:
    root = tmp_path / "samples"
    root.mkdir()
    for name, (data, _) in SAMPLES.items():
        (root / name).write_bytes(data)
    return root
