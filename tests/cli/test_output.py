"""Output: colour, hostile names, plain glyphs, JSON, interrupts and engine logs."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.support import corpus
from uploadshield.checks import Check
from uploadshield.cli import _commands, _scan
from uploadshield.cli._json import SCHEMA
from uploadshield.cli._style import Style, color_enabled, safe
from uploadshield.web import json_safe

if TYPE_CHECKING:
    from tests.cli.conftest import Cli
    from uploadshield import InspectedFile, Violation


class FakeTerminal(io.StringIO):
    def __init__(self, *, tty: bool, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    def isatty(self) -> bool:
        return self._tty

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding


def test_colour_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(name, raising=False)
    terminal, pipe = FakeTerminal(tty=True), FakeTerminal(tty=False)
    assert color_enabled("auto", terminal) is True
    assert color_enabled("auto", pipe) is False
    assert color_enabled("always", pipe) is True
    assert color_enabled("never", terminal) is False
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert color_enabled("auto", pipe) is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert color_enabled("auto", terminal) is False  # NO_COLOR wins over FORCE_COLOR
    assert color_enabled("always", terminal) is True  # an explicit flag wins over both
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.delenv("FORCE_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert color_enabled("auto", terminal) is False


def test_colour_on_request(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "a.png").write_bytes(corpus.png())
    assert "\x1b[" in cli("scan", tmp_path, "--color", "always").out
    assert "\x1b[" not in cli("scan", tmp_path, "--color", "never").out


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        ("plain name.pdf", "plain name.pdf"),
        ("caf" + chr(0xE9) + ".pdf", "caf" + chr(0xE9) + ".pdf"),
        ("a\x1b[2Jb.pdf", "a\\x1b[2Jb.pdf"),
        ("a\r\nINFO forged.pdf", "a\\x0d\\x0aINFO forged.pdf"),
        ("invoice" + chr(0x202E) + "fdp.exe", "invoice\\u202efdp.exe"),
        ("x" + chr(0xDCFF) + ".png", "x\\udcff.png"),
    ],
)
def test_untrusted_names_are_shown_safely(name: str, shown: str) -> None:
    assert safe(name) == shown


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX file names")
def test_hostile_file_names_cannot_drive_the_terminal(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "a\x1b[2Jb.png").write_bytes(corpus.PHP_SHELL)
    (tmp_path / "line\nbreak.png").write_bytes(corpus.png())
    out = cli("scan", tmp_path).out
    assert "\x1b" not in out
    assert "a\\x1b[2Jb.png" in out
    assert "line\\x0abreak.png" in out


def test_plain_glyphs_where_the_terminal_cannot_show_symbols() -> None:
    fancy = Style(FakeTerminal(tty=True), color=False)
    plain = Style(FakeTerminal(tty=True, encoding="cp1252"), color=False)
    assert (fancy.ok, fancy.bad, fancy.arrow) == ("\u2713", "\u2717", "\u2192")
    assert (plain.ok, plain.bad, plain.arrow, plain.ellipsis) == ("OK", "X", "->", "...")


def test_json_document(cli: Cli, tmp_path: Path) -> None:
    (tmp_path / "js.pdf").write_bytes(corpus.pdf_with_javascript())
    run = cli("validate", tmp_path, "--policy", "pdf", "--json")
    data = run.json()
    assert set(data) == {
        "schema",
        "version",
        "command",
        "policy",
        "files",
        "summary",
        "warnings",
        "interrupted",
        "exit_code",
    }
    assert (data["schema"], data["command"], data["policy"]) == (SCHEMA, "validate", "pdf")
    assert data["exit_code"] == run.status == 1
    (entry,) = data["files"]
    assert entry["verdict"] == "dangerous"
    assert len(entry["sha256"]) == 64
    assert entry["detected_type"] == "application/pdf"
    (error,) = entry["errors"]
    assert error["code"] == "pdf_active_content"
    assert error["verdict"] == "dangerous"
    assert error["details"]["keywords"] == ["JS", "JavaScript"]
    assert "field" not in entry
    assert run.err == ""


def test_json_safe_values() -> None:
    assert json_safe({"a": {3, 1}, "b": b"\x00\xff", "c": (1, "x"), 4: None}) == {
        "a": [1, 3],
        "b": "00ff",
        "c": [1, "x"],
        "4": None,
    }
    json.dumps(json_safe({"x": object()}))  # anything else becomes text


def test_interrupt_reports_what_was_done(
    cli: Cli, samples: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = _commands._inspect

    def interrupt_after(count: int) -> None:
        calls = iter(range(count + 1))

        def interrupting(*args: object, **kwargs: object) -> object:
            if next(calls) == count:
                raise KeyboardInterrupt
            return real(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(_commands, "_inspect", interrupting)

    interrupt_after(2)
    run = cli("scan", samples, "--json")
    assert run.status == 130
    data = run.json()
    assert data["interrupted"] is True
    assert data["exit_code"] == 130
    assert len(data["files"]) == 2
    interrupt_after(2)
    human = cli("scan", samples)
    assert human.status == 130
    assert "2 files in" in human.out
    assert "Interrupted" in human.out


@dataclass(frozen=True)
class Crashes(Check):
    name = "crashes"

    def run(self, file: InspectedFile) -> Iterator[Violation]:
        raise RuntimeError("parser bug")


def test_engine_logs_stay_out_of_the_report(
    cli: Cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = _scan.scan_policy
    monkeypatch.setattr(_commands, "scan_policy", lambda extra=(): real((*extra, Crashes())))
    (tmp_path / "a.png").write_bytes(corpus.png())
    quiet = cli("scan", tmp_path)
    assert quiet.status == 1
    assert "check_failed" in quiet.out
    assert "Traceback" not in quiet.err + quiet.out
    verbose = cli("scan", tmp_path, "-v")
    assert "Traceback" in verbose.err
    assert "parser bug" in verbose.err
