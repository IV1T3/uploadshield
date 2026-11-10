"""The command line itself: help, version, usage errors and the entry points."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from uploadshield import __version__

if TYPE_CHECKING:
    from tests.cli.conftest import Cli


@pytest.mark.parametrize("command", [None, "scan", "validate", "policies", "explain"])
def test_help(cli: Cli, command: str | None) -> None:
    run = cli(*(c for c in (command, "--help") if c))
    assert run.status == 0
    assert "usage: uploadshield" in run.out
    if command is None:
        assert "examples:" in run.out
        assert "exit status" in run.out


def test_version(cli: Cli) -> None:
    run = cli("--version")
    assert run.status == 0
    assert run.out.strip() == f"uploadshield {__version__}"


@pytest.mark.parametrize(
    "argv",
    [(), ("scan",), ("frobnicate",), ("scan", "--colour", "x", "."), ("validate", "--policy")],
)
def test_usage_errors_exit_two(cli: Cli, argv: tuple[str, ...]) -> None:
    run = cli(*argv)
    assert run.status == 2
    assert "usage:" in run.err
    assert run.out == ""


def test_python_dash_m_and_the_console_script() -> None:
    module = subprocess.run(
        [sys.executable, "-m", "uploadshield", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert module.returncode == 0
    assert module.stdout.strip() == f"uploadshield {__version__}"
    script = Path(sys.executable).with_name("uploadshield")
    if not script.exists():  # pragma: no cover - e.g. Windows (uploadshield.exe)
        pytest.skip("console script not installed next to the interpreter")
    done = subprocess.run(
        [script, "explain", "polyglot"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0
    assert done.stdout.startswith("polyglot")
