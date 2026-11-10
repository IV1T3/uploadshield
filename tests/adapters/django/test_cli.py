"""``uploadshield validate --django``: the project's own policies on the command line."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

from uploadshield.cli import main


def run(capsys: pytest.CaptureFixture[str], *argv: object) -> tuple[int, str, str]:
    status = main([str(a) for a in argv])
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def big_png() -> bytes:
    buffer = io.BytesIO()
    Image.effect_noise((64, 64), 64).save(buffer, "PNG")  # incompressible: > 2 KB
    return buffer.getvalue()


def test_project_policies_by_name(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "a.png").write_bytes(big_png())
    status, out, _ = run(
        capsys, "validate", tmp_path / "a.png", "--django", "--policy", "tiny_images"
    )
    assert status == 1
    assert 'refused by "tiny_images"' in out
    assert "file_too_large" in out
    # Without --django the name is unknown: it only exists in the settings.
    status, _, err = run(capsys, "validate", tmp_path / "a.png", "--policy", "tiny_images")
    assert status == 2
    assert "use --django" in err


def test_default_is_the_projects_default_policy(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.4\n%%EOF\n")
    status, out, _ = run(capsys, "validate", tmp_path / "a.pdf", "--django", "--json")
    assert json.loads(out)["policy"] == "default"
    assert status == 0


def test_policies_lists_the_project_ones(capsys: pytest.CaptureFixture[str]) -> None:
    status, out, _ = run(capsys, "policies", "--django")
    assert status == 0
    assert "tiny_images" in out
    assert "(project)" in out
    status, out, _ = run(capsys, "policies", "text", "--django")
    assert "Plain text (text/plain)" in out


def test_missing_settings_exit_two(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("DJANGO_SETTINGS_MODULE")
    (tmp_path / "a.png").write_bytes(b"x")
    status, _, err = run(capsys, "validate", tmp_path / "a.png", "--django")
    assert status == 2
    assert "--settings" in err
    # A settings module that cannot be imported (Django is set up once per process).
    environment = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    done = subprocess.run(
        [sys.executable, "-m", "uploadshield", "policies", "--settings", "no.such.settings"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    assert done.returncode == 2
    assert "No module named 'no'" in done.stderr
